import os
import configparser
import logging
import urllib.request
import urllib.response
import json
import time
import datetime
import enum
import hashlib
import heapq
import threading
import socket
import socketserver
import selectors

from typing import Union

CLOUDFLARE_API_PREFIX = "https://api.cloudflare.com/client/v4"

logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=logging.INFO)


def read_config(config_file: str = "config.ini") -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


def get_cloudflare_dns_records(bearer_token: str, zone_id: str) -> Union[dict, None]:
    assert bearer_token and zone_id, "bearer_token and zone_id must be provided"
    url = "{}/zones/{}/dns_records".format(CLOUDFLARE_API_PREFIX, zone_id)
    headers = {
        "Authorization": "Bearer {}".format(bearer_token),
        "Content-Type": "application/json",
    }
    request = urllib.request.Request(url, headers=headers)
    response = urllib.request.urlopen(request)
    return json.loads(response.read().decode("utf-8"))


def handle_cloudflare_dns_records(dns_records: dict) -> Union[list, None]:
    assert dns_records, "dns_records must be provided"
    if dns_records["success"]:
        records = []
        for record in dns_records["result"]:
            records.append(
                {
                    "name": record["name"],
                    "type": record["type"],
                    "content": record["content"],
                    "comment": record["comment"],
                    "tags": record["tags"]
                }
            )
        return records


def simple_server_filter(dns_records: list) -> Union[list, None]:
    assert dns_records, "dns_records must be provided"
    filtered_records = []
    for record in dns_records:
        if record["type"] == "A" and "server" in record["name"]:
            filtered_records.append(record)
    return filtered_records


def get_server_record(bearer_token: str, zone_id: str) -> Union[list, None]:
    assert bearer_token and zone_id, "bearer_token and zone_id must be provided"
    dns_records = get_cloudflare_dns_records(bearer_token, zone_id)
    dns_records = handle_cloudflare_dns_records(dns_records)
    dns_records = simple_server_filter(dns_records)
    return dns_records


def get_public_ip() -> Union[str, None]:
    url = "https://checkip.amazonaws.com"
    request = urllib.request.Request(url)
    response = urllib.request.urlopen(request)
    return response.read().decode("utf-8")


def get_timestamp() -> float:
    now = datetime.datetime.now()
    if now.second > 30:
        now = now + datetime.timedelta(minutes=1)
    nearest_minute = now.replace(second=0, microsecond=0)
    unix_timestamp = time.mktime(nearest_minute.timetuple())
    return unix_timestamp


def generate_hash(data: str, salt: str) -> bytes:
    assert data, "data must be provided"
    data = salt + data + str(get_timestamp())
    return hashlib.sha256(data.encode("utf-8")).hexdigest().encode("utf-8")


def validate_hash(data: str, salt: str, data_hash: bytes) -> bool:
    assert data and salt and data_hash, "data, salt and hash must be provided"
    return generate_hash(data, salt) == data_hash


class ElectionStatus(enum.Enum):
    LOOKING = 0
    FOLLOWING = 1
    LEADING = 2


class TCPSocketClient(socket.socket):
    def __init__(self, ip, port, timeout=5):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.settimeout(timeout)
        self.connect((ip, port))

    def send_message(self, message: dict, salt: str):
        assert message, "message must be provided"
        message_json = json.dumps(message)
        self.sendall(generate_hash(message_json, salt) + message_json.encode("utf-8") + b"\n")


class TCPSocketServer(socket.socket):
    def __init__(self, config: configparser.ConfigParser):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.config = config

        self.setblocking(False)
        self.bind((self.config["server"]["ip"], int(self.config["server"]["port"])))
        logging.info(
            "VPSKeeper server listening on {}:{}".format(self.config["server"]["ip"], self.config["server"]["port"]))

        self.start_time = time.time()
        self.membership = ElectionStatus.LOOKING
        self.connection_pool = {}
        self.message_queue = []
        self.servers_records = []

        self.update_server_records_thread = threading.Thread(target=self.update_server_records)
        self.update_server_records_thread.daemon = True
        self.update_server_records_thread.start()

        self.establish_connections_thread = threading.Thread(target=self.establish_connections)
        self.establish_connections_thread.daemon = True
        self.establish_connections_thread.start()

    def readline(self):
        buffer = b""
        while not buffer.endswith(b"\n"):
            buffer += self.recv(1)
        return buffer

    def loop(self):
        while True:
            if self.membership == ElectionStatus.LOOKING:
                self.handle_looking()
            elif self.membership == ElectionStatus.FOLLOWING:
                self.handle_following()
            elif self.membership == ElectionStatus.LEADING:
                self.handle_leading()
            else:
                logging.error("Unknown status: {}".format(self.membership))
            time.sleep(5)

    def message_handle(self):
        data = self.readline().strip()
        if validate_hash(data[64:].decode("utf-8"), self.config["cloudflare"]["bearer_token"], data[:64]):
            heapq.heappush(self.message_queue, (time.time(), json.loads(data[64:].decode("utf-8"))))

    def handle_looking(self):
        pass

    def handle_following(self):
        pass

    def handle_leading(self):
        pass

    def establish_connections(self):
        while True:
            for record in self.servers_records:
                if record["content"] == self.host_public_ip:
                    continue
                if record["name"] not in self.connection_pool:
                    try:
                        self.connection_pool[record["name"]] = TCPSocketClient(ip=record["content"],
                                                                               port=int(self.config["server"]["port"]))
                        logging.info("Connected to {}".format(record["name"]))
                    except Exception as e:
                        logging.error(e)
            time.sleep(5)

    def update_server_records(self):
        while True:
            try:
                logging.info("Updating server records")
                self.host_public_ip = get_public_ip()
                self.servers_records = get_server_record(self.config["cloudflare"]["bearer_token"],
                                                         self.config["cloudflare"]["zone_id"])
                self.listen(len(self.servers_records))
                logging.info("Server records updated")
                time.sleep(60)
            except Exception as e:
                logging.error(e)
                time.sleep(5)

    @property
    def membership(self):
        return self.election_status

    @membership.setter
    def membership(self, value):
        self.election_status = value
        logging.info("Membership changed to {}".format(self.election_status))


def main_loop(config: configparser.ConfigParser):
    assert config, "config must be provided"

    server = TCPSocketServer(config)

    server_thread = threading.Thread(target=server.loop)
    server_thread.daemon = True
    server_thread.start()
    server_thread.join()


if __name__ == "__main__":
    main_loop(read_config())
