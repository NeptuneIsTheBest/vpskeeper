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
import selectors

from typing import Union

CLOUDFLARE_API_PREFIX = "https://api.cloudflare.com/client/v4"

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(module)s %(funcName)s %(message)s",
    level=logging.INFO
)


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
    response = urllib.request.urlopen(request, timeout=5)
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
    dns_records = simple_server_filter(handle_cloudflare_dns_records(get_cloudflare_dns_records(bearer_token, zone_id)))
    return dns_records.sort()


def get_public_ip() -> Union[str, None]:
    url = "https://checkip.amazonaws.com"
    request = urllib.request.Request(url)
    response = urllib.request.urlopen(request, timeout=5)
    return response.read().decode("utf-8").strip()


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


class TCPSocketServer:
    def __init__(self, config: configparser.ConfigParser):
        self.config = config
        self.host_public_ip = get_public_ip()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(False)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.config["server"]["ip"], int(self.config["server"]["port"])))
        self.socket.listen()
        logging.info(
            "VPSKeeper server listening on {}:{}".format(self.config["server"]["ip"],
                                                         self.config["server"]["port"])
        )

        self.start_time = time.time()
        self.membership = ElectionStatus.LOOKING
        self.server_records = []
        self.incoming_connections = {}
        self.outgoing_connections = {}
        self.message_queue = []
        self.vote_pool = {}

        self.selector = selectors.DefaultSelector()
        self.selector.register(self.socket, selectors.EVENT_READ, self.accept_handle)

        self.update_server_records_thread = threading.Thread(target=self.update_server_records)
        self.update_server_records_thread.daemon = True
        self.update_server_records_thread.start()

        self.establish_connections_thread = threading.Thread(target=self.establish_connections_loop)
        self.establish_connections_thread.daemon = True
        self.establish_connections_thread.start()

        self.select_loop_thread = threading.Thread(target=self.select_loop)
        self.select_loop_thread.daemon = True
        self.select_loop_thread.start()

        self.heartbeat_loop_thread = threading.Thread(target=self.heartbeat_loop)
        self.heartbeat_loop_thread.daemon = True
        self.heartbeat_loop_thread.start()

    def re_listen(self, backlog):
        self.selector.unregister(self.socket)
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            logging.warning("Error shutting down socket: {}".format(e))
        self.socket.close()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(False)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.config["server"]["ip"], int(self.config["server"]["port"])))
        self.socket.listen(backlog)
        self.selector.register(self.socket, selectors.EVENT_READ, self.accept_handle)

    def accept_handle(self, sock, mask):
        connection, address = sock.accept()
        connection.setblocking(False)
        logging.info("Incoming connection from {}".format(address[0]))
        for record in self.server_records:
            if record["content"] == address[0]:
                self.incoming_connections[address] = {
                    "connection": connection,
                    "last_heartbeat": time.time()
                }
                self.selector.register(connection, selectors.EVENT_READ, self.message_handle)
                logging.info("Connection from {} is allowed".format(address[0]))
                return
        logging.info("Connection from {} is not allowed".format(address[0]))
        connection.shutdown(socket.SHUT_RDWR)
        connection.close()

    def loop(self):
        while True:
            if self.membership == ElectionStatus.LOOKING:
                self.handle_looking()
            elif self.membership == ElectionStatus.FOLLOWING:
                self.handle_following()
            elif self.membership == ElectionStatus.LEADING:
                self.handle_leading()
            time.sleep(5)

    def select_loop(self):
        while True:
            events = self.selector.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

    def message_handle(self, sock, mask):
        data = b""
        while not data.endswith(b"\n"):
            try:
                data += sock.recv(1024)
            except TimeoutError as e:
                logging.warning("Timeout when receiving data from {}: {}".format(sock.getpeername()[0], e))
                return
            except Exception as e:
                logging.warning("Failed to receive data from {}: {}".format(sock.getpeername()[0], e))
                return
        if validate_hash(data[64:].decode("utf-8"), self.config["cloudflare"]["bearer_token"], data[:64]):
            json_data = json.loads(data[64:].decode("utf-8"))
            if json_data["type"] == "heartbeat":
                self.incoming_connections[sock.getpeername()[0]]["last_heartbeat"] = time.time()
            elif json_data["type"] == "vote":
                pass
            elif json_data["type"] == "request":
                pass
            elif json_data["type"] == "response":
                pass
            else:
                logging.warning("Unknown message type from {}: {}".format(sock.getpeername()[0], json_data["type"]))
            heapq.heappush(self.message_queue, (time.time(), json_data))

    def heartbeat_loop(self):
        while True:
            for key, value in list(self.outgoing_connections.items()):
                ip = key
                connection = value["connection"]
                threading.Thread(target=self.send_heartbeat, args=(ip, connection)).start()
            time.sleep(10)

    def send_heartbeat(self, ip, connection):
        try:
            connection.send_message({"type": "heartbeat"}, self.config["cloudflare"]["bearer_token"])
        except Exception as e:
            logging.warning("Failed to send heartbeat to {}: {}".format(ip, e))
            self.outgoing_connections.pop(ip)

    def handle_looking(self):
        pass

    def handle_following(self):
        pass

    def handle_leading(self):
        pass

    def establish_connections_loop(self):
        while True:
            for record in self.server_records:
                threading.Thread(target=self.establish_connection, args=(record,)).start()
            time.sleep(10)

    def establish_connection(self, server_record):
        if server_record["content"] != self.host_public_ip:
            if server_record["content"] not in self.outgoing_connections:
                try:
                    logging.info("Connecting to {}({})".format(server_record["name"], server_record["content"]))
                    self.outgoing_connections[server_record["content"]] = {
                        "connection": TCPSocketClient(
                            ip=server_record["content"],
                            port=int(self.config["server"]["port"]),
                            timeout=3
                        ),
                        "last_heartbeat": time.time()
                    }
                    logging.info("Connected to {}({})".format(server_record["name"], server_record["content"]))
                except Exception as e:
                    logging.warning(
                        "Failed to connect to {}({}): {}".format(server_record["name"], server_record["content"], e))

    def update_server_records(self):
        while True:
            try:
                logging.info("Updating server records")
                self.host_public_ip = get_public_ip()
                new_server_records = get_server_record(self.config["cloudflare"]["bearer_token"],
                                                       self.config["cloudflare"]["zone_id"])
                if self.server_records != new_server_records:
                    logging.info("Server records updated")
                    self.server_records = new_server_records
                    self.re_listen(len(self.server_records))
                else:
                    logging.info("Server records unchanged")
                time.sleep(60)
            except Exception as e:
                logging.error(e)
                time.sleep(5)

    @property
    def membership(self):
        return self.election_status

    @membership.setter
    def membership(self, value):
        if not isinstance(value, ElectionStatus):
            if isinstance(value, int):
                value = ElectionStatus(value)
            else:
                raise TypeError("Membership must be an instance of ElectionStatus")
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
    if not os.path.exists("config.ini"):
        logging.error("config.ini not found")
        exit(1)
    main_loop(read_config())
