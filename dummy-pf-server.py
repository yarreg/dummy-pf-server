import socket
import sys
import json
import struct
import base64
import logging
import argparse
import itertools
from datetime import datetime
from dataclasses import dataclass
from collections.abc import Generator
from threading import Condition

# Constants
PROTOCOL_VERSION = 2
PUSH_DATA = 0x00
PUSH_ACK = 0x01
PULL_DATA = 0x02
PULL_RESP = 0x03
PULL_ACK = 0x04
TX_ACK = 0x05

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler(sys.stdout))


@dataclass
class StatPayload:
    """
    Represents the 'stat' payload in a PF Protocol PUSH_DATA packet.
    """

    pubk: str  # gateway public key
    regi: str  # gateway registration identifier eg. EU868


@dataclass
class RxpkMetaPayload:
    """
    Represents the 'meta' payload. "meta" field in the rxpk object.
    """

    gateway_id: str
    gateway_name: str
    regi: str
    network: str | None = None
    gateway_h3index: str | None = None
    gateway_lat: str | None = None
    gateway_long: str | None = None
    region_common_name: str | None = None
    region_config_id: str | None = None


@dataclass
class TxpkPayload:
    """
    Represents the 'txpk' payload in a PF Protocol PULL_RESP packet.
    """

    imme: bool  # Send packet immediately (will ignore tmst & tmms)
    freq: float  # TX central frequency in MHz (unsigned float, Hz precision)
    rfch: int  # Concentrator "RF chain" used for TX (unsigned integer)
    powe: int  # TX output power in dBm (unsigned integer, dBm precision)
    modu: str  # Modulation identifier "LORA" or "FSK"
    size: int  # RF packet payload size in bytes (unsigned integer)
    data: str  # Base64 encoded RF packet payload, padding optional
    tmst: int | None = None  # Send packet on a certain timestamp value (will ignore tmms)
    tmms: int | None = None  # Send packet at a certain GPS time (GPS synchronization required)
    datr: str | None = None  # LoRa datarate identifier (eg. SF12BW500)
    codr: str | None = None  # LoRa ECC coding rate identifier
    fdev: int | None = None  # FSK frequency deviation (unsigned integer, in Hz)
    ipol: bool | None = None  # LoRa modulation polarization inversion
    prea: int | None = None  # RF preamble size (unsigned integer)
    ncrc: bool | None = None  # If true, disable the CRC of the physical layer (optional)


@dataclass
class RxpkPayload:
    """
    Represents the 'rxpk' payload in a PF Protocol PUSH_DATA packet.
    """

    time: datetime  # UTC time of pkt RX, us precision, ISO 8601 'compact' format
    tmst: int  # Internal timestamp of "RX finished" event (32b unsigned)
    freq: float  # RX central frequency in MHz (unsigned float, Hz precision)
    lsnr: float  # Lora SNR ratio in dB (signed float, 0.1 dB precision)
    chan: int  # Concentrator "IF" channel used for RX (unsigned integer)
    rfch: int  # Concentrator "RF chain" used for RX (unsigned integer)
    stat: int  # CRC status: 1 = OK, -1 = fail, 0 = no CRC
    modu: str  # Modulation identifier "LORA" or "FSK"
    datr: str  # LoRa datarate identifier (eg. SF12BW500)
    codr: str  # LoRa ECC coding rate identifier
    rssi: int  # RSSI in dBm (signed integer, 1 dB precision)
    size: int  # RF packet payload size in bytes (unsigned integer)
    data: bytes  # Base64 encoded RF packet payload, padded
    meta: RxpkMetaPayload  # gateway meta information
    tmms: int | None = None  # GPS time of pkt RX, number of milliseconds since 06.Jan.1980

    def get_bandwidth(self) -> int:
        """
        Returns the bandwidth in Hz based on the datr field.
        """
        bw = int(self.datr.split("BW")[1])
        return bw * 1000

    def get_spreading_factor(self) -> int:
        """
        Returns the spreading factor based on the datr field.
        """
        sf = int(self.datr.split("SF")[1].split("BW")[0])
        return sf


@dataclass
class IncomingPacket:
    version: int
    token: int
    identifier: int
    gw_mac: str

    @classmethod
    def decode(cls, packet_data: bytes) -> "IncomingPacket":
        """
        Decodes an incoming packet from gateway, it is PUSH_DATA, PULL_DATA or TX_ACK

        Args:
            packet_data (bytes): The raw packet data received from the gateway.

        Returns:
            IncomingPacket: IncomingPacket object.
        """
        minimal_packet_size = 4

        # Check if packet is long enough to contain header information
        if len(packet_data) < minimal_packet_size:
            raise ValueError("Packet is too short to contain data")

        # Unpack packet header
        version, token, identifier = struct.unpack("<BHB", packet_data[:minimal_packet_size])

        if version != PROTOCOL_VERSION:
            raise ValueError(f"Invalid protocol version: {version}")

        packet_data = packet_data[minimal_packet_size:]
        gw_mac_size = 8

        # Check if packet is long enough to contain header information
        if len(packet_data) < gw_mac_size:
            raise ValueError("Packet is too short to contain data")

        # Parse gateway MAC
        gw_mac = struct.unpack("<Q", packet_data[:gw_mac_size])[0]
        gw_mac_hex = format(gw_mac, "016x")

        return cls(version=version, token=token, identifier=identifier, gw_mac=gw_mac_hex)


@dataclass
class PullDataPacket(IncomingPacket):
    pass


@dataclass
class PushDataPacket(IncomingPacket):
    rxpk: list[RxpkPayload] | None = None
    stat: StatPayload | None = None

    @classmethod
    def decode(cls, packet_data: bytes) -> "PushDataPacket":
        """
        Decodes a PUSH_DATA packet from gateway.

        Args:
            packet_data (bytes): The raw packet data received from the gateway.

        Returns:
            PushDataPacket: PushDataPacket object.
        """
        packet = super().decode(packet_data)

        if packet.identifier != PUSH_DATA:
            raise ValueError(f"Invalid packet identifier: {packet.identifier} != PUSH_DATA")

        minimal_packet_size = 12

        # Extract JSON payload
        json_data = packet_data[minimal_packet_size:].decode("utf-8")
        if not json_data:
            raise ValueError("JSON payload is empty")

        json_data = json.loads(json_data)
        if "stat" in json_data:
            packet.stat = StatPayload(**json_data["stat"])

        if "rxpk" in json_data:
            packet.rxpk = []
            for rxpk in json_data["rxpk"]:
                print("===>", packet.gw_mac, json_data)
                rxpk["tmms"] = rxpk.get("tmms", None)  # Optional field
                rxpk["time"] = datetime.strptime(rxpk["time"], "%Y-%m-%dT%H:%M:%S.%fZ")
                rxpk["meta"] = RxpkMetaPayload(**rxpk["meta"])
                rxpk["data"] = base64.b64decode(rxpk["data"])
                packet.rxpk.append(RxpkPayload(**rxpk))

        return packet


@dataclass
class TxAckPayload:
    """
    Represents the 'txpk_ack' payload in a PF Protocol TX_ACK packet.
    """

    error: str


@dataclass
class TxAckPacket(IncomingPacket):
    txpk_ack: TxAckPayload | None = None

    @classmethod
    def decode(cls, packet_data: bytes) -> "TxAckPacket":
        """
        Decodes a TX_ACK packet from gateway.

        Args:
            packet_data (bytes): The raw packet data received from the gateway.

        Returns:
            TxAckPacket: TxAckPacket object.
        """
        packet = super().decode(packet_data)

        if packet.identifier != TX_ACK:
            raise ValueError(f"Invalid packet identifier: {packet.identifier} != TX_ACK")

        minimal_packet_size = 12

        # Extract JSON payload
        json_data = packet_data[minimal_packet_size:].decode("utf-8")
        if not json_data:
            return packet

        json_data = json.loads(json_data)
        if "txpk_ack" in json_data:
            packet.txpk_ack = TxAckPayload(**json_data["txpk_ack"])

        return packet


class TxAckFuture:
    def __init__(self) -> None:
        self._condition = Condition()
        self._result = None
        self._cancelled = False

    def set_result(self, result: TxAckPacket) -> None:
        with self._condition:
            if not self._cancelled:
                self._result = result
                self._condition.notify_all()

    def wait_for_result(self, timeout: float = None) -> TxAckPacket | None:
        with self._condition:
            if self._cancelled:
                return None
            self._condition.wait(timeout)
            return self._result

    def cancel(self) -> None:
        with self._condition:
            self._cancelled = True
            self._condition.notify_all()

    @property
    def result(self) -> TxAckPacket | None:
        return self._result

    @property
    def done(self) -> bool:
        with self._condition:
            return self._result is not None

    @property
    def cancelled(self) -> bool:
        return self._cancelled


class Server:
    def __init__(self, port) -> None:
        self.port: int = port

        """
        Dictionary to store gateway information. gw_mac -> (ip, port)
        In future we should expire gateways that are not sending data, but for now we just keep them forever
        """
        self.gateways: dict[str, tuple[str, int]] = {}

        # Server socket
        self.sock: socket.socket = None

        # Token generator to use in PULL_RESP packets
        self.pull_resp_tokens = self._token_generator()

        """
        Dict to store TxAck objects that are returned by the send_pull_resp_to_gw method.
        token -> TxAck
        """
        self.tx_ack_futures = {}

    def _token_generator(self) -> Generator[int]:
        """
        Creates a generator to cycle from 0 to 65535
        """
        return itertools.cycle(range(65536))

    def _send_pull_ack(self, address: tuple[str, int], token: int) -> None:
        """
        Sends a PULL_ACK packet to the specified address.

        Args:
            sock (socket.socket): The UDP socket used for communication.
            address (tuple): The address of the gateway (IP, port).
            token (int): The token value from the corresponding PULL_DATA packet.
        """
        # Create the PULL_ACK packet
        pull_ack_packet = struct.pack("<BHB", PROTOCOL_VERSION, token, PULL_ACK)

        # Send the PULL_ACK packet
        sent = self.sock.sendto(pull_ack_packet, address)
        logger.debug(f"Sent PULL_ACK ({sent} bytes) to {address}")

    def _send_push_ack(self, address: tuple[str, int], token: int) -> None:
        """
        Sends a PUSH_ACK packet to the specified address.

        Args:
            sock (socket.socket): The UDP socket used for communication.
            address (tuple): The address of the gateway (IP, port).
            token (int): The token value from the corresponding PUSH_DATA packet.
        """
        # Create the PUSH_ACK packet
        push_ack_packet = struct.pack("<BHB", PROTOCOL_VERSION, token, PUSH_ACK)

        # Send the PUSH_ACK packet
        sent = self.sock.sendto(push_ack_packet, address)
        logger.debug(f"Sent PUSH_ACK ({sent} bytes) to {address}")

    def send_pull_resp_to_gw(self, gw_mac: str, data: bytes) -> TxAckFuture:
        """
        Sends a PULL_RESP packet to the specified gateway.

        Args:
            gw_mac (str): The gateway MAC address.
            token (int): The token value from the corresponding PULL_DATA packet.
            data (bytes): The data to be sent in the PULL_RESP packet.
        """
        if gw_mac not in self.gateways:
            logger.error(f"Gateway {gw_mac} not found")
            raise ValueError(f"Gateway {gw_mac} not found")

        address = self.gateways[gw_mac]
        token = next(self.pull_resp_tokens)

        if token in self.tx_ack_futures:
            logger.error(f"Token {token} already in use. Cancel it")
            self.tx_ack_futures[token].cancel()

        tx_ack_future = TxAckFuture()
        self.tx_ack_futures[token] = tx_ack_future

        # Send the PULL_RESP packet
        self._send_pull_resp(address, token, data)

        return tx_ack_future

    def _send_pull_resp(self, address: tuple[str, int], token: int, data: bytes) -> None:
        """
        Sends a PULL_RESP packet to the specified address.

        Args:
            sock (socket.socket): The UDP socket used for communication.
            address (tuple): The address of the gateway (IP, port).
            token (int): The token value from the corresponding PULL_DATA packet.
            data (bytes): The data to be sent in the PULL_RESP packet.
        """
        # Create the PULL_RESP packet
        pull_resp_packet = struct.pack("<BHB", PROTOCOL_VERSION, token, PULL_RESP) + data

        # Send the PULL_RESP packet
        sent = self.sock.sendto(pull_resp_packet, address)
        logger.debug(f"Sent PULL_RESP ({sent} bytes) to {address}")

    def on_rxpk(self, gw_mac, rxpk: RxpkPayload) -> None:
        """
        Function that is called when a PUSH_DATA packet is received.
        This function should be overridden by the user to handle the received packets.

        Args:
            gw_mac (str): The gateway MAC address.
            rxpk (RxpkPayload): The received packet.
        """
        pass

    def on_stat(self, gw_mac, stat: StatPayload) -> None:
        """
        Function that is called when a gateway status is received.
        This function should be overridden by the user to handle the received status.

        Args:
            gw_mac (str): The gateway MAC address.
            stat (StatPayload): The gateway status.
        """
        pass

    def start_server_loop(self) -> None:
        """
        Function that starts the UDP server, listens for incoming packets, decodes PUSH_DATA packets, sends PUSH_ACK replies,
        and forwards data to the specified destination address.
        """

        # Create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind socket to a specific address and port
        server_address = ("0.0.0.0", self.port)
        self.sock.bind(server_address)
        logging.debug(f"Server started on port {self.port}")

        packet_decoders = {
            PUSH_DATA: PushDataPacket.decode,
            PULL_DATA: PullDataPacket.decode,
            TX_ACK: TxAckPacket.decode,
        }

        while True:
            # Receive data from clients
            data, address = self.sock.recvfrom(1024 * 5)
            logging.debug(f"Received {len(data)} bytes from {address}")
            try:
                if len(data) < 4:
                    raise ValueError("Packet is too short to contain data")
                packet_identifier = data[3]

                if packet_identifier not in packet_decoders:
                    raise ValueError(f"Invalid packet identifier: {packet_identifier}")

                pf_packet = packet_decoders[packet_identifier](data)

                # Update gateway address
                self.gateways[pf_packet.gw_mac] = address

                if packet_identifier == PUSH_DATA:
                    if pf_packet.stat:
                        logging.debug(f"Gateway status: {pf_packet.stat}")
                        self.on_stat(pf_packet.gw_mac, pf_packet.stat)
                    if pf_packet.rxpk:
                        logging.debug(f"Received {pf_packet}")

                        # Parse lorawan message
                        for packet in pf_packet.rxpk:
                            self.on_rxpk(pf_packet.gw_mac, packet)

                    # Send PUSH_ACK reply
                    self._send_push_ack(address, pf_packet.token)

                elif packet_identifier == PULL_DATA:
                    logging.debug(f"Received PULL_DATA packet from {address}")
                    # Send PULL_ACK reply
                    self._send_pull_ack(address, pf_packet.token)

                elif packet_identifier == TX_ACK:
                    logging.info(f"Received TX_ACK packet from {address} result: {pf_packet.txpk_ack}")
                    if pf_packet.token in self.tx_ack_futures:
                        tx_ack_future = self.tx_ack_futures.pop(pf_packet.token)
                        tx_ack_future.set_result(pf_packet)
                        logging.info(f"TX_ACK future set for token {pf_packet.token}")

            except KeyboardInterrupt:
                break

            except Exception as e:
                logging.exception(f"Error decoding packet: {e}")
                pass

        self.sock.close()


class DummyServer(Server):
    def on_rxpk(self, gw_mac, rxpk: RxpkPayload) -> None:
        """
        Function that is called when a PUSH_DATA packet is received.
        This function should be overridden by the user to handle the received packets.

        Args:
            gw_mac (str): The gateway MAC address.
            rxpk (RxpkPayload): The received packet.
        """
        logger.info(f"Received packet from {gw_mac}: {rxpk}")


def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(description="Dummy PF Server")
    parser.add_argument("--port", type=int, default=32100, help="Port to listen on")
    args = parser.parse_args()

    logger.info(f"Starting server on port {args.port}")
    server = DummyServer(args.port)
    server.start_server_loop()


if __name__ == "__main__":
    main()
