from __future__ import annotations

import queue
import threading
from dataclasses import dataclass
from typing import Any

from scapy.all import (
    AsyncSniffer,
    conf,
    IP,
    TCP,
    UDP,
    DNS,
)

from backend.ingest.stream import PacketRecord


@dataclass(frozen=True)
class CaptureInterface:
    """
    A locally visible passive packet-capture interface.

    name:
        Actual Npcap/Scapy device identifier used by AsyncSniffer.

    display_name:
        Human-readable adapter name shown by the dashboard.

    address:
        Primary IPv4 address associated with the adapter.
    """

    name: str
    address: str | None = None
    display_name: str | None = None


class LiveCaptureError(RuntimeError):
    pass


def list_capture_interfaces() -> list[CaptureInterface]:
    """
    Enumerate Scapy/libpcap interfaces with their friendly names.

    This deliberately uses Scapy's interface table rather than
    get_if_list(), because Windows/Npcap exposes multiple virtual
    adapters whose raw NPF names are not meaningful to an operator.

    No packets are transmitted here.
    """

    interfaces: list[CaptureInterface] = []

    try:
        scapy_interfaces = list(conf.ifaces.values())
    except Exception as exc:
        raise LiveCaptureError(
            f"Unable to enumerate Scapy/Npcap interfaces: {exc}"
        ) from exc

    for iface in scapy_interfaces:
        try:
            name = str(getattr(iface, "name", "") or "")
            friendly_name = str(
                getattr(iface, "description", "")
                or getattr(iface, "name", "")
                or ""
            )
            address = str(getattr(iface, "ip", "") or "")

            if not name:
                continue

            # Scapy may expose a blank IPv4 address for adapters that
            # do not currently have one.
            if address in {"", "0.0.0.0"}:
                address_value: str | None = None
            else:
                address_value = address

            # Prefer the adapter's friendly Windows/Scapy name.
            display_name = friendly_name or name

            interfaces.append(
                CaptureInterface(
                    name=name,
                    address=address_value,
                    display_name=display_name,
                )
            )

        except Exception:
            # One malformed/unsupported adapter must not prevent
            # discovery of the remaining capture interfaces.
            continue

    # Put interfaces with usable IPv4 addresses first.
    # Prefer normal LAN/Wi-Fi adapters over link-local and virtual
    # adapters while keeping every discoverable interface available.
    def sort_key(item: CaptureInterface) -> tuple[int, int, str]:
        address = item.address or ""
        name = (item.display_name or "").lower()

        has_ipv4 = 0 if address else 1
        is_link_local = 1 if address.startswith("169.254.") else 0
        is_loopback = 1 if address.startswith("127.") else 0

        # Wi-Fi/Ethernet with a real LAN address should naturally
        # appear before virtual/link-local interfaces.
        if "wi-fi" in name or "wireless" in name:
            adapter_priority = 0
        elif "ethernet" in name:
            adapter_priority = 1
        elif "bluetooth" in name:
            adapter_priority = 3
        elif "loopback" in name:
            adapter_priority = 4
        else:
            adapter_priority = 2

        return (
            has_ipv4 + is_link_local + is_loopback,
            adapter_priority,
            name,
        )

    interfaces.sort(key=sort_key)

    return interfaces


def _dns_query(packet: Any) -> str | None:
    try:
        if packet.haslayer(DNS) and packet[DNS].qd is not None:
            raw = packet[DNS].qd.qname

            if isinstance(raw, bytes):
                return raw.rstrip(b".").decode(
                    "utf-8",
                    errors="ignore",
                )

            return str(raw).rstrip(".")

    except Exception:
        return None

    return None


def packet_to_record(packet: Any) -> PacketRecord | None:
    """
    Convert a captured Scapy packet into Sentinel's PacketRecord.

    Only packet metadata is extracted. Payloads are not decrypted,
    transmitted, modified, or replayed.
    """

    if not packet.haslayer(IP):
        return None

    ip = packet[IP]

    src_port: int | None = None
    dst_port: int | None = None

    protocol = str(ip.proto)
    tcp_flags = ""

    if packet.haslayer(TCP):
        protocol = "TCP"

        tcp = packet[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        tcp_flags = str(tcp.flags)

    elif packet.haslayer(UDP):
        protocol = "UDP"

        udp = packet[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)

    elif int(ip.proto) == 1:
        protocol = "ICMP"

    try:
        timestamp = float(packet.time)
    except Exception:
        return None

    return PacketRecord(
        timestamp=timestamp,
        src_ip=str(ip.src),
        dst_ip=str(ip.dst),
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        dns_query=_dns_query(packet),
        packet_size=len(packet),
    )


class LivePacketCapture:
    """
    Passive Windows/Npcap capture adapter.

    IMPORTANT:
    - Does not transmit packets.
    - Does not probe hosts.
    - Does not modify packets.
    - Does not decrypt payloads.
    - Captures metadata only.
    """

    def __init__(
        self,
        interface: str,
        max_queue: int = 10000,
    ):
        self.interface = interface

        self._queue: queue.Queue[PacketRecord] = queue.Queue(
            maxsize=max_queue
        )

        self._sniffer: AsyncSniffer | None = None
        self._lock = threading.Lock()

        self._captured = 0
        self._dropped = 0

    @property
    def captured(self) -> int:
        return self._captured

    @property
    def dropped(self) -> int:
        return self._dropped

    @property
    def running(self) -> bool:
        return self._sniffer is not None

    def _on_packet(self, packet: Any) -> None:
        record = packet_to_record(packet)

        if record is None:
            return

        self._captured += 1

        try:
            self._queue.put_nowait(record)

        except queue.Full:
            self._dropped += 1

    def start(self) -> None:
        with self._lock:

            if self._sniffer is not None:
                return

            try:
                kwargs: dict[str, Any] = {
                    "iface": self.interface,
                    "store": False,
                    "prn": self._on_packet,
                }
                if not getattr(conf, "use_pcap", False) and getattr(conf, "L3socket", None):
                    kwargs["L2socket"] = conf.L3socket

                self._sniffer = AsyncSniffer(**kwargs)
                self._sniffer.start()

                import time
                time.sleep(0.1)
                if getattr(self._sniffer, "exception", None):
                    thread_exc = self._sniffer.exception
                    self._sniffer = None
                    raise thread_exc

            except Exception as exc:
                self._sniffer = None

                raise LiveCaptureError(
                    "Live capture could not start. "
                    "Verify that Npcap is installed and running on Windows, "
                    "or run the capture client in an Administrator terminal. "
                    f"Underlying error: {exc}"
                ) from exc

    def stop(self) -> None:
        with self._lock:
            sniffer = self._sniffer
            self._sniffer = None

        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass

    def drain(self, limit: int = 256) -> list[PacketRecord]:
        packets: list[PacketRecord] = []

        for _ in range(limit):
            try:
                packets.append(
                    self._queue.get_nowait()
                )

            except queue.Empty:
                break

        return packets