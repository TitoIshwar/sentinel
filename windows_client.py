#!/usr/bin/env python3
"""
Sentinel Windows Capture Client (IntCap Bridge)
==============================================
Captures REAL network packets on Windows via IntCap/Npcap and securely
transmits the extracted packet records to the deployed Sentinel backend (Render or local).

ARCHITECTURE:
    Hardware/Network -> Windows Npcap -> LivePacketCapture -> windows_client.py
    -> HTTPS POST /live/ingest -> Render Backend -> WebSocket/Stream/API -> Web Frontend -> Graph

NO SIMULATION GUARANTEE:
    This client NEVER generates mock, synthetic, random, or demo packets.
    If no packets are observed on the hardware interface, 0 packets are transmitted.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Any

# Ensure project root is on sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' package is required. Install it using: pip install requests")
    sys.exit(1)

from backend.ingest.live_capture import (
    CaptureInterface,
    LiveCaptureError,
    LivePacketCapture,
    list_capture_interfaces,
)
from backend.ingest.stream import PacketRecord


class WindowsCaptureClient:
    """
    Passive Windows capture bridge connecting local Npcap/IntCap hardware capture
    to the Sentinel cloud backend.
    """

    def __init__(
        self,
        backend_url: str,
        interface_name: str | None = None,
        api_key: str | None = None,
        batch_size: int = 50,
        flush_interval: float = 0.25,
    ):
        self.backend_url = backend_url.rstrip("/")
        self.interface_name = interface_name
        self.api_key = api_key or os.getenv("SENTINEL_CAPTURE_KEY", "").strip()
        self.batch_size = max(1, batch_size)
        self.flush_interval = max(0.05, flush_interval)

        self.selected_interface: CaptureInterface | None = None
        self.capture: LivePacketCapture | None = None

        self._running = False
        self._total_captured = 0
        self._total_sent = 0
        self._total_batches = 0
        self._start_time: float | None = None

    def select_interface(self) -> CaptureInterface:
        """Find the requested capture interface, or auto-select the best adapter."""
        try:
            interfaces = list_capture_interfaces()
        except Exception as exc:
            raise RuntimeError(f"Unable to enumerate Windows capture interfaces: {exc}") from exc

        if not interfaces:
            raise RuntimeError(
                "No capture interfaces discovered. Ensure Npcap is installed and running on Windows."
            )

        if self.interface_name:
            target = self.interface_name.strip().lower()
            for iface in interfaces:
                if (
                    target == iface.name.lower()
                    or (iface.display_name and target in iface.display_name.lower())
                ):
                    return iface
            print(f"[WARN] Interface '{self.interface_name}' not found. Available adapters:")
            for idx, iface in enumerate(interfaces, 1):
                addr = iface.address or "No IPv4"
                print(f"  [{idx}] {iface.display_name or iface.name} ({addr})")
            print(f"[INFO] Falling back to default adapter: {interfaces[0].display_name or interfaces[0].name}")

        return interfaces[0]

    def test_backend_connection(self) -> bool:
        """Verify reachability of the Sentinel backend before starting capture."""
        health_url = f"{self.backend_url}/health"
        print(f"[CONNECT] Testing backend reachability at {health_url}...")
        try:
            resp = requests.get(health_url, timeout=10)
            if resp.status_code == 200:
                print(f"[CONNECT] Backend healthy! Status: {resp.json().get('status', 'ok')}")
                return True
            print(f"[WARN] Backend returned status code {resp.status_code}")
            return True
        except requests.RequestException as exc:
            print(f"[WARN] Could not reach backend: {exc}")
            print("[INFO] Capture will continue and retry transmission automatically.")
            return False

    def validate_packet(self, record: PacketRecord) -> dict[str, Any] | None:
        """
        Validate packet metadata fields before transmission.
        Ensures strict schema conformance with Sentinel backend expectations.
        """
        if not isinstance(record.timestamp, (int, float)) or record.timestamp <= 0:
            return None

        # Protocol normalization
        proto = str(record.protocol).upper() if record.protocol else "OTHER"
        if proto not in {"TCP", "UDP", "ICMP", "OTHER"}:
            proto = "OTHER"

        return {
            "timestamp": float(record.timestamp),
            "src_ip": str(record.src_ip) if record.src_ip else None,
            "dst_ip": str(record.dst_ip) if record.dst_ip else None,
            "protocol": proto,
            "src_port": int(record.src_port) if record.src_port is not None else None,
            "dst_port": int(record.dst_port) if record.dst_port is not None else None,
            "packet_size": int(record.packet_size) if record.packet_size is not None else 0,
            "tcp_flags": str(record.tcp_flags) if record.tcp_flags else None,
            "dns_query": str(record.dns_query) if record.dns_query else None,
        }

    def transmit_batch(self, batch: list[dict[str, Any]]) -> bool:
        """Send a batch of validated real packets to the Sentinel backend."""
        if not batch:
            return True

        ingest_url = f"{self.backend_url}/live/ingest"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-Capture-Key"] = self.api_key

        payload = {
            "client_id": "windows-capture-client",
            "interface": self.selected_interface.display_name if self.selected_interface else None,
            "packets": batch,
        }

        try:
            resp = requests.post(ingest_url, json=payload, headers=headers, timeout=5)
            if resp.status_code == 200:
                self._total_sent += len(batch)
                self._total_batches += 1
                return True
            if resp.status_code == 401:
                print("[ERROR] Authentication failed (401 Unauthorized). Check SENTINEL_CAPTURE_KEY.")
            else:
                print(f"[WARN] Ingest endpoint returned HTTP {resp.status_code}: {resp.text}")
            return False
        except requests.RequestException as exc:
            # Network drop or server sleep on Render
            print(f"[RETRY] Transmission failed: {exc}. Retrying...")
            return False

    def start(self) -> None:
        """Start the IntCap capture loop and real-time streaming."""
        self.selected_interface = self.select_interface()
        addr = self.selected_interface.address or "No IPv4"
        name = self.selected_interface.display_name or self.selected_interface.name

        print("=" * 60)
        print("  SENTINEL WINDOWS CAPTURE CLIENT (IntCap Live)")
        print("=" * 60)
        print(f"  Target Backend : {self.backend_url}")
        print(f"  Capture Adapter: {name}")
        print(f"  IP Address     : {addr}")
        print(f"  Batch Size     : {self.batch_size} packets")
        print(f"  Flush Interval : {self.flush_interval}s")
        print("=" * 60)
        print("[INFO] Initializing Npcap/IntCap hardware capture...")

        self.capture = LivePacketCapture(self.selected_interface.name)
        try:
            self.capture.start()
        except LiveCaptureError as exc:
            print(f"[FATAL] Live packet capture could not start: {exc}")
            print("IntCap  : FAILED")
            sys.exit(1)

        backend_ok = self.test_backend_connection()

        self._running = True
        self._start_time = time.time()
        print(f"\nIntCap  : CONNECTED ({name})")
        print(f"Backend : {'CONNECTED' if backend_ok else 'CONNECTING...'} ({self.backend_url})")
        print(f"Data    : RECEIVING real traffic...\n")

        buffer: list[dict[str, Any]] = []
        last_flush = time.time()
        last_log = time.time()
        backend_connected = backend_ok

        try:
            while self._running:
                # Drain real captured packets from Npcap queue
                records = self.capture.drain(limit=self.batch_size)

                for rec in records:
                    valid_dict = self.validate_packet(rec)
                    if valid_dict is not None:
                        buffer.append(valid_dict)
                        self._total_captured += 1

                now = time.time()
                # Transmit if buffer reaches batch size or flush interval elapsed
                if buffer and (len(buffer) >= self.batch_size or (now - last_flush) >= self.flush_interval):
                    success = self.transmit_batch(buffer)
                    if success:
                        backend_connected = True
                        buffer = []
                        last_flush = now
                    else:
                        backend_connected = False
                        # On failure, wait briefly before retrying
                        time.sleep(1.0)
                        last_flush = time.time()

                # Status report every 3 seconds
                if now - last_log >= 3.0:
                    pps = self._total_sent / max(now - self._start_time, 0.001)
                    state_str = "STREAMING" if self._total_sent > 0 else "RECEIVING"
                    print(
                        f"[STATUS] IntCap: CONNECTED | "
                        f"Backend: {'CONNECTED' if backend_connected else 'RETRYING'} | "
                        f"Data: {state_str} ({self._total_sent} pkts sent @ {pps:.1f} pps, {len(buffer)} pending)"
                    )
                    last_log = now

                time.sleep(0.02)

        except KeyboardInterrupt:
            print("\n[STOP] Stopping capture client...")
        finally:
            self.stop(buffer)

    def stop(self, pending_buffer: list[dict[str, Any]] | None = None) -> None:
        """Stop capture, flush pending records, and print final summary."""
        self._running = False
        if self.capture:
            try:
                self.capture.stop()
            except Exception:
                pass

        if pending_buffer:
            print(f"[FLUSH] Transmitting {len(pending_buffer)} remaining packets...")
            self.transmit_batch(pending_buffer)

        duration = max(time.time() - (self._start_time or time.time()), 0.001)
        print("\n" + "=" * 60)
        print("  CAPTURE SESSION SUMMARY")
        print("=" * 60)
        print(f"  Duration          : {duration:.1f} seconds")
        print(f"  Total Captured    : {self._total_captured} real packets")
        print(f"  Total Transmitted : {self._total_sent} real packets")
        print(f"  Total Batches     : {self._total_batches}")
        print(f"  Average Rate      : {self._total_sent / duration:.1f} pps")
        print("=" * 60 + "\n")


def print_interfaces() -> None:
    """Print available Windows capture interfaces."""
    print("\nScanning for Windows Npcap capture interfaces...")
    try:
        ifaces = list_capture_interfaces()
        if not ifaces:
            print("[WARN] No capture interfaces found.")
            return

        print(f"\nDiscovered {len(ifaces)} capture interface(s):")
        print("-" * 70)
        for i, iface in enumerate(ifaces, 1):
            addr = iface.address or "No IPv4 assigned"
            name = iface.display_name or iface.name
            print(f"  [{i}] {name}")
            print(f"      Device : {iface.name}")
            print(f"      Address: {addr}")
        print("-" * 70)
    except Exception as exc:
        print(f"[ERROR] Failed to list interfaces: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sentinel Windows Capture Client (IntCap to Render Bridge)"
    )
    parser.add_argument(
        "--url",
        "-u",
        default=os.getenv("SENTINEL_BACKEND_URL", "http://localhost:8000"),
        help="Sentinel backend URL (default: http://localhost:8000 or $SENTINEL_BACKEND_URL)",
    )
    parser.add_argument(
        "--interface",
        "-i",
        default=os.getenv("SENTINEL_INTERFACE", None),
        help="Interface name or partial display name to capture on (default: auto-detected LAN/Wi-Fi)",
    )
    parser.add_argument(
        "--list",
        "-l",
        action="store_true",
        help="List all available network capture interfaces on this Windows machine and exit",
    )
    parser.add_argument(
        "--key",
        "-k",
        default=os.getenv("SENTINEL_CAPTURE_KEY", None),
        help="Optional API key for authenticating with the backend",
    )
    parser.add_argument(
        "--batch-size",
        "-b",
        type=int,
        default=50,
        help="Maximum packets per transmission batch (default: 50)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.25,
        help="Flush interval in seconds (default: 0.25)",
    )

    args = parser.parse_args()

    if args.list:
        print_interfaces()
        return

    client = WindowsCaptureClient(
        backend_url=args.url,
        interface_name=args.interface,
        api_key=args.key,
        batch_size=args.batch_size,
        flush_interval=args.interval,
    )
    client.start()


if __name__ == "__main__":
    main()
