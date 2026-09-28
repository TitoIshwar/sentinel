from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from fastapi import (
    FastAPI,
    HTTPException,
    UploadFile,
    File,
    WebSocket,
    WebSocketDisconnect,
    Header,
)
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from backend.features.dns_features import DNSFeatureExtractor
from backend.features.dns_tracker import DNSTracker
from backend.features.tls_features import TLSFeatureExtractor
from backend.features.tls_tracker import TLSTracker
from backend.features.window import WindowFeatures
from backend.ingest.live_capture import (
    CaptureInterface,
    LiveCaptureError,
    LivePacketCapture,
    list_capture_interfaces,
)
from backend.ingest.replay_engine import TrafficReplayEngine
from backend.ingest.stream import PacketRecord, PacketStream
from backend.ingest.stream_processor import StreamingResult


app = FastAPI(
    title="Sentinel",
    description=(
        "AI-based passive cyber-threat detection "
        "for unidirectional IP traffic."
    ),
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# ENVIRONMENT & CORS CONFIGURATION
# ---------------------------------------------------------------------------

IS_CLOUD_DEPLOYMENT = bool(
    os.getenv("RENDER")
    or os.getenv("SENTINEL_MODE") == "cloud"
    or not sys.platform.startswith("win")
)

CAPTURE_API_KEY = os.getenv("SENTINEL_CAPTURE_KEY", "").strip()

allowed_origins_env = (
    os.getenv("SENTINEL_ALLOWED_ORIGINS")
    or os.getenv("ALLOWED_ORIGINS")
    or os.getenv("FRONTEND_URL")
)
if allowed_origins_env:
    allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
else:
    # Standard local development origins + wildcard default
    allowed_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True if allowed_origins != ["*"] else False,
    allow_methods=["*"],
    allow_headers=["*"],
)


DATASET_PATH = Path("datasets/test_traffic.pcap")

# Existing replay processor.
processor = TrafficReplayEngine()


# ---------------------------------------------------------------------------
# LIVE CAPTURE STATE
# ---------------------------------------------------------------------------

_live_lock = threading.RLock()
_live_capture: LivePacketCapture | None = None
_live_worker: threading.Thread | None = None
_live_stop_event = threading.Event()

_live_interface: CaptureInterface | None = None
_live_started_at: float | None = None
_live_last_result: StreamingResult | None = None
_live_last_error: str | None = None
_live_packets_processed = 0
_live_processing_duration = 0.0

# Remote Windows Client tracking (for Render deployment)
_live_client_last_seen: float | None = None
_live_client_interface: str | None = None
_live_is_remote = False


def _is_client_connected() -> bool:
    """Return True if a remote Windows capture client has streamed packets within the last 10s."""
    if _live_client_last_seen is None:
        return False
    return (time.time() - _live_client_last_seen) < 10.0


class PacketRecordIn(BaseModel):
    timestamp: float
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str = "OTHER"
    src_port: int | None = None
    dst_port: int | None = None
    packet_size: int = 0
    tcp_flags: str | None = None
    dns_query: str | None = None


class LiveIngestRequest(BaseModel):
    client_id: str = "windows-capture-client"
    interface: str | None = None
    packets: list[PacketRecordIn]


class LiveStartRequest(BaseModel):
    interface: str


# ---------------------------------------------------------------------------
# COMMON HELPERS
# ---------------------------------------------------------------------------

def make_normal_window(index: int) -> WindowFeatures:
    return WindowFeatures(
        start_time=float(index),
        end_time=float(index + 1),
        packet_count=20 + (index % 3),
        byte_count=2000 + (index * 20),
        packets_per_second=20.0 + (index % 3),
        bytes_per_second=2000.0 + (index * 20),
        syn_count=2,
        syns_per_second=2.0,
        syn_ratio=0.10,
        unique_src_ips=2,
        unique_dst_ips=2,
        unique_dst_ports=2,
        dominant_dst_ip="10.0.0.20",
        dominant_dst_port=443,
        source_ip_entropy=1.0,
    )


def _build_intelligence_response(final, metrics):
    """
    Shared helper that formats a completed pipeline result
    into the standard JSON response structure.
    """
    intelligence = []

    for item in final.intelligence:
        intelligence.append(
            {
                "source_ip": item.source_ip,
                "threat_class": item.threat_class,
                "unified_score": item.threat_score.unified_score,
                "risk_level": item.threat_score.risk_level,
                "detector_score": item.threat_score.detector_score,
                "ml_score": item.threat_score.ml_score,
                "correlation_score": item.threat_score.correlation_score,
                "progression_score": item.threat_score.progression_score,
                "requires_alert": item.risk_decision.requires_alert,
                "rationale": item.risk_decision.rationale,
            }
        )

    # Serialize active alert details for frontend consumption.
    # The existing active_alerts integer count is preserved for
    # backward compatibility with /status, /replay, and any other
    # existing API consumers. alert_details is the new array that
    # the frontend Alerts Queue reads after PCAP analysis.
    alert_details = []

    for active_alert in final.active_alerts:
        a = active_alert.alert

        alert_details.append(
            {
                "timestamp": (
                    a.timestamp.isoformat()
                    if a.timestamp is not None
                    else None
                ),
                "flow_id": (
                    list(a.flow_id)
                    if a.flow_id is not None
                    else None
                ),
                "threat_class": a.threat_class,
                "confidence": a.confidence,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "destination_ip": a.destination_ip,
                "source_port": a.source_port,
                "destination_port": a.destination_port,
                "protocol": a.protocol,
                "evidence": a.evidence,
                "first_seen": (
                    active_alert.first_seen.isoformat()
                    if active_alert.first_seen is not None
                    else None
                ),
                "last_seen": (
                    active_alert.last_seen.isoformat()
                    if active_alert.last_seen is not None
                    else None
                ),
                "detection_count": active_alert.detection_count,
            }
        )

    return {
        "packets_processed": metrics.packets_processed,
        "replay_duration_seconds": metrics.replay_duration,
        "processing_duration_seconds": metrics.processing_duration,
        "average_latency_ms": metrics.average_latency_ms,
        "maximum_latency_ms": metrics.maximum_latency_ms,
        "packets_per_second": metrics.packets_per_second,
        "ml_anomaly_score": final.ml_anomaly_score,
        "ml_is_anomaly": final.ml_is_anomaly,
        "active_alerts": len(final.active_alerts),
        "alert_details": alert_details,
        "correlated_chains": len(final.correlated_evidence),
        "intelligence": intelligence,
    }


def _serialize(value: Any):
    """
    Convert Sentinel dataclasses/models/enums into JSON-safe data.
    """
    if value is None:
        return None

    if is_dataclass(value):
        return jsonable_encoder(asdict(value))

    return jsonable_encoder(value)


def _serialize_live_result(result: StreamingResult | None):
    if result is None:
        return None

    return {
        "packet_timestamp": result.packet_timestamp,
        "window_features": _serialize(result.window_features),
        "new_alerts": _serialize(result.new_alerts),
        "active_alerts": _serialize(result.active_alerts),
        "correlated_evidence": _serialize(result.correlated_evidence),
        "intelligence": _serialize(result.intelligence),
        "ml_anomaly_score": result.ml_anomaly_score,
        "ml_is_anomaly": result.ml_is_anomaly,
    }


def _serialize_dns_state(dns_tracker: DNSTracker) -> dict:
    """
    Flatten all observed DNS query groups into a list of
    DnsRecord-compatible dicts for the frontend DNS Analysis page.

    Only real observed metadata is returned. Nothing is fabricated.
    """
    recent_queries: list[dict] = []

    for group in dns_tracker.get_groups():
        for ts, query in zip(group.timestamps, group.queries):
            try:
                features = DNSFeatureExtractor.extract(query)
                entropy: float | None = features.entropy
                query_length: int | None = features.query_length
            except Exception:
                entropy = None
                query_length = len(query) if query else None

            recent_queries.append(
                {
                    "source_ip": group.source_ip,
                    "destination_ip": group.destination_ip,
                    "query": query,
                    "timestamp": ts,
                    "query_length": query_length,
                    "entropy": entropy,
                }
            )

    # Keep the 200 most recent entries by timestamp.
    recent_queries.sort(key=lambda x: x["timestamp"])

    return {
        "query_count": len(recent_queries),
        "recent_queries": recent_queries[-200:],
    }


def _serialize_encrypted_sessions(tls_tracker: TLSTracker) -> dict:
    """
    Compute TLS/QUIC session features from the passive tracker groups
    and return them as EncryptedSession-compatible dicts for the
    frontend Encrypted Traffic page.

    Only metadata (packet sizes, timestamps, endpoints) is used.
    No payload is decrypted or inspected.
    """
    sessions: list[dict] = []

    for group in tls_tracker.get_groups():
        if not group.timestamps:
            continue

        try:
            features = TLSFeatureExtractor.extract(
                session_id=group.session_id,
                timestamps=group.timestamps,
                packet_sizes=group.packet_sizes,
                client_fingerprint=group.client_fingerprint,
                server_fingerprint=group.server_fingerprint,
            )
        except Exception:
            continue

        sessions.append(
            {
                "source_ip": group.source_ip,
                "destination_ip": group.destination_ip,
                "destination_port": group.destination_port,
                "protocol": group.protocol,
                "packet_count": features.packet_count,
                "total_bytes": features.total_bytes,
                "mean_packet_size": features.mean_packet_size,
                "std_packet_size": features.packet_size_stddev,
                "mean_interarrival": features.mean_interarrival,
                "std_interarrival": features.interarrival_stddev,
                "burstiness": features.burstiness,
                "client_fingerprint": group.client_fingerprint,
                "server_fingerprint": group.server_fingerprint,
            }
        )

    return {
        "encrypted_sessions": len(sessions),
        "encrypted_packet_count": sum(
            s["packet_count"] for s in sessions
        ),
        "sessions": sessions,
    }


# ---------------------------------------------------------------------------
# PCAP ANALYSIS
# ---------------------------------------------------------------------------

def _run_analysis(pcap_path: str):
    """
    Core analysis logic: reset, refit baseline, load packets,
    run replay, return formatted result.
    """
    processor.processor.reset()

    processor.processor.fit_baseline(
        [
            make_normal_window(index)
            for index in range(30)
        ]
    )

    packets = list(
        PacketStream(pcap_path).packets()
    )

    results, metrics = processor.replay(
        packets,
        mode="maximum",
    )

    if not results:
        raise HTTPException(
            status_code=400,
            detail="No packets found in PCAP.",
        )

    final = results[-1]

    return _build_intelligence_response(
        final,
        metrics,
    )


# ---------------------------------------------------------------------------
# LIVE CAPTURE WORKER
# ---------------------------------------------------------------------------

def _process_incoming_packet(packet: PacketRecord) -> None:
    """
    Process exactly one real packet through Sentinel's passive streaming pipeline.
    Updates the sliding window, threat scoring, ML anomaly detection,
    and active tracking.
    """
    global _live_last_result
    global _live_last_error
    global _live_packets_processed
    global _live_processing_duration

    packet_start = time.perf_counter()
    try:
        result = processor.processor.process_packet(packet)
        packet_end = time.perf_counter()

        with _live_lock:
            _live_last_result = result
            _live_packets_processed += 1
            _live_processing_duration += (packet_end - packet_start)
            _live_last_error = None
    except Exception as exc:
        with _live_lock:
            _live_last_error = f"{type(exc).__name__}: {exc}"


def _live_worker_loop() -> None:
    """
    Local Windows worker: drain packets from LivePacketCapture and process
    each packet through the existing SentinelStreamProcessor.

    No packet is transmitted, modified, probed, or decrypted.
    """
    while not _live_stop_event.is_set():
        with _live_lock:
            capture = _live_capture

        if capture is None:
            time.sleep(0.05)
            continue

        packets = capture.drain(limit=256)
        if not packets:
            time.sleep(0.01)
            continue

        for packet in packets:
            if _live_stop_event.is_set():
                break
            _process_incoming_packet(packet)


def _reset_live_state() -> None:
    global _live_last_result
    global _live_last_error
    global _live_packets_processed
    global _live_processing_duration
    global _live_client_last_seen
    global _live_client_interface
    global _live_is_remote

    _live_last_result = None
    _live_last_error = None
    _live_packets_processed = 0
    _live_processing_duration = 0.0
    _live_client_last_seen = None
    _live_client_interface = None
    _live_is_remote = False


def _start_live_capture(interface: CaptureInterface) -> None:
    global _live_capture
    global _live_worker
    global _live_interface
    global _live_started_at
    global _live_is_remote

    with _live_lock:
        if _live_worker is not None and _live_worker.is_alive():
            raise HTTPException(
                status_code=409,
                detail="Live capture is already running.",
            )

        # Reset analytical pipeline
        processor.processor.reset()
        processor.processor.fit_baseline(
            [make_normal_window(index) for index in range(30)]
        )

        _reset_live_state()
        _live_stop_event.clear()
        _live_started_at = time.time()
        _live_is_remote = False

        capture = LivePacketCapture(interface.name)
        try:
            capture.start()
        except LiveCaptureError as exc:
            raise HTTPException(
                status_code=500,
                detail=str(exc),
            ) from exc

        _live_capture = capture
        _live_interface = interface

        _live_worker = threading.Thread(
            target=_live_worker_loop,
            name="sentinel-live-worker",
            daemon=True,
        )
        _live_worker.start()


def _stop_live_capture() -> dict:
    global _live_capture
    global _live_worker
    global _live_interface
    global _live_started_at

    with _live_lock:
        capture = _live_capture
        worker = _live_worker
        _live_stop_event.set()

    if worker is not None:
        worker.join(timeout=2.0)

    if capture is not None:
        capture.stop()

    with _live_lock:
        captured = (
            capture.captured
            if capture is not None
            else _live_packets_processed
        )
        dropped = (
            capture.dropped
            if capture is not None
            else 0
        )
        processed = _live_packets_processed

        _live_capture = None
        _live_worker = None
        _live_interface = None
        _live_started_at = None

    return {
        "running": False,
        "captured": captured,
        "processed": processed,
        "dropped": dropped,
    }


# ---------------------------------------------------------------------------
# STARTUP
# ---------------------------------------------------------------------------

@app.on_event("startup")
def startup():
    """
    Initialize the ML baseline from trusted normal traffic before
    replay or live processing begins.
    """
    processor.processor.fit_baseline(
        [
            make_normal_window(index)
            for index in range(30)
        ]
    )


# ---------------------------------------------------------------------------
# BASIC ENDPOINTS
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {
        "name": "Sentinel",
        "status": "running",
        "mode": "passive",
        "payload_decryption": False,
        "active_mitigation": False,
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "healthy": True,
        "ml_ready": (
            processor.processor.pipeline.is_ml_ready()
        ),
    }


@app.get("/status")
def status():
    pipeline = processor.processor.pipeline

    alerts = pipeline.get_active_alerts()
    incidents = pipeline.get_incidents()
    evidence = pipeline.get_correlated_evidence()
    intelligence = pipeline.get_intelligence()

    with _live_lock:
        live_running = (
            _live_capture is not None
            and _live_capture.running
        )

    return {
        "active_alerts": len(alerts),
        "incidents": len(incidents),
        "correlated_chains": len(evidence),
        "intelligence_results": len(intelligence),
        "ml_ready": pipeline.is_ml_ready(),
        "live_capture": live_running,
    }


# ---------------------------------------------------------------------------
# CAPTURE INTERFACES
# ---------------------------------------------------------------------------

@app.get("/interfaces")
def interfaces():
    """
    Return locally visible Npcap capture interfaces on Windows,
    or remote client adapter information when deployed on Render/cloud.
    """
    if IS_CLOUD_DEPLOYMENT:
        if _live_client_interface:
            return [
                {
                    "name": _live_client_interface,
                    "address": "remote",
                    "display_name": f"{_live_client_interface} (Windows Client)",
                }
            ]
        return [
            {
                "name": "windows-client",
                "address": None,
                "display_name": "Windows Client Adapter (Connect windows_client.py)",
            }
        ]

    try:
        discovered = list_capture_interfaces()
        return [
            {
                "name": item.name,
                "address": item.address,
                "display_name": item.display_name,
            }
            for item in discovered
        ]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# REMOTE CAPTURE INGESTION API (Used by Windows Client)
# ---------------------------------------------------------------------------

@app.post("/live/ingest")
def live_ingest(
    payload: LiveIngestRequest,
    x_capture_key: str | None = Header(None, alias="X-Capture-Key"),
    authorization: str | None = Header(None),
):
    """
    Ingest REAL live-captured packet records from the Windows Capture Client.
    Validates, parses, and executes the passive Sentinel pipeline on each real packet.
    """
    if CAPTURE_API_KEY:
        auth_token = None
        if authorization and authorization.startswith("Bearer "):
            auth_token = authorization[7:].strip()
        provided = x_capture_key or auth_token
        if provided != CAPTURE_API_KEY:
            raise HTTPException(
                status_code=401,
                detail="Unauthorized capture client key.",
            )

    global _live_started_at
    global _live_client_last_seen
    global _live_client_interface
    global _live_is_remote

    with _live_lock:
        if _live_started_at is None:
            _live_started_at = time.time()
        _live_client_last_seen = time.time()
        if payload.interface:
            _live_client_interface = payload.interface
        _live_is_remote = True

    count = 0
    for p in payload.packets:
        rec = PacketRecord(
            timestamp=p.timestamp,
            src_ip=p.src_ip,
            dst_ip=p.dst_ip,
            protocol=p.protocol,
            src_port=p.src_port,
            dst_port=p.dst_port,
            packet_size=p.packet_size,
            tcp_flags=p.tcp_flags,
            dns_query=p.dns_query,
        )
        _process_incoming_packet(rec)
        count += 1

    return {
        "status": "ok",
        "received": count,
        "total_processed": _live_packets_processed,
    }


@app.websocket("/live/ws")
async def live_ws(websocket: WebSocket):
    """
    Real-time streaming WebSocket endpoint for the Windows Capture Client.
    """
    await websocket.accept()
    global _live_started_at
    global _live_client_last_seen
    global _live_client_interface
    global _live_is_remote

    try:
        while True:
            data = await websocket.receive_json()
            if not isinstance(data, dict):
                continue

            if CAPTURE_API_KEY:
                if data.get("key") != CAPTURE_API_KEY:
                    await websocket.send_json({"error": "Unauthorized key"})
                    await websocket.close(code=1008)
                    return

            packets_data = data.get("packets", [])
            if not isinstance(packets_data, list):
                continue

            with _live_lock:
                if _live_started_at is None:
                    _live_started_at = time.time()
                _live_client_last_seen = time.time()
                if data.get("interface"):
                    _live_client_interface = data["interface"]
                _live_is_remote = True

            count = 0
            for p in packets_data:
                try:
                    rec = PacketRecord(
                        timestamp=float(p.get("timestamp", time.time())),
                        src_ip=p.get("src_ip"),
                        dst_ip=p.get("dst_ip"),
                        protocol=str(p.get("protocol", "OTHER")),
                        src_port=p.get("src_port"),
                        dst_port=p.get("dst_port"),
                        packet_size=int(p.get("packet_size", 0)),
                        tcp_flags=p.get("tcp_flags"),
                        dns_query=p.get("dns_query"),
                    )
                    _process_incoming_packet(rec)
                    count += 1
                except Exception:
                    continue

            await websocket.send_json({
                "status": "ok",
                "received": count,
                "total_processed": _live_packets_processed,
            })
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# LIVE CAPTURE CONTROL API
# ---------------------------------------------------------------------------

@app.post("/live/start")
def live_start(request: LiveStartRequest):
    if IS_CLOUD_DEPLOYMENT:
        # On Render cloud deployment:
        # Physical IntCap hardware capture runs on the Windows client machine, not on Render.
        # Initialize the pipeline to receive live telemetry from the Windows client.
        with _live_lock:
            processor.processor.reset()
            processor.processor.fit_baseline(
                [make_normal_window(index) for index in range(30)]
            )
            _reset_live_state()
            _live_started_at = time.time()
            _live_is_remote = True

        return {
            "status": "listening",
            "mode": "cloud",
            "client_connected": _is_client_connected(),
            "interface": None,
            "message": (
                "Render backend is listening for real capture data. "
                "Connect the Windows capture client on your laptop to stream live traffic."
            ),
            "mode_type": "passive",
            "payload_decryption": False,
            "active_mitigation": False,
        }

    # LOCAL WINDOWS MODE:
    discovered = list_capture_interfaces()
    selected = next(
        (item for item in discovered if item.name == request.interface),
        None,
    )

    if selected is None and discovered:
        selected = discovered[0]

    if selected is None:
        raise HTTPException(
            status_code=404,
            detail=f"Capture interface '{request.interface}' was not found.",
        )

    _start_live_capture(selected)

    return {
        "status": "started",
        "mode": "local",
        "interface": {
            "name": selected.name,
            "address": selected.address,
            "display_name": selected.display_name,
        },
        "mode_type": "passive",
        "payload_decryption": False,
        "active_mitigation": False,
    }


@app.get("/live/status")
def live_status():
    with _live_lock:
        capture = _live_capture
        worker = _live_worker

        local_running = (
            capture is not None
            and capture.running
            and worker is not None
            and worker.is_alive()
        )

        client_connected = _is_client_connected()

        is_running = local_running or (_live_is_remote and client_connected)

        captured = (
            capture.captured
            if capture is not None
            else _live_packets_processed
        )

        dropped = (
            capture.dropped
            if capture is not None
            else 0
        )

        processed = _live_packets_processed
        started_at = _live_started_at
        last_result = _live_last_result
        last_error = _live_last_error
        processing_duration = _live_processing_duration
        interface = _live_interface
        client_iface = _live_client_interface

    elapsed = (
        max(time.time() - started_at, 0.0)
        if started_at is not None
        else 0.0
    )

    packets_per_second = (
        processed / processing_duration
        if processing_duration > 0
        else 0.0
    )

    # STRICT RULE: ONLY return result if real packets were processed!
    # No fake data when processed == 0.
    result_data = _serialize_live_result(last_result) if processed > 0 else None

    if result_data is not None:
        pipeline = processor.processor.pipeline
        result_data["dns"] = _serialize_dns_state(pipeline.dns_tracker)
        result_data["encrypted"] = _serialize_encrypted_sessions(pipeline.tls_tracker)

    interface_payload = None
    if interface is not None:
        interface_payload = {
            "name": interface.name,
            "address": interface.address,
            "display_name": interface.display_name,
        }
    elif client_iface is not None:
        interface_payload = {
            "name": client_iface,
            "address": "remote",
            "display_name": f"{client_iface} (Windows Client)",
        }

    return {
        "running": is_running,
        "mode": "cloud" if IS_CLOUD_DEPLOYMENT else "local",
        "client_connected": client_connected,
        "interface": interface_payload,
        "captured": captured,
        "processed": processed,
        "dropped": dropped,
        "elapsed_seconds": round(elapsed, 3),
        "processing_duration_seconds": round(processing_duration, 6),
        "packets_per_second": round(packets_per_second, 2),
        "last_error": last_error,
        "result": result_data,
    }


@app.get("/live/events")
def live_events():
    """
    Return the latest processed live intelligence snapshot.
    The frontend can poll this endpoint without requiring a WebSocket connection.
    """
    with _live_lock:
        result = _live_last_result
        processed = _live_packets_processed

    # STRICT RULE: No fake result if 0 packets processed
    if processed == 0:
        return {"result": None}

    return {
        "result": _serialize_live_result(result)
    }


@app.post("/live/stop")
def live_stop():
    with _live_lock:
        local_running = (
            _live_capture is not None
            and _live_capture.running
        )
        remote_running = _live_is_remote

    if not local_running and not remote_running:
        return {
            "status": "already_stopped",
            "running": False,
        }

    metrics = _stop_live_capture()
    with _live_lock:
        _reset_live_state()

    return {
        "status": "stopped",
        **metrics,
    }


# ---------------------------------------------------------------------------
# PCAP REPLAY
# ---------------------------------------------------------------------------

@app.post("/replay")
def replay():
    if not DATASET_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail="Test PCAP not found.",
        )

    return _run_analysis(
        str(DATASET_PATH)
    )


# ---------------------------------------------------------------------------
# REPLAY TELEMETRY
# ---------------------------------------------------------------------------

@app.get("/replay/stream")
def replay_stream():
    """
    Return the real Sentinel telemetry series generated from
    the bundled test PCAP.

    This endpoint uses the same passive detection pipeline as
    /replay, but exposes every intermediate WindowFeatures result
    so the frontend can populate its traffic history graph.

    No synthetic traffic values are generated.
    No packets are transmitted.
    """
    if not DATASET_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail="Test PCAP not found.",
        )

    # Start from a clean analytical state.
    processor.processor.reset()

    # Establish the same trusted ML baseline used by /replay
    # and /live/start.
    processor.processor.fit_baseline(
        [
            make_normal_window(index)
            for index in range(30)
        ]
    )

    packets = list(
        PacketStream(DATASET_PATH).packets()
    )

    results, metrics = processor.replay(
        packets,
        mode="maximum",
    )

    if not results:
        raise HTTPException(
            status_code=400,
            detail="No packets found in PCAP.",
        )

    points = []

    for result in results:
        window = result.window_features

        if window is None:
            continue

        points.append(
            {
                "timestamp": result.packet_timestamp,
                "pps": window.packets_per_second,
                "bps": window.bytes_per_second,
                "syn": window.syns_per_second,
                "packet_count": window.packet_count,
                "byte_count": window.byte_count,
                "ml_anomaly_score": (
                    result.ml_anomaly_score
                ),
                "ml_is_anomaly": (
                    result.ml_is_anomaly
                ),
            }
        )

    final = results[-1]

    analysis = _build_intelligence_response(
        final,
        metrics,
    )

    return {
        **analysis,
        "points": points,
    }


# ---------------------------------------------------------------------------
# PCAP UPLOAD
# ---------------------------------------------------------------------------

@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
):
    """
    Accept a user-uploaded PCAP file, run the full
    passive detection pipeline on it, and return
    the intelligence report.

    The uploaded file is written to a temporary location,
    processed, then deleted.
    """
    if (
        not file.filename
        or not (
            file.filename.endswith(".pcap")
            or file.filename.endswith(".pcapng")
        )
    ):
        raise HTTPException(
            status_code=400,
            detail="Only .pcap and .pcapng files are supported.",
        )

    tmp_path = None

    try:
        contents = await file.read()

        with tempfile.NamedTemporaryFile(
            suffix=".pcap",
            delete=False,
        ) as tmp:
            tmp.write(contents)
            tmp_path = tmp.name

        return _run_analysis(
            tmp_path
        )

    finally:
        if (
            tmp_path
            and os.path.exists(tmp_path)
        ):
            os.remove(tmp_path)