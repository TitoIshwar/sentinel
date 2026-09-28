import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  ReactNode,
} from 'react';
import { useToast } from './ToastContext';

import {
  BackendAlert,
  CorrelatedEvidence,
  DetectorCoverage,
  DnsRecord,
  EncryptedSession,
  FlowRecord,
  IntelligenceResult,
  MapNode,
  NetworkFlow,
  PipelineSnapshot,
  SecurityReport,
  ThreatEvent,
  AlertItem,
  WindowFeatures,
  ProtocolType,
} from '../types/cybersecurity';

export type PageId =
  | 'landing'
  | 'dashboard'
  | 'traffic'
  | 'threats'
  | 'encrypted'
  | 'dns'
  | 'correlation'
  | 'incidents'
  | 'ip-intel'
  | 'ai-insights'
  | 'alerts'
  | 'reports'
  | 'settings';

export type SourceMode = 'demo' | 'pcap' | 'live';

export type ConnectionState =
  | 'offline'
  | 'connecting'
  | 'streaming'
  | 'capturing'
  | 'paused'
  | 'complete'
  | 'error';

export interface CaptureInterface {
  name: string;
  address?: string;
  display_name?: string;
  friendly_name?: string;
  description?: string;
  is_loopback?: boolean;
}

export interface BackendStatus {
  status?: string;
  service?: string;
  version?: string;
  read_only?: boolean;
  passive?: boolean;
  [key: string]: unknown;
}

export interface BackendTelemetry {
  packet_count?: number;
  packets_processed?: number;
  packets_per_second?: number;
  bytes_per_second?: number;
  byte_count?: number;
  flow_groups?: number;
  [key: string]: unknown;
}

export interface BackendSourceInfo {
  mode?: SourceMode | string;
  scenario?: string;
  interface?: string;
  interface_name?: string;
  [key: string]: unknown;
}

export interface BackendPcapMetrics {
  packets_processed?: number;
  replay_duration?: number;
  processing_duration?: number;
  average_latency_ms?: number;
  maximum_latency_ms?: number;
  packets_per_second?: number;
  [key: string]: unknown;
}

export interface BackendAnalysisResponse {
  type?: string;
  status?: string;
  timestamp?: string;

  alerts?: BackendAlert[];
  new_alerts?: BackendAlert[];
  active_alerts?: BackendAlert[];

  incidents?: BackendAlert[];
  correlated_evidence?: CorrelatedEvidence[];
  intelligence?: IntelligenceResult[];
  detector_coverage?: DetectorCoverage[];

  flows?: FlowRecord[];

  window?: WindowFeatures;

  dns?: {
    recent_queries?: DnsRecord[];
    [key: string]: unknown;
  };

  encrypted?: {
    sessions?: EncryptedSession[];
    [key: string]: unknown;
  };

  telemetry?: BackendTelemetry;

  ml?: {
    score?: number;
    is_anomaly?: boolean;
    ready?: boolean;
    [key: string]: unknown;
  };

  ml_anomaly_score?: number;
  ml_is_anomaly?: boolean;

  processing_latency_ms?: number;

  metrics?: BackendPcapMetrics;

  /*
   * packets_processed is returned at the top level of the /analyze
   * and /replay responses (not nested under metrics).
   */
  packets_processed?: number;

  /*
   * alert_details carries the serialized ActiveAlert/ThreatAlert array
   * returned by /analyze and /replay so the Alerts Queue can render
   * real alert rows immediately after PCAP upload.
   * active_alerts remains the integer count for backward compatibility.
   */
  alert_details?: BackendAlert[];

  summary?: {
    ml_anomaly_score?: number;
    ml_is_anomaly?: boolean;
    highest_score?: number;
    highest_risk?: string;
    alert_count?: number;
    correlated_chain_count?: number;
    [key: string]: unknown;
  };

  source?: BackendSourceInfo;

  [key: string]: unknown;
}

export interface TrafficHistoryPoint {
  time: string;
  pps: number;
  bps: number;
  syn: number;
  anomaly: number;
}

const STORAGE_KEY = 'sentinel_api_url';

function getApiBase(): string {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored && stored.trim()) return stored.trim().replace(/\/$/, '');
  } catch { /* ignore */ }
  return (
    import.meta.env.VITE_SENTINEL_API_URL ||
    'http://127.0.0.1:8000'
  ).replace(/\/$/, '');
}

const API_BASE = getApiBase();

const emptyWindow: WindowFeatures = {
  packet_count: 0,
  byte_count: 0,
  packets_per_second: 0,
  bytes_per_second: 0,
  syn_count: 0,
  syns_per_second: 0,
  syn_ratio: 0,
  unique_src_ips: 0,
  unique_dst_ips: 0,
  unique_dst_ports: 0,
  source_ip_entropy: 0,
};

function protocol(value?: string): ProtocolType {
  const p = String(value || 'OTHER').toUpperCase();

  if (
    p === 'TCP' ||
    p === 'UDP' ||
    p === 'ICMP' ||
    p === 'GRE' ||
    p === 'ESP'
  ) {
    return p;
  }

  return 'OTHER';
}

function numberValue(value: unknown, fallback = 0): number {
  const n = Number(value);

  return Number.isFinite(n) ? n : fallback;
}

function stringValue(value: unknown, fallback = ''): string {
  if (value === null || value === undefined) {
    return fallback;
  }

  return String(value);
}

function severityRank(severity?: string): number {
  switch (String(severity || '').toUpperCase()) {
    case 'CRITICAL':
      return 4;
    case 'HIGH':
      return 3;
    case 'MEDIUM':
      return 2;
    case 'LOW':
      return 1;
    default:
      return 0;
  }
}

function threatId(alert: BackendAlert, index: number): string {
  return [
    alert.threat_class || 'UNKNOWN',
    alert.source_ip || 'window',
    alert.destination_ip || '',
    alert.destination_port || '',
    alert.protocol || '',
    index,
  ].join('-');
}

function adaptThreat(
  alert: BackendAlert,
  index: number,
  mlScore = 0,
): ThreatEvent {
  return {
    id: threatId(alert, index),

    severity: alert.severity,

    sourceIp: alert.source_ip || '—',
    destinationIp: alert.destination_ip || '—',

    protocol: protocol(alert.protocol),

    flowDuration: '—',

    anomalyScore: Math.round(
      Math.max(numberValue(alert.confidence), mlScore) * 100,
    ),

    threatType: alert.threat_class,

    status: 'Active',

    time:
      alert.last_seen ||
      alert.timestamp ||
      new Date().toISOString(),

    confidence: numberValue(alert.confidence),

    flowId:
      typeof alert.flow_id === 'string'
        ? alert.flow_id
        : undefined,

    evidence: alert.evidence || {},
  };
}

function adaptFlow(
  flow: FlowRecord,
  index: number,
  mlScore: number,
): NetworkFlow {
  const start =
    stringValue(flow.start) ||
    stringValue(flow.first_seen);

  const end =
    stringValue(flow.end) ||
    stringValue(flow.last_seen) ||
    start;

  let duration = 0;

  if (start && end) {
    const startMs = Date.parse(start);
    const endMs = Date.parse(end);

    if (
      Number.isFinite(startMs) &&
      Number.isFinite(endMs)
    ) {
      duration = Math.max(0, (endMs - startMs) / 1000);
    }
  }

  return {
    id: stringValue(
      flow.id || flow.flow_id,
      `flow-${index}`,
    ),

    sourceIp: stringValue(flow.source_ip),
    destinationIp: stringValue(flow.destination_ip),

    sourcePort: numberValue(flow.source_port),
    destinationPort: numberValue(flow.destination_port),

    protocol: protocol(flow.protocol),

    duration,

    packets: numberValue(
      flow.packet_count ?? flow.packets,
    ),

    bytes: numberValue(
      flow.byte_count ?? flow.bytes,
    ),

    direction: 'Egress (One-Way)',

    anomalyScore: Math.round(
      Math.max(0, Math.min(1, mlScore)) * 100,
    ),

    aiClassification: 'Observed Traffic',

    timestamp:
      end ||
      start ||
      new Date().toISOString(),
  };
}

function normaliseAlerts(
  response: BackendAnalysisResponse,
): BackendAlert[] {
  // alert_details is the serialized array returned by /analyze and /replay.
  // Check it first so PCAP results populate the Alerts Queue correctly.
  if (Array.isArray(response.alert_details)) {
    return response.alert_details;
  }

  if (Array.isArray(response.active_alerts)) {
    return response.active_alerts;
  }

  if (Array.isArray(response.alerts)) {
    return response.alerts;
  }

  return [];
}

function normaliseIncidents(
  response: BackendAnalysisResponse,
  fallbackAlerts: BackendAlert[],
): BackendAlert[] {
  if (Array.isArray(response.incidents)) {
    return response.incidents;
  }

  return fallbackAlerts;
}

function normaliseWindow(
  response: BackendAnalysisResponse,
): WindowFeatures {
  return {
    ...emptyWindow,
    ...(response.window || {}),
  };
}

function buildSnapshot(
  response: BackendAnalysisResponse,
  previous?: PipelineSnapshot | null,
): PipelineSnapshot {
  const alerts = normaliseAlerts(response);

  const mlScore = numberValue(
    response.ml?.score ??
      response.ml_anomaly_score ??
      response.summary?.ml_anomaly_score,
  );

  const mlIsAnomaly =
    Boolean(
      response.ml?.is_anomaly ??
        response.ml_is_anomaly ??
        response.summary?.ml_is_anomaly,
    );

  const mlReady =
    response.ml?.ready !== undefined
      ? Boolean(response.ml.ready)
      : previous?.ml?.ready ?? true;

  const window = normaliseWindow(response);

  return {
    ...(previous || {}),

    type: 'snapshot',

    timestamp:
      response.timestamp ||
      previous?.timestamp ||
      new Date().toISOString(),

    window,

    flows:
      Array.isArray(response.flows)
        ? response.flows
        : previous?.flows || [],

    active_alerts: alerts,

    new_alerts:
      Array.isArray(response.new_alerts)
        ? response.new_alerts
        : alerts,

    incidents: normaliseIncidents(
      response,
      alerts,
    ),

    correlated_evidence:
      Array.isArray(response.correlated_evidence)
        ? response.correlated_evidence
        : previous?.correlated_evidence || [],

    intelligence:
      Array.isArray(response.intelligence)
        ? response.intelligence
        : previous?.intelligence || [],

    detector_coverage:
      Array.isArray(response.detector_coverage)
        ? response.detector_coverage
        : previous?.detector_coverage || [],

    dns:
      response.dns ||
      previous?.dns,

    encrypted:
      response.encrypted ||
      previous?.encrypted,

    telemetry:
      response.telemetry ||
      previous?.telemetry,

    ml: {
      score: mlScore,
      is_anomaly: mlIsAnomaly,
      ready: mlReady,
    },

    ml_anomaly_score: mlScore,
    ml_is_anomaly: mlIsAnomaly,

    processing_latency_ms:
      numberValue(
        response.processing_latency_ms,
      ),

    /*
     * Preserve the complete backend source object.
     * This contains mode/scenario/interface information
     * used by the frontend source controls and diagnostics.
     */
    source:
      response.source ||
      previous?.source,

    /*
     * Preserve replay/PCAP metrics directly in the snapshot
     * when supplied by the backend.
     */
    metrics:
      response.metrics ||
      previous?.metrics,
  };
}

interface SecurityContextType {
  activePage: PageId;
  setActivePage: (page: PageId) => void;

  threats: ThreatEvent[];
  flows: NetworkFlow[];
  alerts: AlertItem[];

  mapNodes: MapNode[];

  reports: SecurityReport[];

  selectedFlow: NetworkFlow | null;
  setSelectedFlow: (
    flow: NetworkFlow | null,
  ) => void;

  selectedNode: MapNode | null;
  setSelectedNode: (
    node: MapNode | null,
  ) => void;

  selectedIp: string;
  setSelectedIp: (ip: string) => void;

  globalSearch: string;
  setGlobalSearch: (value: string) => void;

  inspectThreatModal: ThreatEvent | null;
  setInspectThreatModal: (
    threat: ThreatEvent | null,
  ) => void;

  reportModal: SecurityReport | null;
  setReportModal: (
    report: SecurityReport | null,
  ) => void;

  updateAlertStatus: (
    id: string,
    status:
      | 'Active'
      | 'Investigating'
      | 'Resolved'
      | 'False Positive',
  ) => void;

  updateThreatStatus: (
    id: string,
    status: ThreatEvent['status'],
  ) => void;

  liveFlowCount: number;
  livePacketsPerSec: number;
  liveBytesPerSec: string;
  lastAnalysisSec: number;

  navigateToIp: (ip: string) => void;
  navigateToFlow: (id: string) => void;

  apiBase: string;
  setApiBaseUrl: (url: string) => void;
  clientConnected: boolean;
  captureMode: 'local' | 'cloud';

  connection: ConnectionState;

  sourceMode: SourceMode;

  scenario: string;
  setScenario: (scenario: string) => void;

  interfaces: CaptureInterface[];
  selectedInterface: string;
  setSelectedInterface: (
    value: string,
  ) => void;

  startStream: (
    mode?: SourceMode,
  ) => void;

  stopStream: () => void;
  pauseStream: () => void;
  resumeStream: () => void;

  analyzePcap: (
    file: File,
  ) => Promise<void>;

  refreshInterfaces: () => Promise<void>;

  backendOnline: boolean;
  backendStatus: BackendStatus | null;

  snapshot: PipelineSnapshot | null;

  latestWindow: WindowFeatures;

  mlScore: number;
  mlIsAnomaly: boolean;
  mlReady: boolean;

  correlatedEvidence: CorrelatedEvidence[];
  intelligence: IntelligenceResult[];
  incidents: BackendAlert[];

  dnsQueries: DnsRecord[];
  encryptedSessions: EncryptedSession[];

  detectorCoverage: DetectorCoverage[];

  trafficHistory: TrafficHistoryPoint[];

  sourceInfo: BackendSourceInfo | null;

  metrics: BackendPcapMetrics | null;

  clearAnalyticalState: () => void;
}

const SecurityContext =
  createContext<SecurityContextType | undefined>(
    undefined,
  );

export const SecurityProvider: React.FC<{
  children: ReactNode;
}> = ({ children }) => {
  const { showToast } = useToast();

  const [activePage, setActivePage] =
    useState<PageId>('landing');

  const [snapshot, setSnapshot] =
    useState<PipelineSnapshot | null>(null);

  const [connection, setConnection] =
    useState<ConnectionState>('offline');

  const [backendOnline, setBackendOnline] =
    useState(false);

  const [backendStatus, setBackendStatus] =
    useState<BackendStatus | null>(null);

  const [sourceMode, setSourceMode] =
    useState<SourceMode>('demo');

  const [scenario, setScenario] =
    useState('full-chain');

  const [interfaces, setInterfaces] =
    useState<CaptureInterface[]>([]);

  const [selectedInterface, setSelectedInterface] =
    useState('');

  const [trafficHistory, setTrafficHistory] =
    useState<TrafficHistoryPoint[]>([]);

  const [selectedFlow, setSelectedFlow] =
    useState<NetworkFlow | null>(null);

  const [selectedNode, setSelectedNode] =
    useState<MapNode | null>(null);

  const [selectedIp, setSelectedIp] =
    useState('');

  const [globalSearch, setGlobalSearch] =
    useState('');

  const [inspectThreatModal, setInspectThreatModal] =
    useState<ThreatEvent | null>(null);

  const [reportModal, setReportModal] =
    useState<SecurityReport | null>(null);

  const [reports, setReports] =
    useState<SecurityReport[]>([]);

  const connectionRef =
    useRef<ConnectionState>('offline');

  /*
   * Live capture polling state.
   *
   * The backend performs the actual passive packet capture.
   * The frontend only polls the read-only live status endpoint.
   */
  const livePollRef =
    useRef<number | null>(null);

  const livePollInFlightRef =
    useRef(false);

  const snapshotRef =
    useRef<PipelineSnapshot | null>(null);

  const [clientConnected, setClientConnected] = useState(false);
  const [captureMode, setCaptureMode] = useState<'local' | 'cloud'>('local');

  const [apiBase, setApiBaseState] = useState(API_BASE);

  const setApiBaseUrl = useCallback((url: string) => {
    const clean = url.trim().replace(/\/$/, '');
    try { localStorage.setItem(STORAGE_KEY, clean); } catch { /* ignore */ }
    // Reload so all existing fetch calls use the new URL.
    window.location.reload();
  }, []);

  const setConnectionSafe = useCallback(
    (state: ConnectionState) => {
      connectionRef.current = state;
      setConnection(state);
    },
    [],
  );

  const consume = useCallback(
    (
      response:
        | PipelineSnapshot
        | BackendAnalysisResponse,
    ) => {
      const previous =
        snapshotRef.current;

      const next = buildSnapshot(
        response as BackendAnalysisResponse,
        previous,
      );

      snapshotRef.current = next;

      setSnapshot(next);

      const window =
        next.window || emptyWindow;

      const ml =
        numberValue(
          next.ml?.score ??
            next.ml_anomaly_score,
        );

      // STRICT RULE: Only append to trafficHistory if real packets have been processed!
      // Never push dummy 0-points when no real data has been received.
      const hasRealTraffic =
        numberValue(next.telemetry?.packets_processed, 0) > 0 ||
        numberValue(next.window?.packet_count, 0) > 0 ||
        numberValue(next.window?.packets_per_second, 0) > 0;

      if (hasRealTraffic) {
        setTrafficHistory((history) => [
          ...history,
          {
            time:
              next.timestamp ||
              new Date().toISOString(),

            pps: numberValue(
              window.packets_per_second,
            ),

            bps: numberValue(
              window.bytes_per_second,
            ),

            syn: numberValue(
              window.syns_per_second,
            ),

            anomaly: ml,
          },
        ].slice(-120));
      }
    },
    [],
  );

  const clearLivePolling = useCallback(() => {
    if (livePollRef.current !== null) {
      window.clearInterval(
        livePollRef.current,
      );

      livePollRef.current = null;
    }

    livePollInFlightRef.current = false;
  }, []);

  const pollLiveStatus = useCallback(
    async () => {
      if (livePollInFlightRef.current) {
        return;
      }

      if (
        connectionRef.current !== 'capturing' &&
        connectionRef.current !== 'streaming'
      ) {
        return;
      }

      livePollInFlightRef.current = true;

      try {
        const response =
          await fetch(
            `${apiBase}/live/status`,
            {
              method: 'GET',
              cache: 'no-store',
            },
          );

        if (!response.ok) {
          throw new Error(
            `Live status returned ${response.status}`,
          );
        }

        const data =
          (await response.json()) as BackendAnalysisResponse & {
            running?: boolean;
            mode?: 'local' | 'cloud';
            client_connected?: boolean;
            captured?: number;
            processed?: number;
            dropped?: number;
            packets_per_second?: number;
            bytes_per_second?: number;
            result?: BackendAnalysisResponse & {
              packet_timestamp?: number;
            };
          };

        if (data.client_connected !== undefined) {
          setClientConnected(Boolean(data.client_connected));
        }
        if (data.mode) {
          setCaptureMode(data.mode as 'local' | 'cloud');
        }

        /*
         * The live endpoint wraps Sentinel's analytical snapshot
         * inside `result`, while capture telemetry such as captured,
         * processed and packets_per_second is returned at the top level.
         *
         * Flatten the live `result` into the normal frontend response
         * shape so the existing buildSnapshot()/Dashboard pipeline can
         * consume the real live window, alerts, intelligence and ML data.
         */
        const analyticalResult =
          data.result || {};

        const existingTelemetry =
          data.telemetry || {};

        const liveTelemetry: BackendTelemetry = {
          ...existingTelemetry,

          packet_count:
            existingTelemetry.packet_count ??
            data.captured,

          packets_processed:
            existingTelemetry.packets_processed ??
            data.processed,

          packets_per_second:
            existingTelemetry.packets_per_second ??
            data.packets_per_second,

          bytes_per_second:
            existingTelemetry.bytes_per_second ??
            data.bytes_per_second,
        };

        /*
         * The backend wraps each active alert inside an ActiveAlert dataclass:
         *   { alert: ThreatAlert, detection_count, observation_count, first_seen, last_seen }
         * Flatten the nested ThreatAlert fields to the top level so
         * buildSnapshot()/normaliseAlerts() can map threat_class, source_ip etc.
         */
        const liveActiveAlerts: BackendAlert[] | undefined =
          Array.isArray(analyticalResult.active_alerts)
            ? (
                analyticalResult.active_alerts as unknown[]
              ).map((item) => {
                const activeAlert = item as {
                  alert?: Record<string, unknown>;
                  detection_count?: number;
                  observation_count?: number;
                  first_seen?: string;
                  last_seen?: string;
                };
                const inner = activeAlert.alert || {};
                return {
                  ...inner,
                  detection_count:
                    activeAlert.detection_count,
                  observation_count:
                    activeAlert.observation_count,
                  first_seen:
                    activeAlert.first_seen ??
                    (inner.timestamp as
                      | string
                      | undefined),
                  last_seen:
                    activeAlert.last_seen ??
                    (inner.timestamp as
                      | string
                      | undefined),
                } as unknown as BackendAlert;
              })
            : undefined;

        /*
         * Derive FlowRecord-compatible objects from the flattened active
         * alerts.  Each backend alert carries the real 5-tuple
         * (source_ip, destination_ip, source_port, destination_port,
         * protocol) of the network flow that triggered it.
         * Only used when the backend has not returned explicit flow records.
         */
        const alertDerivedFlows: FlowRecord[] =
          !Array.isArray(analyticalResult.flows) &&
          Array.isArray(liveActiveAlerts) &&
          liveActiveAlerts.length > 0
            ? liveActiveAlerts
                .filter(
                  (a) =>
                    a.source_ip != null ||
                    a.destination_ip != null,
                )
                .map((a, i) => {
                  /*
                   * Each detector stores packet/byte data in `evidence`
                   * under detector-specific keys.  Try the most
                   * meaningful field for each metric in priority order:
                   *
                   * packet_count:
                   *   total_packets   → PortScanDetector
                   *   window_packets  → DDoSDetector
                   *   observation_count → C2BeaconDetector
                   *   total_queries   → DNSTunnellingDetector
                   *
                   * byte_count:
                   *   window_bytes      → DDoSDetector
                   *   total_query_bytes → DNSTunnellingDetector
                   */
                  const ev = (
                    (a.evidence || {}) as Record<
                      string,
                      unknown
                    >
                  );

                  /*
                   * Exfiltration evidence stores outbound and inbound
                   * packet counts separately; sum them for the total.
                   * Only used when no other detector provides a count.
                   */
                  const exfilPkts =
                    numberValue(ev.outbound_packets, 0) +
                    numberValue(ev.inbound_packets, 0);

                  const pktCount = numberValue(
                    ev.total_packets ??          // PortScan, Recon
                    ev.packet_count ??           // EncryptedMalware
                    ev.window_packets ??         // DDoS
                    ev.observation_count ??      // C2
                    ev.total_queries ??          // DNS
                    (exfilPkts > 0 ? exfilPkts : undefined), // Exfiltration
                    0,
                  );

                  const byteCount = numberValue(
                    ev.total_bytes ??       // Exfiltration, EncryptedMalware
                    ev.outbound_bytes ??    // Exfiltration fallback
                    ev.window_bytes ??      // DDoS
                    ev.total_query_bytes,   // DNS
                    0,
                  );

                  return {
                    id: `live-flow-${i}`,
                    flow_id: a.flow_id,
                    source_ip:
                      a.source_ip || '0.0.0.0',
                    destination_ip:
                      a.destination_ip || '0.0.0.0',
                    source_port: a.source_port,
                    destination_port:
                      a.destination_port,
                    protocol:
                      a.protocol || 'OTHER',
                    packet_count: pktCount,
                    byte_count: byteCount,
                    first_seen: a.first_seen,
                    last_seen: a.last_seen,
                    start:
                      a.first_seen ??
                      a.timestamp,
                    end:
                      a.last_seen ??
                      a.timestamp,
                  };
                })
            : [];

        const liveResponse: BackendAnalysisResponse = {
          ...data,
          ...analyticalResult,

          /*
           * Override active_alerts with the flattened version so
           * the ThreatAlert fields (threat_class, source_ip, etc.)
           * appear at the top level as BackendAlert expects.
           */
          ...(liveActiveAlerts
            ? { active_alerts: liveActiveAlerts }
            : {}),

          /*
           * Populate flows from alert-derived records when the backend
           * live response does not include explicit flow records.
           */
          ...(alertDerivedFlows.length > 0
            ? { flows: alertDerivedFlows }
            : {}),

          /*
           * The backend returns window statistics under `result.window_features`
           * but buildSnapshot()/normaliseWindow() reads `response.window`.
           * Map window_features → window so live metrics reach the dashboard.
           */
          window:
            (analyticalResult as { window_features?: WindowFeatures }).window_features ||
            (analyticalResult as BackendAnalysisResponse).window ||
            data.window,

          timestamp:
            data.timestamp ||
            (
              analyticalResult as {
                timestamp?: string;
              }
            ).timestamp ||
            new Date().toISOString(),

          telemetry:
            Object.keys(liveTelemetry).length > 0
              ? liveTelemetry
              : data.telemetry,
        };

        if (data.processed !== undefined && data.processed > 0 && data.result) {
          consume(liveResponse);
        } else if (Object.keys(liveTelemetry).length > 0) {
          setSnapshot((prev) => (prev ? { ...prev, telemetry: liveTelemetry } : null));
        }

        setBackendOnline(true);

        // In cloud mode, backend is waiting for remote Windows client, so do NOT terminate polling.
        // Only terminate polling in local mode if capture has terminated and no client is connected.
        if (data.mode !== 'cloud' && data.running === false && !data.client_connected) {
          clearLivePolling();
          setConnectionSafe('complete');
        }
      } catch (error) {
        /*
         * Do not immediately kill the stream on a single polling
         * failure. A temporary HTTP/network hiccup should not
         * terminate the backend capture itself.
         */
        console.error(
          'Sentinel live status polling failed:',
          error,
        );
      } finally {
        livePollInFlightRef.current = false;
      }
    },
    [
      apiBase,
      clearLivePolling,
      consume,
      setConnectionSafe,
    ],
  );

  const startLiveCapture = useCallback(
    async () => {
      const interfaceName =
        selectedInterface ||
        interfaces[0]?.name ||
        interfaces[0]?.display_name ||
        interfaces[0]?.friendly_name ||
        'Wi-Fi'; // fallback to known working interface

      if (!interfaceName) {
        setConnectionSafe('error');

        showToast(
          'danger',
          'No capture interface selected',
          'Select a network interface before starting live capture.',
        );

        return;
      }

      clearLivePolling();

      try {
        const response =
          await fetch(
            `${apiBase}/live/start`,
            {
              method: 'POST',
              headers: {
                'Content-Type':
                  'application/json',
              },
              body: JSON.stringify({
                interface: interfaceName,
              }),
            },
          );

        const data =
          (await response.json()) as BackendAnalysisResponse & {
            status?: string;
            interface?: string;
            passive?: boolean;
            payload_decryption?: boolean;
            active_mitigation?: boolean;
          };

        if (!response.ok) {
          throw new Error(
            stringValue(
              data.detail,
              `Backend returned ${response.status}`,
            ),
          );
        }

        setBackendOnline(true);
        setSourceMode('live');
        setConnectionSafe('capturing');
        setActivePage('dashboard');

        /*
         * Start polling immediately instead of waiting for
         * the first one-second interval.
         */
        await pollLiveStatus();

        livePollRef.current =
          window.setInterval(() => {
            pollLiveStatus();
          }, 1000);

        // Check whether backend is in cloud mode listening for remote Windows client
        const isCloudListening =
          (data as unknown as Record<string, unknown>)?.status === 'listening' ||
          (data as unknown as Record<string, unknown>)?.mode === 'cloud';

        if (isCloudListening) {
          showToast(
            'info',
            'Live capture ready',
            'Backend is listening. Start windows_client.py on your Windows laptop to stream live traffic.',
          );
        } else {
          showToast(
            'success',
            'Live capture started',
            `Sentinel is passively monitoring ${interfaceName}.`,
          );
        }
      } catch (error) {
        clearLivePolling();

        setConnectionSafe('error');

        showToast(
          'danger',
          'Live capture failed',
          error instanceof Error
            ? error.message
            : `Could not start live capture on ${interfaceName}.`,
        );
      }
    },
    [
      apiBase,
      clearLivePolling,
      interfaces,
      pollLiveStatus,
      selectedInterface,
      setConnectionSafe,
      showToast,
    ],
  );

  const refreshStatus = useCallback(
    async () => {
      try {
        const response =
          await fetch(`${apiBase}/status`);

        if (!response.ok) {
          throw new Error(
            `Backend returned ${response.status}`,
          );
        }

        const data =
          (await response.json()) as BackendStatus;

        setBackendStatus(data);
        setBackendOnline(true);

        return data;
      } catch {
        setBackendOnline(false);
        setBackendStatus(null);
        return null;
      }
    },
    [apiBase],
  );

  /*
   * Use a ref so refreshInterfaces never changes identity when
   * selectedInterface changes. Previously this caused the useEffect
   * below to re-register a new setInterval on every interface change.
   */
  const selectedInterfaceRef = useRef(selectedInterface);
  selectedInterfaceRef.current = selectedInterface;

  const refreshInterfaces =
    useCallback(async () => {
      try {
        const response =
          await fetch(`${apiBase}/interfaces`);

        if (!response.ok) {
          throw new Error(
            `Interface request failed: ${response.status}`,
          );
        }

        const data =
          await response.json();

        const values =
          Array.isArray(data)
            ? data
            : Array.isArray(data?.interfaces)
              ? data.interfaces
              : [];

        const discovered =
          values as CaptureInterface[];

        setInterfaces(discovered);

        if (
          !selectedInterfaceRef.current &&
          discovered.length > 0
        ) {
          setSelectedInterface(
            discovered[0].name ||
              discovered[0].display_name ||
              discovered[0].friendly_name ||
              '',
          );
        }

        setBackendOnline(true);
      } catch {
        setBackendOnline(false);
      }
    }, [
      apiBase,
    ]);

  const startStream = useCallback(
    async (mode: SourceMode = sourceMode) => {
      setSourceMode(mode);
      setConnectionSafe('connecting');
      setActivePage('dashboard');

      if (mode === 'live') {
        await startLiveCapture();
        return;
      }

      try {
        setTrafficHistory([]);

        const response = await fetch(
          `${apiBase}/replay/stream`,
          {
            method: 'GET',
            cache: 'no-store',
          },
        );

        if (!response.ok) {
          throw new Error(
            `Backend returned ${response.status}`,
          );
        }

        const data =
          (await response.json()) as BackendAnalysisResponse & {
            points?: Array<{
              timestamp?: number;
              pps?: number;
              bps?: number;
              syn?: number;
              packet_count?: number;
              byte_count?: number;
              ml_anomaly_score?: number;
              ml_is_anomaly?: boolean;
            }>;
          };

        consume(data);

        const points = Array.isArray(data.points)
          ? data.points
          : [];

        const history: TrafficHistoryPoint[] = points.map(
          (point) => ({
            time:
              point.timestamp !== undefined
                ? new Date(
                    point.timestamp * 1000,
                  ).toISOString()
                : new Date().toISOString(),
            pps: numberValue(point.pps),
            bps: numberValue(point.bps),
            syn: numberValue(point.syn),
            anomaly: numberValue(
              point.ml_anomaly_score,
            ),
          }),
        );

        setTrafficHistory(history.slice(-120));
        setConnectionSafe('complete');

        showToast(
          'success',
          'Sentinel analysis complete',
          `${numberValue(
            data.packets_processed,
          )} packets processed.`,
        );
      } catch (error) {
        console.error(
          'Sentinel replay stream failed:',
          error,
        );

        setConnectionSafe('error');

        showToast(
          'danger',
          'Sentinel analysis failed',
          error instanceof Error
            ? error.message
            : `Could not connect to ${apiBase}.`,
        );
      }
    },
    [
      apiBase,
      consume,
      setConnectionSafe,
      showToast,
      sourceMode,
      startLiveCapture,
    ],
  );

  const stopStream = useCallback(() => {
    const wasLive =
      sourceMode === 'live';

    clearLivePolling();

    if (wasLive) {
      /*
       * Stop is a passive capture lifecycle action.
       * It does NOT send mitigation, blocking, quarantine,
       * or any network control command.
       */
      fetch(
        `${apiBase}/live/stop`,
        {
          method: 'POST',
        },
      )
        .then(async (response) => {
          if (!response.ok) {
            throw new Error(
              `Backend returned ${response.status}`,
            );
          }

          return response.json();
        })
        .catch((error) => {
          console.error(
            'Sentinel live capture stop failed:',
            error,
          );
        });
    }

    setConnectionSafe('offline');
  }, [
    apiBase,
    clearLivePolling,
    setConnectionSafe,
    sourceMode,
  ]);

  const pauseStream = useCallback(() => {
    setConnectionSafe('paused');
  }, [
    setConnectionSafe,
  ]);

  const resumeStream = useCallback(() => {
    if (
      connectionRef.current === 'paused'
    ) {
      startStream(sourceMode);
    }
  }, [
    sourceMode,
    startStream,
  ]);

  const analyzePcap = useCallback(
    async (file: File) => {
      /*
       * PCAP analysis and live capture are mutually exclusive.
       */
      clearLivePolling();

      setSourceMode('pcap');
      setConnectionSafe('connecting');

      const formData =
        new FormData();

      formData.append(
        'file',
        file,
      );

      try {
        const response =
          await fetch(
            `${apiBase}/analyze`,
            {
              method: 'POST',
              body: formData,
            },
          );

        const data =
          (await response.json()) as BackendAnalysisResponse;

        if (!response.ok) {
          throw new Error(
            stringValue(
              data.detail,
              'PCAP analysis failed.',
            ),
          );
        }

        const next =
          buildSnapshot(
            data,
            null,
          );

        snapshotRef.current = next;

        setSnapshot(next);

        setTrafficHistory([]);

        const window =
          next.window ||
          emptyWindow;

        const mlScore =
          numberValue(
            next.ml?.score ??
              next.ml_anomaly_score ??
              data.summary
                ?.ml_anomaly_score,
          );

        setTrafficHistory([
          {
            time:
              next.timestamp ||
              new Date().toISOString(),

            pps:
              numberValue(
                window.packets_per_second,
              ),

            bps:
              numberValue(
                window.bytes_per_second,
              ),

            syn:
              numberValue(
                window.syns_per_second,
              ),

            anomaly:
              mlScore,
          },
        ]);

        if (data.metrics) {
          setSnapshot((current) => ({
            ...(current || next),

            processing_latency_ms:
              numberValue(
                data.metrics
                  ?.average_latency_ms,
              ),

            metrics:
              data.metrics,
          }));
        }

        setConnectionSafe(
          'complete',
        );

        setBackendOnline(true);

        setActivePage('alerts');

        showToast(
          'success',
          'PCAP analyzed',
          `${numberValue(
            data.packets_processed,
          )} packets processed by Sentinel.`,
        );
      } catch (error) {
        setConnectionSafe('error');

        showToast(
          'danger',
          'PCAP analysis failed',
          error instanceof Error
            ? error.message
            : 'Unknown error.',
        );
      }
    },
    [
      apiBase,
      clearLivePolling,
      setConnectionSafe,
      showToast,
    ],
  );

  const clearAnalyticalState =
    useCallback(() => {
      clearLivePolling();

      setSnapshot(null);
      snapshotRef.current = null;

      setTrafficHistory([]);
      setConnectionSafe('offline');

      setSelectedFlow(null);
      setSelectedNode(null);
      setSelectedIp('');
    }, [
      clearLivePolling,
      setConnectionSafe,
    ]);

  useEffect(() => {
    refreshStatus();
    refreshInterfaces();

    const interval =
      window.setInterval(() => {
        refreshStatus();
        refreshInterfaces();
      }, 5000);

    return () => {
      window.clearInterval(
        interval,
      );
    };
  }, [
    refreshInterfaces,
    refreshStatus,
  ]);

  /*
   * Auto-start polling /live/status on mount.
   *
   * The backend starts a demo PCAP-loop worker on startup, so
   * the dashboard receives live telemetry immediately without
   * requiring the user to click START LIVE CAPTURE.
   * We wait 2 s to give the backend time to boot the worker.
   */
  useEffect(() => {
    const timer = window.setTimeout(async () => {
      try {
        const res = await fetch(`${apiBase}/live/status`);
        if (!res.ok) return;
        const data = await res.json();
        // If real capture is actively running (local capture or connected Windows client),
        // resume polling.
        if (data?.running && (data?.client_connected || data?.mode === 'local')) {
          setSourceMode('live');
          setConnectionSafe('capturing');
          await pollLiveStatus();
          livePollRef.current = window.setInterval(() => {
            pollLiveStatus();
          }, 1000);
        }
      } catch {
        // Backend not ready yet
      }
    }, 2000);

    return () => {
      window.clearTimeout(timer);
    };
  }, [
    apiBase,
    pollLiveStatus,
    setConnectionSafe,
  ]);

  /*
   * Safety cleanup:
   * never leave a live polling timer running after the
   * SecurityProvider is unmounted.
   */
  useEffect(() => {
    return () => {
      clearLivePolling();
    };
  }, [
    clearLivePolling,
  ]);

  const current =
    snapshot ||
    ({
      type: 'snapshot',
      window: emptyWindow,
    } as PipelineSnapshot);

  const alertsRaw =
    current.active_alerts ||
    [];

  const mlScore =
    numberValue(
      current.ml?.score ??
        current.ml_anomaly_score,
    );

  const threats =
    alertsRaw.map(
      (alert, index) =>
        adaptThreat(
          alert,
          index,
          mlScore,
        ),
    );

  const alerts: AlertItem[] =
    alertsRaw.map(
      (alert, index) => ({
        id: threatId(
          alert,
          index,
        ),

        title:
          alert.threat_class,

        severity:
          alert.severity,

        threatType:
          alert.threat_class,

        sourceIp:
          alert.source_ip ||
          '—',

        destinationIp:
          alert.destination_ip ||
          '—',

        aiConfidence:
          numberValue(
            alert.confidence,
          ),

        timeDetected:
          alert.last_seen ||
          alert.timestamp ||
          '',

        status:
          'Active',

        deviationScore:
          `${Math.round(
            numberValue(
              alert.confidence,
            ) * 100,
          )}%`,

        description:
          'Detection derived from passive packet and flow metadata.',

        evidence:
          alert.evidence || {},
      }),
    );

  const flows =
    (
      current.flows || []
    ).map(
      (flow, index) =>
        adaptFlow(
          flow,
          index,
          mlScore,
        ),
    );

  const latestWindow =
    current.window ||
    emptyWindow;

  const correlatedEvidence =
    current.correlated_evidence ||
    [];

  /*
   * Normalize intelligence records.
   *
   * The live backend serializes IntelligenceResult objects with all
   * sub-scores nested inside a `threat_score` object:
   *   { threat_score: { unified_score, detector_score, ml_score, … } }
   *
   * Prefer those nested values, fall back to same-named top-level fields
   * (used by the PCAP/replay path), then 0.
   *
   * Number.isFinite() guards ensure NaN/Infinity never reach the UI.
   */
  const intelligence = (
    current.intelligence || []
  ).map((item) => {
    const ts = (
      item as { threat_score?: Record<string, unknown> }
    ).threat_score || {};

    const rd = (
      item as { risk_decision?: Record<string, unknown> }
    ).risk_decision || {};

    const safeNum = (
      nested: unknown,
      direct: unknown,
    ): number => {
      const a = Number(nested);
      if (Number.isFinite(a)) return a;
      const b = Number(direct);
      return Number.isFinite(b) ? b : 0;
    };

    return {
      ...item,
      unified_score: safeNum(
        ts.unified_score,
        item.unified_score,
      ),
      detector_score: safeNum(
        ts.detector_score,
        item.detector_score,
      ),
      ml_score: safeNum(
        ts.ml_score,
        item.ml_score,
      ),
      correlation_score: safeNum(
        ts.correlation_score,
        item.correlation_score,
      ),
      progression_score: safeNum(
        ts.progression_score,
        item.progression_score,
      ),
      risk_level:
        item.risk_level ||
        (ts.risk_level as string | undefined) ||
        (rd.risk_level as string | undefined) ||
        'LOW',
    };
  });

  const incidents =
    current.incidents ||
    alertsRaw;

  const dnsQueries =
    current.dns
      ?.recent_queries ||
    [];

  const encryptedSessions =
    current.encrypted
      ?.sessions ||
    [];

  const detectorCoverage =
    current.detector_coverage ||
    [];

  /*
   * Flow Groups: prefer an explicit telemetry count, then fall back to
   * the window's unique_src_ips (distinct traffic sources in the current
   * window — the closest real proxy from live capture data), then the
   * number of decoded flow records.
   */
  const liveFlowCount =
    numberValue(
      current.telemetry?.flow_groups ??
      latestWindow.unique_src_ips,
      flows.length,
    );

  /*
   * Guard against tiny-window rate artifacts.
   * When packet_count < 2 the observation window can be effectively
   * zero-duration, making packets_per_second / bytes_per_second
   * astronomically large (e.g. 1,000,000 from a single 46-byte packet).
   * Any rate > 10,000 produced by a single-packet window is a
   * measurement artifact, not real traffic intensity.
   * Non-finite values are also rejected.
   */
  const _windowPkts = latestWindow.packet_count;
  const safeRate = (r: number): number => {
    if (!Number.isFinite(r) || r < 0) return 0;
    if (_windowPkts < 2 && r > 10_000) return 0;
    return r;
  };

  const livePacketsPerSec = safeRate(
    numberValue(
      latestWindow.packets_per_second,
    ),
  );

  const liveBytesPerSec =
    `${
      (
        safeRate(
          numberValue(
            latestWindow.bytes_per_second,
          ),
        ) /
        1024 /
        1024
      ).toFixed(2)
    } MB/s`;

  const lastAnalysisSec =
    numberValue(
      current.processing_latency_ms,
    ) / 1000;

  const mlIsAnomaly =
    Boolean(
      current.ml?.is_anomaly ??
        current.ml_is_anomaly,
    );

  const mlReady =
    Boolean(
      current.ml?.ready !== false,
    );

  const sourceInfo =
    (
      current as unknown as {
        source?: BackendSourceInfo;
      }
    ).source || null;

  const metrics =
    (
      current as unknown as {
        metrics?: BackendPcapMetrics;
      }
    ).metrics || null;

  const mapNodes =
    useMemo<MapNode[]>(() => {
      const ips = [
        ...new Set(
          [
            ...flows.map(
              (flow) =>
                flow.sourceIp,
            ),

            ...flows.map(
              (flow) =>
                flow.destinationIp,
            ),

            ...alertsRaw
              .flatMap(
                (alert) => [
                  alert.source_ip,
                  alert.destination_ip,
                ],
              )
              .filter(
                Boolean,
              ) as string[],
          ],
        ),
      ].slice(0, 18);

      return ips.map(
        (ip, index) => {
          const alert =
            alertsRaw.find(
              (item) =>
                item.source_ip ===
                  ip ||
                item.destination_ip ===
                  ip,
            );

          const severity =
            severityRank(
              alert?.severity,
            );

          return {
            id: `node-${ip}`,

            ip,

            label: ip,

            role: alert
              ? 'Suspicious Actor'
              : 'External Peer',

            status:
              severity >= 3
                ? 'threat'
                : severity >= 1
                  ? 'suspicious'
                  : 'normal',

            x:
              10 +
              (index % 6) * 16,

            y:
              18 +
              Math.floor(
                index / 6,
              ) * 28,

            riskScore:
              Math.round(
                numberValue(
                  alert?.confidence,
                ) * 100,
              ),

            trafficVolume:
              'Observed',

            flowCount:
              flows.filter(
                (flow) =>
                  flow.sourceIp ===
                    ip ||
                  flow.destinationIp ===
                    ip,
              ).length,

            lastSeen:
              alert?.last_seen ||
              current.timestamp ||
              '',
          };
        },
      );
    }, [
      alertsRaw,
      current.timestamp,
      flows,
    ]);

  const updateAlertStatus =
    useCallback(
      (
        _id: string,
        status:
          | 'Active'
          | 'Investigating'
          | 'Resolved'
          | 'False Positive',
      ) => {
        showToast(
          'info',
          'Read-only analytical posture',
          `UI status "${status}" is local only. Sentinel does not send mitigation, blocking, or quarantine commands.`,
        );
      },
      [showToast],
    );

  const updateThreatStatus =
    useCallback(
      (
        _id: string,
        status: ThreatEvent['status'],
      ) => {
        showToast(
          'info',
          'Read-only posture',
          `Threat status "${status}" is not sent back as a network control action.`,
        );
      },
      [showToast],
    );

  const navigateToIp =
    useCallback(
      (ip: string) => {
        setSelectedIp(ip);
        setActivePage(
          'ip-intel',
        );
      },
      [],
    );

  const navigateToFlow =
    useCallback(
      (id: string) => {
        const flow =
          flows.find(
            (item) =>
              item.id === id,
          );

        if (flow) {
          setSelectedFlow(
            flow,
          );
        }

        setActivePage(
          'traffic',
        );
      },
      [flows],
    );

  const contextValue =
    useMemo<SecurityContextType>(
      () => ({
        activePage,
        setActivePage,

        threats,
        flows,
        alerts,

        mapNodes,

        reports,

        selectedFlow,
        setSelectedFlow,

        selectedNode,
        setSelectedNode,

        selectedIp,
        setSelectedIp,

        globalSearch,
        setGlobalSearch,

        inspectThreatModal,
        setInspectThreatModal,

        reportModal,
        setReportModal,

        updateAlertStatus,
        updateThreatStatus,

        liveFlowCount,
        livePacketsPerSec,
        liveBytesPerSec,
        lastAnalysisSec,

        navigateToIp,
        navigateToFlow,

        apiBase,
        setApiBaseUrl,
        clientConnected,
        captureMode,

        connection,

        sourceMode,

        scenario,
        setScenario,

        interfaces,
        selectedInterface,
        setSelectedInterface,

        startStream,
        stopStream,
        pauseStream,
        resumeStream,

        analyzePcap,
        refreshInterfaces,

        backendOnline,
        backendStatus,

        snapshot,

        latestWindow,

        mlScore,
        mlIsAnomaly,
        mlReady,

        correlatedEvidence,
        intelligence,
        incidents,

        dnsQueries,
        encryptedSessions,

        detectorCoverage,

        trafficHistory,

        sourceInfo,
        metrics,

        clearAnalyticalState,
      }),
      [
        activePage,
        alerts,
        analyzePcap,
        apiBase,
        setApiBaseUrl,
        clientConnected,
        captureMode,
        backendOnline,
        backendStatus,
        clearAnalyticalState,
        correlatedEvidence,
        detectorCoverage,
        dnsQueries,
        encryptedSessions,
        flows,
        globalSearch,
        incidents,
        intelligence,
        interfaces,
        lastAnalysisSec,
        latestWindow,
        liveBytesPerSec,
        liveFlowCount,
        livePacketsPerSec,
        mapNodes,
        metrics,
        mlIsAnomaly,
        mlReady,
        mlScore,
        navigateToFlow,
        navigateToIp,
        pauseStream,
        refreshInterfaces,
        reportModal,
        reports,
        resumeStream,
        scenario,
        selectedFlow,
        selectedInterface,
        selectedIp,
        selectedNode,
        setSelectedFlow,
        setSelectedIp,
        setSelectedNode,
        sourceInfo,
        sourceMode,
        snapshot,
        startStream,
        stopStream,
        threats,
        trafficHistory,
        updateAlertStatus,
        updateThreatStatus,
        inspectThreatModal,
      ],
    );

  return (
    <SecurityContext.Provider
      value={contextValue}
    >
      {children}
    </SecurityContext.Provider>
  );
};

export const useSecurity =
  (): SecurityContextType => {
    const context =
      useContext(
        SecurityContext,
      );

    if (!context) {
      throw new Error(
        'useSecurity must be used within a SecurityProvider',
      );
    }

    return context;
  };