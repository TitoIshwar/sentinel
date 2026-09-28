import React from 'react';
import {
  Activity,
  ShieldAlert,
  BrainCircuit,
  Radio,
  Database,
} from 'lucide-react';
import { MetricCard } from '../components/shared/MetricCard';
import { TrafficAreaChart } from '../components/visualizations/TrafficAreaChart';
import { ThreatDonutChart } from '../components/visualizations/ThreatDonutChart';
import { useSecurity } from '../context/SecurityContext';

export const DashboardPage: React.FC = () => {
  const {
    liveFlowCount,
    livePacketsPerSec,
    liveBytesPerSec,
    mlScore,
    mlIsAnomaly,
    latestWindow,
    alerts,
    intelligence,
    correlatedEvidence,
    connection,
    sourceMode,
    scenario,
    startStream,
    stopStream,
    clientConnected,
    captureMode,
  } = useSecurity();

  const risk = intelligence.length
    ? Math.max(
        ...intelligence.map(
          (x) => x.unified_score,
        ),
      )
    : 0;

  return (
    <div className="space-y-6 pb-10">
      <div className="flex flex-wrap justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-2xl lg:text-3xl font-bold">
              Sentinel Command Center
            </h2>

            <span className="text-[10px] px-2 py-1 rounded-full border border-emerald-500/30 text-emerald-500">
              PASSIVE / READ-ONLY
            </span>
          </div>

          <p className="text-xs text-slate-500 mt-1">
            Live backend telemetry, stateful detectors, ML anomaly scoring and
            evidence correlation.
          </p>
        </div>

        <div className="flex gap-2">
          <button
            onClick={() => startStream('live')}
            className="px-3 py-2 rounded-lg bg-blue-600 text-white text-xs font-semibold"
          >
            START LIVE CAPTURE
          </button>

          <button
            onClick={stopStream}
            className="px-3 py-2 rounded-lg border text-xs"
          >
            STOP
          </button>
        </div>
      </div>

      {sourceMode === 'live' && (
        <div
          className={`flex items-center justify-between p-3.5 rounded-xl border text-xs ${
            clientConnected
              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
              : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
          }`}
        >
          <div className="flex items-center gap-2.5">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                clientConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
              }`}
            />
            <div>
              <b className="font-semibold">
                {clientConnected
                  ? 'Windows Capture Client Connected'
                  : 'Waiting for Windows Capture Client'}
              </b>
              <span className="text-slate-400 ml-2">
                {clientConnected
                  ? 'Streaming real live hardware packets to Render backend.'
                  : 'Render cloud cannot access laptop IntCap directly. Run windows_client.py on your Windows laptop.'}
              </span>
            </div>
          </div>
          {!clientConnected && (
            <code className="hidden sm:inline-block font-mono bg-black/40 px-2.5 py-1 rounded text-cyan-300 border border-slate-700/50">
              python windows_client.py
            </code>
          )}
        </div>
      )}

      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Flow Groups"
          value={liveFlowCount.toLocaleString()}
          change="vs last window"
          changeType="neutral"
          icon={Activity}
          accentColor="cyan"
          sparklineData={[0]}
        />

        <MetricCard
          title="Packets / sec"
          value={livePacketsPerSec.toFixed(1)}
          change={`window ${latestWindow.packet_count}`}
          changeType="positive"
          icon={Radio}
          accentColor="cyan"
          sparklineData={[0]}
        />

        <MetricCard
          title="Active Alerts"
          value={alerts.length.toString()}
          change={alerts.length ? `${alerts.length} active` : 'none active'}
          changeType={
            alerts.length
              ? 'negative'
              : 'positive'
          }
          icon={ShieldAlert}
          accentColor="red"
          sparklineData={[0]}
        />

        <MetricCard
          title="Unified Risk"
          value={`${(risk * 100).toFixed(1)}%`}
          subtext={
            risk >= 0.85
              ? 'CRITICAL'
              : risk >= 0.7
                ? 'HIGH'
                : risk >= 0.5
                  ? 'MEDIUM'
                  : 'LOW'
          }
          icon={BrainCircuit}
          accentColor={
            risk >= 0.7
              ? 'red'
              : 'emerald'
          }
          badge={
            mlIsAnomaly
              ? 'ANOMALY'
              : 'BASELINE'
          }
          sparklineData={[0]}
        />
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <TrafficAreaChart />
        </div>

        <ThreatDonutChart />
      </div>

      <div className="grid md:grid-cols-4 gap-4">
        <div className="glass-card p-4 rounded-2xl">
          <span className="text-[10px] uppercase text-slate-500">
            Bytes / sec
          </span>

          <b className="block text-xl mt-1">
            {liveBytesPerSec}
          </b>
        </div>

        <div className="glass-card p-4 rounded-2xl">
          <span className="text-[10px] uppercase text-slate-500">
            Sources
          </span>

          <b className="block text-xl mt-1">
            {latestWindow.unique_src_ips}
          </b>
        </div>

        <div className="glass-card p-4 rounded-2xl">
          <span className="text-[10px] uppercase text-slate-500">
            Destinations
          </span>

          <b className="block text-xl mt-1">
            {latestWindow.unique_dst_ips}
          </b>
        </div>

        <div className="glass-card p-4 rounded-2xl">
          <span className="text-[10px] uppercase text-slate-500">
            Correlation chains
          </span>

          <b className="block text-xl mt-1">
            {correlatedEvidence.length}
          </b>
        </div>
      </div>

      <div className="glass-card rounded-2xl p-6">
        <div className="flex justify-between items-center mb-4">
          <div>
            <h3 className="font-bold">
              Current analytical state
            </h3>

            <p className="text-xs text-slate-500">
              Scenario: {scenario} · connection:{' '}
              {connection}
            </p>
          </div>

          <Database className="w-5 h-5 text-blue-500" />
        </div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          <div>
            <span className="text-slate-500">
              Window packets
            </span>

            <b className="block mt-1">
              {latestWindow.packet_count}
            </b>
          </div>

          <div>
            <span className="text-slate-500">
              SYN ratio
            </span>

            <b className="block mt-1">
              {latestWindow.syn_ratio.toFixed(3)}
            </b>
          </div>

          <div>
            <span className="text-slate-500">
              Source entropy
            </span>

            <b className="block mt-1">
              {latestWindow.source_ip_entropy.toFixed(3)}
            </b>
          </div>

          <div>
            <span className="text-slate-500">
              ML anomaly
            </span>

            <b className="block mt-1">
              {mlScore.toFixed(3)}
            </b>
          </div>
        </div>
      </div>
    </div>
  );
};