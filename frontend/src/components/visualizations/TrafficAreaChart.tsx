import React, { useEffect } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';
import { Activity, Laptop } from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';

export const TrafficAreaChart: React.FC = () => {
  const { trafficHistory, connection, sourceMode, clientConnected, captureMode } = useSecurity();

  const data = trafficHistory.map((x, i) => ({
    i,
    pps: +x.pps.toFixed(1),
    mbps: +(x.bps / 1024 / 1024).toFixed(3),
    time: x.time,
  }));

  useEffect(() => {
    if (data.length > 0) {
      console.log(`[GRAPH] Rendering ${data.length} real data points`);
    }
  }, [data.length]);

  return (
    <div className="glass-card rounded-2xl p-5 h-full">
      <div className="flex items-center justify-between mb-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="font-bold">Live Passive Traffic</h3>
            {sourceMode === 'live' && (
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${
                  clientConnected
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                    : 'border-amber-500/40 bg-amber-500/10 text-amber-400'
                }`}
              >
                {clientConnected
                  ? 'CLIENT CONNECTED'
                  : captureMode === 'cloud'
                  ? 'WAITING FOR CLIENT'
                  : 'LOCAL CAPTURE'}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500">
            Packets/s and observed byte rate from real Sentinel stream.
          </p>
        </div>
        <Activity
          className={`w-5 h-5 ${
            data.length > 0 ? 'text-cyan-500 animate-pulse' : 'text-slate-500'
          }`}
        />
      </div>

      <div className="h-64">
        {data.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data}>
              <CartesianGrid strokeDasharray="3 3" opacity={0.15} />
              <XAxis dataKey="i" hide />
              <YAxis yAxisId="left" />
              <YAxis yAxisId="right" orientation="right" />
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const d = payload[0].payload;
                    return (
                      <div className="glass-card p-2 rounded-lg text-xs font-mono border border-slate-700 shadow-lg">
                        <div className="text-slate-400">Point #{d.i}</div>
                        <div className="text-cyan-400 font-bold">{d.pps} pkts/s</div>
                        <div className="text-blue-400">{d.mbps} MB/s</div>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Area
                yAxisId="left"
                type="monotone"
                dataKey="pps"
                fillOpacity={0.12}
                strokeWidth={2}
                fill="#06b6d4"
                stroke="#06b6d4"
                name="Packets / s"
              />
              <Area
                yAxisId="right"
                type="monotone"
                dataKey="mbps"
                fillOpacity={0.08}
                strokeWidth={2}
                fill="#3b82f6"
                stroke="#3b82f6"
                name="MB / s"
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="h-full grid place-items-center text-center p-4 border border-dashed border-slate-800/80 rounded-xl">
            <div className="max-w-md space-y-2.5">
              {sourceMode === 'live' && !clientConnected ? (
                <>
                  <Laptop className="w-8 h-8 text-amber-400/80 mx-auto" />
                  <p className="text-sm font-semibold text-slate-200">
                    Waiting for live capture data…
                  </p>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Live capture unavailable directly on cloud server — connect the Windows capture client to stream real hardware traffic.
                  </p>
                  <div className="pt-2">
                    <code className="text-[11px] font-mono px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-cyan-400 inline-block select-all">
                      python windows_client.py --url &lt;render-backend-url&gt;
                    </code>
                  </div>
                </>
              ) : (
                <>
                  <Activity className="w-8 h-8 text-slate-500 mx-auto opacity-50" />
                  <p className="text-sm font-medium text-slate-400">
                    Waiting for live capture data…
                  </p>
                  <p className="text-xs text-slate-500">
                    Start live capture or connect the Windows capture client to begin plotting real telemetry.
                  </p>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
