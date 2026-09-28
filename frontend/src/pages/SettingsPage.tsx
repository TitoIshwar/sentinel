import React, { useState } from 'react';
import { useSecurity } from '../context/SecurityContext';
import { Settings2, Radio, Server, RefreshCw, Laptop, CheckCircle, AlertCircle } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const {
    apiBase,
    setApiBaseUrl,
    backendOnline,
    interfaces,
    selectedInterface,
    setSelectedInterface,
    refreshInterfaces,
    scenario,
    setScenario,
    sourceMode,
    connection,
    clientConnected,
    captureMode,
  } = useSecurity();

  const [inputUrl, setInputUrl] = useState(apiBase);
  const [testingConnection, setTestingConnection] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  const handleSaveUrl = () => {
    if (inputUrl.trim()) {
      setApiBaseUrl(inputUrl.trim());
    }
  };

  const handleTestConnection = async () => {
    setTestingConnection(true);
    setTestResult(null);
    try {
      const res = await fetch(`${inputUrl.trim().replace(/\/$/, '')}/health`, {
        cache: 'no-store',
      });
      if (res.ok) {
        const data = await res.json();
        setTestResult(`Success! Backend status: ${data.status || 'healthy'}`);
      } else {
        setTestResult(`Error: HTTP ${res.status}`);
      }
    } catch (err) {
      setTestResult(`Failed to connect: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setTestingConnection(false);
    }
  };

  const handleResetUrl = () => {
    try {
      localStorage.removeItem('sentinel_api_url');
    } catch {
      /* ignore */
    }
    window.location.reload();
  };

  return (
    <div className="space-y-6 pb-12">
      <div>
        <h2 className="text-2xl font-bold">Sentinel Integration & Settings</h2>
        <p className="text-xs text-slate-500 mt-1">
          Runtime connection, passive Windows IntCap bridge configuration, and analytical boundary settings.
        </p>
      </div>

      <div className="grid lg:grid-cols-2 gap-5">
        {/* Backend Connection Card */}
        <div className="glass-card rounded-2xl p-6">
          <div className="flex items-center gap-3">
            <Server className="w-5 h-5 text-blue-500" />
            <h3 className="font-bold">Backend Connection</h3>
          </div>

          <div className="mt-5 space-y-4 text-sm">
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">
                Sentinel Backend API Base URL
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={inputUrl}
                  onChange={(e) => setInputUrl(e.target.value)}
                  placeholder="https://sentinel-backend.onrender.com or http://127.0.0.1:8000"
                  className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono focus:outline-none focus:border-blue-500"
                />
                <button
                  onClick={handleSaveUrl}
                  className="px-3 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold"
                >
                  Save & Reload
                </button>
              </div>
              <div className="flex items-center justify-between mt-2">
                <button
                  onClick={handleTestConnection}
                  disabled={testingConnection}
                  className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
                >
                  {testingConnection ? 'Testing...' : 'Test Connection'}
                </button>
                <button
                  onClick={handleResetUrl}
                  className="text-xs text-slate-400 hover:text-slate-200"
                >
                  Reset to Default
                </button>
              </div>
              {testResult && (
                <div
                  className={`mt-2 p-2 rounded text-xs font-mono ${
                    testResult.startsWith('Success')
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                  }`}
                >
                  {testResult}
                </div>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3 pt-2">
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50">
                <span className="text-xs text-slate-500">API Status</span>
                <b
                  className={`block mt-1 font-mono ${
                    backendOnline ? 'text-emerald-500' : 'text-rose-500'
                  }`}
                >
                  {backendOnline ? 'ONLINE' : 'OFFLINE'}
                </b>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50">
                <span className="text-xs text-slate-500">Deployment Mode</span>
                <b className="block mt-1 uppercase text-slate-300 font-mono">
                  {captureMode}
                </b>
              </div>
            </div>

            <button
              onClick={refreshInterfaces}
              className="px-3 py-2 border rounded-lg text-xs flex gap-2 items-center hover:bg-slate-800 transition-colors"
            >
              <RefreshCw className="w-4 h-4" /> Refresh Backend State
            </button>
          </div>
        </div>

        {/* Windows Capture Client Card */}
        <div className="glass-card rounded-2xl p-6">
          <div className="flex items-center gap-3">
            <Laptop className="w-5 h-5 text-cyan-500" />
            <h3 className="font-bold">Windows IntCap Capture Bridge</h3>
          </div>

          <div className="mt-5 space-y-4">
            <p className="text-xs text-slate-400 leading-relaxed">
              When deployed on Render, packet capture hardware (IntCap / Npcap) runs on your local
              Windows laptop. The Windows client captures real packets and streams them securely to the
              cloud backend.
            </p>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <span className="text-xs font-semibold text-slate-300 block">
                Start Client Command (PowerShell / CMD):
              </span>
              <code className="block text-xs font-mono text-cyan-400 bg-black/60 p-2.5 rounded border border-slate-700/60 select-all overflow-x-auto">
                python windows_client.py --url {apiBase}
              </code>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50">
                <span className="text-slate-500">Client Status</span>
                <b
                  className={`flex items-center gap-1.5 mt-1 ${
                    clientConnected ? 'text-emerald-400' : 'text-amber-400'
                  }`}
                >
                  {clientConnected ? (
                    <>
                      <CheckCircle className="w-3.5 h-3.5" /> CONNECTED
                    </>
                  ) : (
                    <>
                      <AlertCircle className="w-3.5 h-3.5" /> DISCONNECTED
                    </>
                  )}
                </b>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50">
                <span className="text-slate-500">Active Pipeline</span>
                <b className="block mt-1 text-slate-300">
                  {clientConnected ? 'Streaming Real Hardware' : 'Waiting for Client'}
                </b>
              </div>
            </div>
          </div>
        </div>

        {/* Passive Capture Adapter Selection */}
        <div className="glass-card rounded-2xl p-6">
          <div className="flex items-center gap-3">
            <Radio className="w-5 h-5 text-emerald-500" />
            <h3 className="font-bold">Passive Capture Settings</h3>
          </div>

          <div className="mt-5 space-y-4">
            <label className="block text-xs text-slate-500">
              Discovered Interface
              <select
                value={selectedInterface}
                onChange={(e) => setSelectedInterface(e.target.value)}
                className="mt-1 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200"
              >
                {interfaces.map((x, i) => (
                  <option key={i} value={x.name}>
                    {x.display_name || x.friendly_name || x.name}
                  </option>
                ))}
              </select>
            </label>

            <label className="block text-xs text-slate-500">
              Replay / Demo Scenario
              <select
                value={scenario}
                onChange={(e) => setScenario(e.target.value)}
                className="mt-1 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200"
              >
                {[
                  'normal',
                  'syn',
                  'udp',
                  'scan',
                  'dns',
                  'c2',
                  'encrypted',
                  'exfil',
                  'full-chain',
                ].map((x) => (
                  <option key={x}>{x}</option>
                ))}
              </select>
            </label>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50">
                Source Mode<b className="block mt-1 uppercase">{sourceMode}</b>
              </div>
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50">
                Connection<b className="block mt-1 uppercase">{connection}</b>
              </div>
            </div>
          </div>
        </div>

        {/* Analytical Boundary Card */}
        <div className="glass-card rounded-2xl p-6">
          <div className="flex gap-3 items-center">
            <Settings2 className="w-5 h-5 text-slate-500" />
            <div>
              <h3 className="font-bold">Analytical Boundary</h3>
              <p className="text-xs text-slate-500">
                Strict passive observation with zero simulation guarantee.
              </p>
            </div>
          </div>

          <ul className="mt-5 grid md:grid-cols-2 gap-3 text-xs text-slate-400">
            <li>✓ Passive IntCap packet extraction</li>
            <li>✓ Real-time streaming to cloud backend</li>
            <li>✓ Sliding window feature extraction</li>
            <li>✓ ML Isolation Forest anomaly score</li>
            <li>✓ Correlation and progression evidence</li>
            <li>✓ Strict zero simulated/fake data rule</li>
            <li>✓ No active probing or network interference</li>
            <li>✓ No payload decryption or storage</li>
          </ul>
        </div>
      </div>
    </div>
  );
};
