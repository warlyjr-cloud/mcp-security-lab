import React, { useState } from 'react';
import { useAppState } from '../store/AppStateContext';

interface Finding {
  id: string;
  severity: string;
  title: string;
  evidence?: string;
  location?: string;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'text-term-error',
  high: 'text-term-error',
  medium: 'text-term-warn',
  low: 'text-term-dim',
  info: 'text-term-dim',
};

export const ScannerModule: React.FC = () => {
  const { addLog } = useAppState();
  const [command, setCommand] = useState('node');
  const [args, setArgs] = useState('dist/fixtures/insecure-server.js');
  const [execute, setExecute] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!command.trim()) return;
    setScanning(true);
    setError(null);
    setFindings(null);
    addLog(`Scanning ${command} ${args}`.trim());

    const config = {
      target: {
        command: command.trim(),
        args: args.trim() ? args.trim().split(/\s+/) : [],
        cwd: '.',
      },
      policy: { timeoutMs: 5000, maxTools: 100 },
    };

    try {
      const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:3000';
      const response = await fetch(`${apiBase}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config, execute }),
      });
      const data = await response.json();
      if (response.ok) {
        setFindings(data.findings ?? []);
        addLog(`Scan complete: ${(data.findings ?? []).length} findings`);
      } else {
        setError(data.error ?? 'Scan failed');
        addLog(`Scan error: ${data.error}`);
      }
    } catch (err: any) {
      setError(`Connection error: ${err.message}`);
      addLog(`Scan connection error: ${err.message}`);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="p-4 h-full flex flex-col gap-4">
      <h2 className="text-xl font-bold uppercase border-b border-term-dim pb-2">MCP Server Scanner</h2>

      <form onSubmit={runScan} className="flex flex-col gap-2">
        <div className="flex gap-2 items-center">
          <label className="text-term-dim w-24">COMMAND:</label>
          <input
            type="text"
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            className="bg-transparent border-b border-term-fg outline-none flex-1"
            placeholder="node"
            disabled={scanning}
          />
        </div>
        <div className="flex gap-2 items-center">
          <label className="text-term-dim w-24">ARGS:</label>
          <input
            type="text"
            value={args}
            onChange={(e) => setArgs(e.target.value)}
            className="bg-transparent border-b border-term-fg outline-none flex-1"
            placeholder="path/to/server.js"
            disabled={scanning}
          />
        </div>
        <div className="flex gap-4 items-center">
          <label className="flex gap-2 items-center text-term-dim">
            <input
              type="checkbox"
              checked={execute}
              onChange={(e) => setExecute(e.target.checked)}
              disabled={scanning}
            />
            --execute (start the server & discover tools)
          </label>
          <button
            type="submit"
            disabled={scanning || !command.trim()}
            className="border border-term-warn text-term-warn px-4 py-1 hover:bg-term-warn hover:text-term-bg disabled:opacity-50"
          >
            {scanning ? 'SCANNING...' : 'RUN SCAN'}
          </button>
        </div>
      </form>

      <div className="flex-1 border border-term-dim p-2 overflow-y-auto font-mono text-sm bg-term-bg/50">
        {error && <div className="text-term-error">{`> ERROR: ${error}`}</div>}
        {findings && findings.length === 0 && (
          <div className="text-term-dim">{'> No findings.'}</div>
        )}
        {findings?.map((finding, i) => (
          <div key={i} className="mb-2">
            <div className={SEVERITY_COLOR[finding.severity] ?? 'text-term-fg'}>
              {`[${finding.severity.toUpperCase()}] ${finding.id} ${finding.title}`}
            </div>
            {finding.location && <div className="text-term-dim pl-4">{`@ ${finding.location}`}</div>}
            {finding.evidence && <div className="text-term-dim pl-4">{finding.evidence}</div>}
          </div>
        ))}
        {!findings && !error && !scanning && (
          <div className="text-term-dim">
            {'> Enter a local MCP server command and RUN SCAN. Real, deterministic results from the MCP Verifier engine.'}
          </div>
        )}
      </div>
    </div>
  );
};
