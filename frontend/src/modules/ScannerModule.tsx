import React, { useState, useEffect } from 'react';
import { useAppState } from '../store/AppStateContext';

export const ScannerModule: React.FC = () => {
  const { addLog } = useAppState();
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [target, setTarget] = useState('');
  const [logs, setLogs] = useState<string[]>([]);

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (scanning && progress < 100) {
      interval = setInterval(() => {
        setProgress(p => {
          const next = p + Math.floor(Math.random() * 10) + 1;
          return next > 100 ? 100 : next;
        });
        
        const mockEvents = [
          `Scanning port ${Math.floor(Math.random() * 65535)}...`,
          `Checking SSL/TLS certificates...`,
          `Running SAST analysis on target...`,
          `Found potential XSS vulnerability...`,
          `Analyzing dependencies...`
        ];
        setLogs(prev => [...prev, mockEvents[Math.floor(Math.random() * mockEvents.length)]].slice(-20));
      }, 500);
    } else if (progress >= 100 && scanning) {
      setScanning(false);
      addLog(`Scan completed for ${target}`);
      setLogs(prev => [...prev, '[SCAN COMPLETE] 4 vulnerabilities found.']);
    }
    return () => clearInterval(interval);
  }, [scanning, progress, target, addLog]);

  const handleStartScan = () => {
    if (!target) return;
    setScanning(true);
    setProgress(0);
    setLogs([`Starting scan on ${target}...`]);
    addLog(`Initiated scan on ${target}`);
  };

  const handleExport = () => {
    const data = JSON.stringify({ target, logs, timestamp: new Date().toISOString() }, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan_report_${Date.now()}.json`;
    a.click();
    addLog(`Exported scan report for ${target}`);
  };

  return (
    <div className="p-4 h-full flex flex-col gap-4">
      <h2 className="text-xl font-bold uppercase border-b border-term-dim pb-2">Target Scanner</h2>
      
      <div className="flex gap-2 items-center">
        <label className="text-term-dim">TARGET_URL:</label>
        <input 
          type="text" 
          value={target} 
          onChange={e => setTarget(e.target.value)} 
          className="bg-transparent border-b border-term-fg outline-none flex-1 placeholder-term-dim/50" 
          placeholder="https://example.com" 
          disabled={scanning}
        />
        <button 
          onClick={handleStartScan} 
          disabled={scanning || !target}
          className="border border-term-warn text-term-warn px-4 py-1 hover:bg-term-warn hover:text-term-bg disabled:opacity-50"
        >
          {scanning ? 'SCANNING...' : 'START SCAN'}
        </button>
      </div>

      <div className="mt-4">
        <div className="text-term-dim mb-1">PROGRESS [{progress}%]</div>
        <div className="h-4 border border-term-fg w-full p-0.5">
          <div className="h-full bg-term-warn transition-all duration-300" style={{ width: `${progress}%` }}></div>
        </div>
      </div>

      <div className="flex-1 border border-term-dim p-2 overflow-y-auto font-mono text-sm mt-4 bg-term-bg/50">
        {logs.map((log, i) => (
          <div key={i} className="text-term-fg">{`> ${log}`}</div>
        ))}
      </div>

      <div className="flex justify-end mt-2">
        <button 
          onClick={handleExport} 
          disabled={progress < 100 || logs.length === 0}
          className="border border-term-fg px-4 py-1 hover:bg-term-fg hover:text-term-bg disabled:opacity-50"
        >
          EXPORT REPORT JSON
        </button>
      </div>
    </div>
  );
};
