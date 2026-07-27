import React from 'react';

export const SummaryModule: React.FC = () => {
  return (
    <div className="p-4 h-full flex flex-col gap-4">
      <h2 className="text-xl font-bold uppercase border-b border-term-dim pb-2 mb-4">System Summary</h2>

      <div className="border border-term-warn text-term-warn text-xs p-2 uppercase tracking-wide">
        ⚠ Sample data — illustrative dashboard figures, not a live scan result.
      </div>


      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="border border-term-error p-4 flex flex-col items-center justify-center glow">
          <span className="text-term-error font-bold text-4xl">12</span>
          <span className="text-term-dim uppercase mt-2">Critical</span>
        </div>
        <div className="border border-term-warn p-4 flex flex-col items-center justify-center">
          <span className="text-term-warn font-bold text-4xl">34</span>
          <span className="text-term-dim uppercase mt-2">High</span>
        </div>
        <div className="border border-term-dim p-4 flex flex-col items-center justify-center">
          <span className="text-term-fg font-bold text-4xl">89</span>
          <span className="text-term-dim uppercase mt-2">Medium</span>
        </div>
        <div className="border border-term-accent p-4 flex flex-col items-center justify-center">
          <span className="text-term-dim font-bold text-4xl">156</span>
          <span className="text-term-dim uppercase mt-2">Low</span>
        </div>
      </div>
      
      <div className="mt-8">
        <h3 className="text-lg font-bold mb-2">Recent Alerts</h3>
        <ul className="space-y-2 font-mono text-sm">
          <li className="flex gap-2 items-center"><span className="text-term-error">[CRIT]</span> SQL Injection detected in /api/auth</li>
          <li className="flex gap-2 items-center"><span className="text-term-warn">[HIGH]</span> Outdated dependency: express@4.17.1</li>
          <li className="flex gap-2 items-center"><span className="text-term-dim">[INFO]</span> Scheduled scan completed successfully</li>
        </ul>
      </div>
    </div>
  );
};
