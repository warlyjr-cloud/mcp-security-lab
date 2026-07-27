import React from 'react';

export const ComplianceMatrixModule: React.FC = () => {
  const frameworks = [
    { name: 'OWASP Top 10', score: 75, status: 'WARNING' },
    { name: 'NIST CSF', score: 92, status: 'PASS' },
    { name: 'PCI-DSS', score: 45, status: 'FAILED' },
    { name: 'CIS Benchmarks', score: 88, status: 'PASS' }
  ];

  return (
    <div className="p-4 h-full flex flex-col gap-4">
      <h2 className="text-xl font-bold uppercase border-b border-term-dim pb-2">Compliance Matrix</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {frameworks.map((fw, i) => (
          <div key={i} className={`border p-4 ${fw.status === 'FAILED' ? 'border-term-error' : fw.status === 'WARNING' ? 'border-term-warn' : 'border-term-dim'}`}>
            <div className="flex justify-between items-center mb-2">
              <h3 className="font-bold text-lg">{fw.name}</h3>
              <span className={`font-bold ${fw.status === 'FAILED' ? 'text-term-error flicker' : fw.status === 'WARNING' ? 'text-term-warn' : 'text-term-fg'}`}>
                {fw.status}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-term-dim">Score:</span>
              <span className="font-bold text-xl">{fw.score}%</span>
            </div>
            {fw.status !== 'PASS' && (
              <button className="mt-4 w-full border border-term-accent text-term-accent py-1 hover:bg-term-accent hover:text-term-bg text-sm">
                REQUEST AI REMEDIATION PLAN
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
