import React from 'react';
import { useAppState } from '../store/AppStateContext';

export const HelpModal: React.FC = () => {
  const { setActiveTab } = useAppState();

  return (
    <div className="absolute inset-0 bg-term-bg/90 z-50 flex items-center justify-center p-8 backdrop-blur-sm">
      <div className="border-2 border-term-fg bg-term-bg max-w-2xl w-full p-6 shadow-[0_0_20px_rgba(var(--text-color),0.2)]">
        <div className="flex justify-between items-center mb-6 border-b border-term-fg pb-2">
          <h2 className="text-2xl font-bold uppercase glow">System Command Palette</h2>
          <button onClick={() => setActiveTab('summary')} className="text-term-dim hover:text-term-error hover:scale-110 transition-transform">
            [X] CLOSE
          </button>
        </div>

        <div className="grid grid-cols-2 gap-8">
          <div>
            <h3 className="text-term-accent font-bold mb-2">KEYBINDINGS</h3>
            <ul className="space-y-1 text-sm">
              <li><span className="text-term-warn">[F1]</span> Help & Cheatsheet</li>
              <li><span className="text-term-warn">[F2]</span> Summary Dashboard</li>
              <li><span className="text-term-warn">[F3]</span> Scanner Simulator</li>
              <li><span className="text-term-warn">[F4]</span> AI Consultant</li>
              <li><span className="text-term-warn">[F5]</span> Code Auditor</li>
              <li><span className="text-term-warn">[F6]</span> Threat Feed</li>
              <li><span className="text-term-warn">[F7]</span> Compliance Matrix</li>
              <li><span className="text-term-warn">[F8]</span> Port Scanner</li>
              <li><span className="text-term-warn">[F9]</span> MCP Inspector</li>
            </ul>
          </div>

          <div>
            <h3 className="text-term-accent font-bold mb-2">CLI COMMANDS</h3>
            <ul className="space-y-2 text-sm">
              <li><code className="text-term-warn">clear</code> - Clears terminal output buffer</li>
              <li><code className="text-term-warn">theme &lt;color&gt;</code> - Changes active theme (matrix, dracula, cyberpunk, amber, nord)</li>
              <li><code className="text-term-warn">help</code> - Opens this module</li>
              <li><code className="text-term-warn">scan</code> - Simulates target scanning</li>
              <li><code className="text-term-warn">consult</code> - Calls AI Consultant</li>
            </ul>
          </div>
        </div>

        <div className="mt-8 text-xs text-center text-term-dim">
          CYBERCONSULT ADVANCED SECURITY SUITE v1.0.0 // AUTHORIZED PERSONNEL ONLY
        </div>
      </div>
    </div>
  );
};
