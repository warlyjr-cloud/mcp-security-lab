import React from 'react';
import { ShieldAlert, Cpu } from 'lucide-react';
import { useAppState } from '../store/AppStateContext';

export const Header: React.FC = () => {
  const { theme } = useAppState();

  return (
    <div className="flex justify-between items-center p-2 border-b border-term-border bg-term-bg/90">
      <div className="flex items-center gap-2">
        <ShieldAlert className="text-term-warn glow" size={20} />
        <span className="font-bold tracking-widest uppercase">CyberConsult <span className="text-term-dim">SYS::CORE</span></span>
      </div>
      
      <div className="flex items-center gap-4 text-sm">
        <div className="flex items-center gap-1">
          <span className="text-term-dim">THREAT_LEVEL:</span>
          <span className="text-term-warn flicker">ELEVATED</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="text-term-dim">AI_STATUS:</span>
          <span className="text-term-fg">ONLINE</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="text-term-dim">THEME:</span>
          <span className="uppercase">{theme}</span>
        </div>
        <Cpu className="text-term-fg" size={16} />
      </div>
    </div>
  );
};
