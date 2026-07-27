import React, { useEffect } from 'react';
import { useAppState, type TabType } from '../store/AppStateContext';

const TABS: { id: TabType; label: string; key: string }[] = [
  { id: 'help', label: 'HELP', key: 'F1' },
  { id: 'summary', label: 'SUMMARY', key: 'F2' },
  { id: 'scanner', label: 'SCANNER', key: 'F3' },
  { id: 'ai', label: 'AI_CONSULTANT', key: 'F4' },
  { id: 'auditor', label: 'CODE_AUDIT', key: 'F5' },
  { id: 'threat', label: 'THREAT_FEED', key: 'F6' },
  { id: 'compliance', label: 'COMPLIANCE', key: 'F7' },
  { id: 'port', label: 'PORT_SCAN', key: 'F8' },
  { id: 'mcp', label: 'MCP_INSPECT', key: 'F9' },
];

export const NavigationBar: React.FC = () => {
  const { activeTab, setActiveTab } = useAppState();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const match = TABS.find(t => t.key === e.key);
      if (match) {
        e.preventDefault();
        setActiveTab(match.id);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [setActiveTab]);

  return (
    <div className="flex border-b border-term-border overflow-x-auto bg-term-bg">
      {TABS.map((tab) => (
        <button
          key={tab.id}
          onClick={() => setActiveTab(tab.id)}
          className={`flex-1 py-1 px-4 border-r border-term-border whitespace-nowrap focus:outline-none text-sm
            ${activeTab === tab.id ? 'bg-term-fg text-term-bg font-bold' : 'text-term-fg hover:bg-term-dim/20'}`}
        >
          <span className="opacity-50 mr-2">[{tab.key}]</span>
          {tab.label}
        </button>
      ))}
    </div>
  );
};
