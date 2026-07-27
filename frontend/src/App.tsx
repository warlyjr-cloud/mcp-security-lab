import React from 'react';
import { AppStateProvider, useAppState } from './store/AppStateContext';
import { Header } from './components/Header';
import { NavigationBar } from './components/NavigationBar';
import { Terminal } from './components/Terminal';
import { SummaryModule } from './modules/SummaryModule';

import { HelpModal } from './modules/HelpModal';
import { AiConsultantModule } from './modules/AiConsultantModule';
import { ScannerModule } from './modules/ScannerModule';
import { ComplianceMatrixModule } from './modules/ComplianceMatrixModule';

const ModuleRenderer: React.FC = () => {
  const { activeTab } = useAppState();

  const renderContent = () => {
    switch (activeTab) {
      case 'summary': return <SummaryModule />;
      case 'help': return <HelpModal />;
      case 'scanner': return <ScannerModule />;
      case 'ai': return <AiConsultantModule />;
      case 'auditor': return <div className="p-4 border border-term-dim m-4"><h2 className="text-xl font-bold uppercase border-b border-term-dim pb-2 mb-4">Code Auditor</h2><p className="text-term-dim">Syntax viewer for exploits and payloads.</p></div>;
      case 'threat': return <div className="p-4 border border-term-dim m-4"><h2 className="text-xl font-bold uppercase border-b border-term-dim pb-2 mb-4">Threat Feed</h2><p className="text-term-dim">CVE Database Search Simulation.</p></div>;
      case 'compliance': return <ComplianceMatrixModule />;
      case 'port': return <div className="p-4 border border-term-dim m-4"><h2 className="text-xl font-bold uppercase border-b border-term-dim pb-2 mb-4">Port Scanner</h2><p className="text-term-dim">Dedicated network mapping tool.</p></div>;
      case 'mcp': return <div className="p-4 border border-term-dim m-4"><h2 className="text-xl font-bold uppercase border-b border-term-dim pb-2 mb-4">MCP Inspector</h2><p className="text-term-dim">Context Protocol Inspector logs.</p></div>;
      default: return <SummaryModule />;
    }
  };

  return (
    <div className="flex-1 overflow-y-auto relative z-10">
      {renderContent()}
    </div>
  );
};

function AppContent() {
  return (
    <div className="h-screen flex flex-col font-mono text-term-fg bg-term-bg overflow-hidden relative">
      <div className="crt-overlay"></div>
      <Header />
      <NavigationBar />
      <ModuleRenderer />
      <Terminal />
    </div>
  );
}

function App() {
  return (
    <AppStateProvider>
      <AppContent />
    </AppStateProvider>
  );
}

export default App;
