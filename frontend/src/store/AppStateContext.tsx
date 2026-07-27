import React, { createContext, useContext, useState, useEffect } from 'react';

export type ThemeType = 'matrix' | 'dracula' | 'cyberpunk' | 'amber' | 'nord';
export type TabType = 'help' | 'summary' | 'scanner' | 'ai' | 'auditor' | 'threat' | 'compliance' | 'port' | 'mcp';

interface AppState {
  theme: ThemeType;
  setTheme: (theme: ThemeType) => void;
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  terminalLogs: string[];
  addLog: (log: string) => void;
  clearLogs: () => void;
}

const defaultState: AppState = {
  theme: 'matrix',
  setTheme: () => {},
  activeTab: 'summary',
  setActiveTab: () => {},
  terminalLogs: [],
  addLog: () => {},
  clearLogs: () => {}
};

const AppStateContext = createContext<AppState>(defaultState);

export const AppStateProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [theme, setThemeState] = useState<ThemeType>('matrix');
  const [activeTab, setActiveTabState] = useState<TabType>('summary');
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);

  useEffect(() => {
    const savedTheme = localStorage.getItem('theme') as ThemeType;
    if (savedTheme) {
      setThemeState(savedTheme);
      document.body.className = savedTheme === 'matrix' ? '' : `theme-${savedTheme}`;
    }
    
    const savedLogs = localStorage.getItem('terminalLogs');
    if (savedLogs) setTerminalLogs(JSON.parse(savedLogs));
  }, []);

  const setTheme = (newTheme: ThemeType) => {
    setThemeState(newTheme);
    localStorage.setItem('theme', newTheme);
    document.body.className = newTheme === 'matrix' ? '' : `theme-${newTheme}`;
  };

  const setActiveTab = (tab: TabType) => {
    setActiveTabState(tab);
  };

  const addLog = (log: string) => {
    setTerminalLogs(prev => {
      const newLogs = [...prev, log].slice(-50); // Keep last 50
      localStorage.setItem('terminalLogs', JSON.stringify(newLogs));
      return newLogs;
    });
  };

  const clearLogs = () => {
    setTerminalLogs([]);
    localStorage.removeItem('terminalLogs');
  };

  return (
    <AppStateContext.Provider value={{ theme, setTheme, activeTab, setActiveTab, terminalLogs, addLog, clearLogs }}>
      {children}
    </AppStateContext.Provider>
  );
};

export const useAppState = () => useContext(AppStateContext);
