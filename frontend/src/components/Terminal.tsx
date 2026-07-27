import React, { useState, useRef, useEffect } from 'react';
import { useAppState, type ThemeType } from '../store/AppStateContext';

export const Terminal: React.FC = () => {
  const { addLog, clearLogs, setTheme } = useAppState();
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const saved = localStorage.getItem('cmdHistory');
    if (saved) setHistory(JSON.parse(saved));
  }, []);

  const handleCommand = (cmd: string) => {
    const trimmed = cmd.trim();
    if (!trimmed) return;

    // Save to history
    const newHistory = [trimmed, ...history].slice(0, 50);
    setHistory(newHistory);
    localStorage.setItem('cmdHistory', JSON.stringify(newHistory));
    setHistoryIndex(-1);

    addLog(`> ${trimmed}`);

    const parts = trimmed.split(' ');
    const command = parts[0].toLowerCase();

    switch (command) {
      case 'clear':
        clearLogs();
        break;
      case 'theme':
        if (parts[1]) {
          const newTheme = parts[1].toLowerCase() as ThemeType;
          const validThemes = ['matrix', 'dracula', 'cyberpunk', 'amber', 'nord'];
          if (validThemes.includes(newTheme)) {
            setTheme(newTheme);
            addLog(`Theme changed to ${newTheme}`);
          } else {
            addLog(`Error: Invalid theme. Valid themes: ${validThemes.join(', ')}`);
          }
        } else {
           addLog(`Usage: theme <color>`);
        }
        break;
      case 'help':
        addLog(`Available commands: clear, theme <color>, help, scan, consult, audit, cve`);
        break;
      case 'scan':
      case 'consult':
      case 'audit':
      case 'cve':
         addLog(`[System] Command '${command}' registered. Module dispatch simulated.`);
         break;
      default:
        addLog(`Error: Command '${command}' not found. Type 'help' for available commands.`);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleCommand(input);
      setInput('');
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (historyIndex < history.length - 1) {
        const nextIndex = historyIndex + 1;
        setHistoryIndex(nextIndex);
        setInput(history[nextIndex]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex > 0) {
        const prevIndex = historyIndex - 1;
        setHistoryIndex(prevIndex);
        setInput(history[prevIndex]);
      } else if (historyIndex === 0) {
        setHistoryIndex(-1);
        setInput('');
      }
    }
  };

  return (
    <div className="h-48 border-t border-term-border bg-term-bg/95 p-2 flex flex-col font-mono text-sm">
      <div className="text-term-dim mb-1">TERMINAL // TYPE 'HELP' FOR COMMANDS</div>
      <div className="flex items-center gap-2">
        <span className="text-term-accent font-bold">$</span>
        <input
          ref={inputRef}
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          className="flex-1 bg-transparent border-none outline-none text-term-fg placeholder-term-dim"
          placeholder="Enter command..."
          autoComplete="off"
          spellCheck="false"
        />
      </div>
    </div>
  );
};
