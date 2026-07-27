import React, { useState } from 'react';
import { useAppState } from '../store/AppStateContext';

export const AiConsultantModule: React.FC = () => {
  const { addLog } = useAppState();
  const [prompt, setPrompt] = useState('');
  const [conversation, setConversation] = useState<{role: 'user'|'ai', text: string}[]>([]);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!prompt.trim()) return;

    const userText = prompt.trim();
    setConversation(prev => [...prev, { role: 'user', text: userText }]);
    setPrompt('');
    setLoading(true);

    try {
      const response = await fetch('http://localhost:3000/api/gemini/consult', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          prompt: userText,
          moduleContext: 'AI Consultant Chat Interface'
        })
      });

      const data = await response.json();
      if (response.ok) {
        setConversation(prev => [...prev, { role: 'ai', text: data.result }]);
      } else {
        setConversation(prev => [...prev, { role: 'ai', text: `Error: ${data.error}` }]);
        addLog(`AI Consultant Error: ${data.error}`);
      }
    } catch (err: any) {
      setConversation(prev => [...prev, { role: 'ai', text: `Connection Error: ${err.message}` }]);
      addLog(`AI Consultant Connection Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-4 h-full flex flex-col gap-4">
      <h2 className="text-xl font-bold uppercase border-b border-term-dim pb-2">AI Security Consultant</h2>
      
      <div className="flex-1 overflow-y-auto border border-term-dim p-4 flex flex-col gap-4 bg-term-bg/50">
        {conversation.map((msg, i) => (
          <div key={i} className={`flex flex-col gap-1 ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
            <span className={`text-xs ${msg.role === 'user' ? 'text-term-dim' : 'text-term-accent font-bold'}`}>
              {msg.role === 'user' ? 'YOU' : 'AI_CONSULTANT'}
            </span>
            <div className={`p-2 max-w-[80%] whitespace-pre-wrap font-mono ${msg.role === 'user' ? 'bg-term-dim/20 border border-term-dim' : 'bg-term-accent/10 border border-term-accent text-term-fg'}`}>
              {msg.text}
            </div>
          </div>
        ))}
        {loading && (
          <div className="text-term-accent animate-pulse">PROCESSING_QUERY...</div>
        )}
      </div>

      <form onSubmit={handleSubmit} className="flex gap-2">
        <span className="text-term-accent self-center font-bold">{'>'}</span>
        <input
          type="text"
          value={prompt}
          onChange={e => setPrompt(e.target.value)}
          placeholder="Ask about vulnerabilities, mitigations, or IaC patches..."
          className="flex-1 bg-transparent border-b border-term-dim p-2 outline-none text-term-fg placeholder-term-dim"
          disabled={loading}
        />
        <button type="submit" disabled={loading} className="px-4 py-2 border border-term-accent hover:bg-term-accent hover:text-term-bg transition-colors">
          SEND
        </button>
      </form>
    </div>
  );
};
