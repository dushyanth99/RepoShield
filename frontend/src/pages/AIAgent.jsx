import { useState, useEffect, useRef } from "react";
import { Bot, TerminalSquare, RefreshCw, Zap, ShieldAlert, Cpu, Activity, Database } from "lucide-react";
import { cn } from "@/utils/cn";

export default function AIAgent() {
  const isDemoMode = localStorage.getItem('demoMode') === 'true';
  const [isBackendConnected, setIsBackendConnected] = useState(isDemoMode);
  const [agentStatus, setAgentStatus] = useState("Idle");
  const [isWaking, setIsWaking] = useState(false);
  const [logs, setLogs] = useState([]);
  const logsEndRef = useRef(null);

  const scrollToBottom = () => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [logs]);

  const handleWakeAgent = () => {
    if (isWaking || agentStatus === "Active") return;
    
    setIsWaking(true);
    setAgentStatus("Initializing...");
    setLogs([]);

    const sequence = [
      { delay: 100, log: { type: 'cmd', text: '$ systemctl start ml_engine.agent' } },
      { delay: 800, log: { type: 'sys', text: 'Initializing neural subsystems...' } },
      { delay: 1500, log: { type: 'success', text: '[OK] Model loaded: CVEFixes-v1.0.8' }, status: 'Model Loaded' },
      { delay: 2200, log: { type: 'info', text: '> Connecting to repository webhooks...' } },
      { delay: 2800, log: { type: 'success', text: '[OK] Connected to 3 active repositories' } },
      { delay: 3500, log: { type: 'info', text: '> Analyzing repository: payment-gateway' }, status: 'Analyzing' },
      { delay: 4200, log: { type: 'info', text: '> Detected SQL Injection pattern in controllers/payment.js' } },
      { delay: 4800, log: { type: 'info', text: '> Cross-referencing with CVE database...' } },
      { delay: 5500, log: { type: 'warn', text: '[WARN] High confidence match: CVE-2023-XXXX' } },
      { delay: 6200, log: { type: 'info', text: '> Generating remediation patch...' } },
      { delay: 7500, log: { type: 'success', text: '[OK] Patch generated. Awaiting manual review.' }, status: 'Active' },
    ];

    sequence.forEach(({ delay, log, status }) => {
      setTimeout(() => {
        setLogs(prev => [...prev, log]);
        if (status) setAgentStatus(status);
        if (delay === 7500) setIsWaking(false);
      }, delay);
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row justify-between md:items-end gap-4">
        <div>
          <h1 className="text-3xl font-heading font-bold text-foreground">AI Security Agent</h1>
          <p className="text-slate-400 mt-1">Autonomous reasoning and automated vulnerability remediation</p>
        </div>
        <div className="flex items-center space-x-3">
          <button 
            onClick={handleWakeAgent}
            disabled={!isBackendConnected || isWaking || agentStatus === "Active"}
            className={cn(
              "flex items-center space-x-2 px-4 py-2 rounded-lg font-medium transition-colors shadow-[0_0_15px_rgba(59,130,246,0.3)]",
              (!isBackendConnected || agentStatus === "Active") 
                ? "bg-slate-800 text-slate-500 cursor-not-allowed shadow-none" 
                : "bg-primary hover:bg-primary-dark text-white"
            )}
          >
            <Zap className={cn("w-4 h-4", isWaking ? "animate-pulse text-yellow-300" : "")} />
            <span>{isWaking ? "Waking..." : agentStatus === "Active" ? "Agent Active" : "Wake Agent"}</span>
          </button>
        </div>
      </div>

      {!isBackendConnected ? (
        <div className="glass-card flex flex-col items-center justify-center p-16 text-center min-h-[400px]">
          <div className="w-20 h-20 bg-navy-800 rounded-full flex items-center justify-center mb-6">
            <Bot className="w-10 h-10 text-slate-500" />
          </div>
          <h3 className="text-xl font-medium text-foreground mb-2">Agent is Hibernating</h3>
          <p className="text-slate-400 max-w-md mb-6">
            The AI Agent requires the ml_engine backend to be online to process CVEFixes dataset models and generate automated remediations.
          </p>
          <button 
            onClick={() => setIsBackendConnected(true)}
            className="flex items-center space-x-2 px-4 py-2 border border-border bg-white/5 hover:bg-white/10 rounded-lg text-slate-300 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Force Connect (Demo)</span>
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
             <div className="glass-card p-5 flex flex-col h-[400px]">
               <h3 className="text-base font-medium text-foreground mb-4">Agent Reasoning Log</h3>
               <div className="bg-navy-950 p-4 rounded-lg font-mono text-sm h-full overflow-y-auto border border-border shadow-inner">
                 {logs.length === 0 ? (
                   <div className="text-slate-600 italic mt-2">Awaiting wake signal...</div>
                 ) : (
                   logs.map((log, i) => (
                     <div key={i} className={cn(
                       "mb-1.5",
                       log.type === 'cmd' ? "text-primary font-bold mb-3" :
                       log.type === 'success' ? "text-green-400" :
                       log.type === 'warn' ? "text-orange-400 font-medium" :
                       log.type === 'sys' ? "text-slate-500" :
                       "text-slate-300"
                     )}>
                       {log.text}
                     </div>
                   ))
                 )}
                 {isWaking && (
                   <div className="flex items-center mt-2">
                     <span className="w-2 h-4 bg-slate-400 animate-pulse"></span>
                   </div>
                 )}
                 <div ref={logsEndRef} />
               </div>
             </div>
          </div>
          <div className="lg:col-span-1 space-y-6">
             <div className="glass-card p-5">
               <h3 className="text-base font-medium text-foreground mb-4">Agent Status</h3>
               <div className="space-y-4">
                 <div className="flex items-center justify-between">
                   <div className="flex items-center space-x-2 text-sm text-slate-300"><Cpu className={cn("w-4 h-4", agentStatus === "Active" ? "text-primary" : "text-slate-500")}/><span>Model Load</span></div>
                   <span className="text-sm font-medium">{agentStatus === "Active" ? "100%" : isWaking ? "85%" : "0%"}</span>
                 </div>
                 <div className="flex items-center justify-between">
                   <div className="flex items-center space-x-2 text-sm text-slate-300"><Activity className={cn("w-4 h-4", agentStatus === "Active" ? "text-green-400" : isWaking ? "text-yellow-400 animate-pulse" : "text-slate-500")}/><span>Status</span></div>
                   <span className={cn(
                     "text-sm font-medium",
                     agentStatus === "Active" ? "text-green-400" : 
                     isWaking ? "text-yellow-400" : "text-slate-500"
                   )}>{agentStatus}</span>
                 </div>
                 <div className="flex items-center justify-between">
                   <div className="flex items-center space-x-2 text-sm text-slate-300"><ShieldAlert className={cn("w-4 h-4", agentStatus === "Active" ? "text-orange-400" : "text-slate-500")}/><span>Tasks</span></div>
                   <span className="text-sm font-medium">{agentStatus === "Active" ? "3 Pending" : "0"}</span>
                 </div>
               </div>
             </div>
          </div>
        </div>
      )}
    </div>
  );
}