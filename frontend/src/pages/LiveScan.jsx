import { useState, useEffect } from "react";
import { Search, Play, Square, Activity, Database, Server, CheckCircle, XCircle } from "lucide-react";
import { cn } from "@/utils/cn";
import { api } from "@/services/api";
import { useAuth } from "@/context/AuthContext";

export default function LiveScan() {
  const [isScanning, setIsScanning] = useState(false);
  const [jobId, setJobId] = useState(null);
  const [jobStatus, setJobStatus] = useState(null);
  const [telemetry, setTelemetry] = useState(null);
  const [error, setError] = useState(null);
  const { user } = useAuth();

  const handleStartScan = async () => {
    try {
      setIsScanning(true);
      setError(null);
      setTelemetry(null);
      // Hardcoded repositoryId for demo/hackathon context
      const repositoryId = "repo-123";
      const response = await api.triggerManualScan(repositoryId);
      setJobId(response.job_id);
      setJobStatus("PENDING");
    } catch (err) {
      setError(err.message || "Failed to trigger scan.");
      setIsScanning(false);
    }
  };

  const handleStopScan = () => {
    setIsScanning(false);
    setJobId(null);
    setJobStatus(null);
    setTelemetry(null);
  };

  useEffect(() => {
    if (!jobId || (!isScanning && jobStatus !== 'VERIFIED' && jobStatus !== 'FAILED')) return;

    // Use EventSource for SSE stream as per Integration Guide
    const eventSource = new EventSource(`/api/v1/jobs/${jobId}/stream`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setTelemetry(data);
        if (data.status) setJobStatus(data.status);

        if (data.status === 'VERIFIED' || data.status === 'FAILED') {
          setIsScanning(false);
          eventSource.close();
        }
      } catch (error) {
        console.error('Failed to parse SSE telemetry data:', error);
      }
    };

    eventSource.onerror = (error) => {
      console.error('SSE Stream disconnected or encountered an error:', error);
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [jobId, isScanning, jobStatus]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row justify-between md:items-end gap-4">
        <div>
          <h1 className="text-3xl font-heading font-bold text-foreground">Live Scan</h1>
          <p className="text-slate-400 mt-1">Real-time vulnerability detection powered by ml_engine</p>
        </div>
        <div className="flex items-center space-x-3">
          <button 
            onClick={isScanning || jobStatus === 'VERIFIED' || jobStatus === 'FAILED' ? handleStopScan : handleStartScan}
            className={cn(
              "flex items-center space-x-2 px-4 py-2 rounded-lg font-medium transition-colors shadow-lg",
              isScanning || jobStatus === 'VERIFIED' || jobStatus === 'FAILED' ? "bg-red-500/20 text-red-500 border border-red-500/50 hover:bg-red-500/30" : "bg-primary hover:bg-primary-dark text-white"
            )}
          >
            {isScanning || jobStatus === 'VERIFIED' || jobStatus === 'FAILED' ? (
              <>
                <Square className="w-4 h-4" />
                <span>Reset Scan</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                <span>Start Global Scan</span>
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/50 text-red-400 p-4 rounded-lg">
          {error}
        </div>
      )}

      {!isScanning && !jobStatus ? (
        <div className="glass-card flex flex-col items-center justify-center p-16 text-center min-h-[400px]">
          <div className="w-20 h-20 bg-navy-800 rounded-full flex items-center justify-center mb-6">
            <Server className="w-10 h-10 text-slate-500" />
          </div>
          <h3 className="text-xl font-medium text-foreground mb-2">No Active Scans</h3>
          <p className="text-slate-400 max-w-md mb-6">
            Click Start Global Scan to trigger the ml_engine scanning job and orchestrator.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="glass-card p-6 min-h-[400px] flex flex-col items-center justify-center">
            <div className="relative">
              {jobStatus === 'VERIFIED' ? (
                <div className="w-32 h-32 rounded-full border-4 border-green-500/20 flex items-center justify-center bg-green-500/10">
                  <CheckCircle className="w-12 h-12 text-green-500" />
                </div>
              ) : jobStatus === 'FAILED' ? (
                <div className="w-32 h-32 rounded-full border-4 border-red-500/20 flex items-center justify-center bg-red-500/10">
                  <XCircle className="w-12 h-12 text-red-500" />
                </div>
              ) : (
                <div className="w-32 h-32 rounded-full border-4 border-primary/20 flex items-center justify-center">
                  <div className="w-28 h-28 rounded-full border-4 border-t-primary border-r-primary border-b-transparent border-l-transparent animate-spin flex items-center justify-center">
                    <Activity className="w-10 h-10 text-primary animate-pulse" />
                  </div>
                </div>
              )}
            </div>
            
            <h3 className="text-lg font-medium text-foreground mt-6">
              {jobStatus === 'PENDING' && "Job Queued..."}
              {jobStatus === 'IN_PROGRESS' && "ml_engine analyzing codebase..."}
              {jobStatus === 'SANDBOXING' && "Executing in secure sandbox..."}
              {jobStatus === 'ML_EVALUATION' && "Evaluating model armor..."}
              {jobStatus === 'FABLE_5_REMEDIATION' && "Generating self-healing patch..."}
              {jobStatus === 'VERIFIED' && "Remediation Verified & Patched"}
              {jobStatus === 'FAILED' && "Remediation Failed"}
            </h3>
            
            <div className="text-sm text-slate-400 mt-2 font-mono">Job ID: {jobId}</div>
          </div>
          
          <div className="glass-card p-6 min-h-[400px]">
            <h3 className="text-base font-medium text-foreground mb-4">Lifecycle State Tracker</h3>
            <div className="bg-navy-950 p-4 rounded-lg font-mono text-sm text-slate-300 h-full overflow-y-auto space-y-4">
              <div className={cn("transition-opacity", jobStatus ? "opacity-100" : "opacity-50")}>
                <span className="text-slate-500">[1]</span> <span className={jobStatus === 'PENDING' ? 'text-primary' : 'text-slate-300'}>PENDING</span>
              </div>
              <div className={cn("transition-opacity", (jobStatus === 'SANDBOXING' || jobStatus === 'ML_EVALUATION' || jobStatus === 'FABLE_5_REMEDIATION' || jobStatus === 'VERIFIED' || jobStatus === 'FAILED') ? "opacity-100" : "opacity-30")}>
                <span className="text-slate-500">[2]</span> <span className={jobStatus === 'SANDBOXING' ? 'text-primary' : 'text-slate-300'}>SANDBOXING</span>
              </div>
              <div className={cn("transition-opacity", (jobStatus === 'ML_EVALUATION' || jobStatus === 'FABLE_5_REMEDIATION' || jobStatus === 'VERIFIED' || jobStatus === 'FAILED') ? "opacity-100" : "opacity-30")}>
                <span className="text-slate-500">[3]</span> <span className={jobStatus === 'ML_EVALUATION' ? 'text-primary' : 'text-slate-300'}>ML_EVALUATION</span>
              </div>
              <div className={cn("transition-opacity", (jobStatus === 'FABLE_5_REMEDIATION' || jobStatus === 'VERIFIED' || jobStatus === 'FAILED') ? "opacity-100" : "opacity-30")}>
                <span className="text-slate-500">[4]</span> <span className={jobStatus === 'FABLE_5_REMEDIATION' ? 'text-primary' : 'text-slate-300'}>FABLE_5_REMEDIATION</span>
              </div>
              
              {telemetry && (
                <div className="pt-4 border-t border-white/10 mt-4 space-y-2">
                  {telemetry.file_path && <div className="text-slate-300">File: {telemetry.file_path}</div>}
                  {telemetry.self_healing_count !== undefined && <div className="text-slate-300">Self-Healing Iterations: {telemetry.self_healing_count}</div>}
                  {telemetry.model_armor_blocked !== undefined && <div className="text-slate-300">Armor Blocks: {telemetry.model_armor_blocked}</div>}
                </div>
              )}

              {(jobStatus === 'VERIFIED' || jobStatus === 'FAILED') && (
                <div className="pt-4 border-t border-white/10 mt-4">
                  {jobStatus === 'VERIFIED' ? (
                    <div className="text-green-400">
                      ✓ VERIFIED: Pull request successfully generated by agent.
                      {telemetry?.pull_request_url && (
                        <div className="mt-2">
                          <a href={telemetry.pull_request_url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                            View Pull Request
                          </a>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="text-red-400">✗ FAILED: Agent could not apply a reliable patch.</div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}