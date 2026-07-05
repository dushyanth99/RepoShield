import { useState } from "react";
import MetricsBanner from "@/components/dashboard/MetricsBanner";
import RiskOverviewGauge from "@/components/dashboard/RiskOverviewGauge";
import VulnerabilitiesChart from "@/components/dashboard/VulnerabilitiesChart";
import { useDashboardMetrics } from "@/hooks/useApi";
import { X } from "lucide-react";

export default function Dashboard() {
  const { data: metrics } = useDashboardMetrics();
  const [isRecentScansOpen, setIsRecentScansOpen] = useState(false);
  
  const isDemoMode = localStorage.getItem('demoMode') === 'true';
  const isOffline = !metrics && !isDemoMode;

  const mockScans = [
    { repo: 'payment-gateway', time: '2m ago', severity: 'Critical', color: 'text-red-400 bg-red-400/10' },
    { repo: 'auth-service', time: '15m ago', severity: 'High', color: 'text-orange-400 bg-orange-400/10' },
    { repo: 'user-service', time: '1h ago', severity: 'Medium', color: 'text-yellow-400 bg-yellow-400/10' },
    { repo: 'notification-service', time: '2h ago', severity: 'Low', color: 'text-green-400 bg-green-400/10' }
  ];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-heading font-bold text-foreground">Dashboard</h1>
          <p className="text-slate-400 mt-1">AI-Powered Autonomous Security for Your Repositories</p>
        </div>
      </div>
      
      {/* Top Banner Metrics */}
      <MetricsBanner isOffline={isOffline} />

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <RiskOverviewGauge isOffline={isOffline} />
        <VulnerabilitiesChart isOffline={isOffline} />
        
        {/* Recent Scans Placeholder */}
        <div className="glass-card p-5 h-[300px]">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-heading font-medium">Recent Scans</h3>
            <button 
              onClick={() => setIsRecentScansOpen(true)}
              className="text-xs text-primary hover:text-primary-dark"
            >
              View All
            </button>
          </div>
          <div className="space-y-3">
            {isOffline ? (
               <div className="flex flex-col items-center justify-center h-48 text-slate-500 text-sm">
                 No recent scans available.
               </div>
            ) : (
              mockScans.map((scan, i) => (
                <div key={i} className="flex justify-between items-center p-2 hover:bg-white/5 rounded-lg transition-colors">
                  <div>
                    <div className="text-sm font-medium text-slate-200">{scan.repo}</div>
                    <div className="text-xs text-slate-500">{scan.time}</div>
                  </div>
                  <div className={`px-2 py-1 rounded text-xs font-medium ${scan.color}`}>
                    {scan.severity}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Live Scan Pipeline & Business Risk / Predictive Analytics Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-card p-5 min-h-[250px]">
          <h3 className="text-lg font-heading font-medium mb-4">Live Scan</h3>
          {isOffline ? (
            <div className="flex flex-col items-center justify-center h-32 text-slate-500 text-sm">
              No active scans.
            </div>
          ) : (
            <>
              <p className="text-sm text-slate-400 mb-6">Real-time scanning of payment-gateway repository</p>
              <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-primary w-2/3 shadow-[0_0_10px_rgba(59,130,246,0.8)]"></div>
              </div>
              <div className="mt-2 text-right text-sm text-primary font-medium">66%</div>
            </>
          )}
        </div>
        
        <div className="glass-card p-5 min-h-[250px]">
          <h3 className="text-lg font-heading font-medium mb-4">Business Risk</h3>
          <p className="text-sm text-slate-400">
            {isOffline ? "No data available." : "Analyze business impact of vulnerabilities."}
          </p>
        </div>
      </div>

      {/* Recent Scans Modal */}
      {isRecentScansOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-navy-900 border border-border w-full max-w-lg rounded-xl shadow-2xl overflow-hidden animate-in zoom-in-95 duration-200 flex flex-col max-h-[80vh]">
            <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-white/5">
              <h2 className="text-lg font-heading font-bold text-foreground">All Recent Scans</h2>
              <button 
                onClick={() => setIsRecentScansOpen(false)}
                className="p-1.5 text-slate-400 hover:text-white hover:bg-white/10 rounded-md transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 overflow-y-auto">
              {isOffline ? (
                <div className="flex flex-col items-center justify-center py-12 text-slate-500">
                  <p>No historical scans found in the database.</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {mockScans.map((scan, i) => (
                    <div key={i} className="flex justify-between items-center p-3 border border-border bg-white/5 rounded-lg">
                      <div>
                        <div className="text-sm font-medium text-slate-200">{scan.repo}</div>
                        <div className="text-xs text-slate-500">{scan.time}</div>
                      </div>
                      <div className={`px-2 py-1 rounded text-xs font-medium ${scan.color}`}>
                        {scan.severity}
                      </div>
                    </div>
                  ))}
                  <div className="flex justify-between items-center p-3 border border-border bg-white/5 rounded-lg opacity-60">
                    <div>
                      <div className="text-sm font-medium text-slate-200">legacy-api-v1</div>
                      <div className="text-xs text-slate-500">1 day ago</div>
                    </div>
                    <div className="px-2 py-1 rounded text-xs font-medium text-green-400 bg-green-400/10">
                      Low
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}