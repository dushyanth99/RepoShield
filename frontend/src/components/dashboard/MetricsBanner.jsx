import { FolderGit2, ShieldAlert, Activity, Bot, ShieldCheck } from "lucide-react";
import { cn } from "@/utils/cn";

const defaultMetrics = [
  { label: "Repositories", value: "24", trend: "↑ 12 this week", trendUp: true, icon: FolderGit2, color: "text-blue-400", bg: "bg-blue-400/10" },
  { label: "Vulnerabilities", value: "156", trend: "↓ 18 resolved", trendUp: true, icon: ShieldAlert, color: "text-red-400", bg: "bg-red-400/10" },
  { label: "Business Risk Score", value: "72", subValue: "/ 100", status: "Medium Risk", icon: Activity, color: "text-orange-400", bg: "bg-orange-400/10" },
  { label: "AI Patches Created", value: "48", trend: "↑ 8 this week", trendUp: true, icon: Bot, color: "text-purple-400", bg: "bg-purple-400/10" },
  { label: "Compliance Score", value: "92%", status: "Good", icon: ShieldCheck, color: "text-green-400", bg: "bg-green-400/10" },
];

const offlineMetrics = [
  { label: "Repositories", value: "0", icon: FolderGit2, color: "text-slate-400", bg: "bg-slate-800" },
  { label: "Vulnerabilities", value: "0", icon: ShieldAlert, color: "text-slate-400", bg: "bg-slate-800" },
  { label: "Business Risk Score", value: "0", subValue: "/ 100", status: "N/A", icon: Activity, color: "text-slate-400", bg: "bg-slate-800" },
  { label: "AI Patches Created", value: "0", icon: Bot, color: "text-slate-400", bg: "bg-slate-800" },
  { label: "Compliance Score", value: "0%", status: "N/A", icon: ShieldCheck, color: "text-slate-400", bg: "bg-slate-800" },
];

export default function MetricsBanner({ isOffline }) {
  const metrics = isOffline ? offlineMetrics : defaultMetrics;

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4 mb-6">
      {metrics.map((m, i) => {
        const Icon = m.icon;
        return (
          <div key={i} className="glass-card p-4 flex flex-col justify-between">
            <div className="flex justify-between items-start mb-2">
              <span className="text-slate-400 text-sm font-medium">{m.label}</span>
              <div className={cn("p-2 rounded-lg", m.bg)}>
                <Icon className={cn("w-5 h-5", m.color)} />
              </div>
            </div>
            <div className="mt-2">
              <div className="flex items-baseline space-x-1">
                <span className="text-2xl font-bold text-foreground">{m.value}</span>
                {m.subValue && <span className="text-sm text-slate-500">{m.subValue}</span>}
              </div>
              
              {m.trend && (
                <div className={cn("text-xs font-medium mt-1", m.trendUp ? "text-green-400" : "text-red-400")}>
                  {m.trend}
                </div>
              )}
              {m.status && (
                <div className={cn(
                  "text-xs font-medium mt-1",
                  m.status === "Medium Risk" ? "text-orange-400" : (m.status === "N/A" ? "text-slate-500" : "text-green-400")
                )}>
                  {m.status}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
