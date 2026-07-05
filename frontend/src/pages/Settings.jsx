import { useState } from "react";
import { Settings as SettingsIcon, Shield, Bell, User, Key, GitPullRequest, History, Database } from "lucide-react";
import { cn } from "@/utils/cn";
import { useDashboardMetrics } from "@/hooks/useApi";

export default function Settings() {
  const [activeTab, setActiveTab] = useState("History");
  const { data: metrics } = useDashboardMetrics();
  const isDemoMode = localStorage.getItem('demoMode') === 'true';
  const isOffline = !metrics && !isDemoMode;

  const tabs = [
    { name: "General", icon: SettingsIcon },
    { name: "History", icon: History },
    { name: "Security", icon: Shield },
    { name: "Notifications", icon: Bell },
    { name: "Account", icon: User },
    { name: "API Keys", icon: Key },
    { name: "Integrations", icon: GitPullRequest },
  ];

  const recentProjects = [
    { name: "payment-gateway", url: "https://github.com/org/payment-gateway", date: "2023-10-24 14:32:00", status: "Active" },
    { name: "auth-service", url: "https://github.com/org/auth-service", date: "2023-10-23 09:15:00", status: "Active" },
    { name: "user-service", url: "https://github.com/org/user-service", date: "2023-10-20 16:45:00", status: "Inactive" },
    { name: "notification-service", url: "https://github.com/org/notification-service", date: "2023-10-18 11:20:00", status: "Active" },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-heading font-bold text-foreground">Settings</h1>
        <p className="text-slate-400 mt-1">Configure your RepoShield preferences and backend connections</p>
      </div>

      <div className="flex flex-col lg:flex-row gap-6">
        {/* Sidebar */}
        <div className="w-full lg:w-64 space-y-1">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
               <button
                key={tab.name}
                onClick={() => setActiveTab(tab.name)}
                className={cn(
                  "w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors",
                  activeTab === tab.name
                    ? "bg-primary text-white"
                    : "text-slate-400 hover:text-slate-200 hover:bg-white/5"
                )}
              >
                <Icon className="w-5 h-5" />
                <span>{tab.name}</span>
              </button>
            );
          })}
        </div>

        {/* Content */}
        <div className="flex-1 glass-card p-6 min-h-[400px]">
          <h2 className="text-xl font-medium text-foreground mb-6">{activeTab}</h2>
          
          {activeTab === "General" && (
            <div className="space-y-6 max-w-2xl">
              <div className="space-y-2">
                <label className="text-sm font-medium text-slate-300">Backend API URL</label>
                <input 
                  type="text" 
                  defaultValue="https://unmendable-lala-complexly.ngrok-free.dev"
                  className="w-full bg-navy-950 border border-border rounded-lg py-2 px-3 text-sm text-foreground focus:outline-none focus:border-primary/50 transition-colors"
                />
                <p className="text-xs text-slate-500">The endpoint where the ml_engine and backend are hosted.</p>
              </div>
              <button className="bg-primary hover:bg-primary-dark text-white px-4 py-2 rounded-lg font-medium transition-colors">
                Save Changes
              </button>
            </div>
          )}

          {activeTab === "History" && (
            <div className="space-y-4">
              <p className="text-slate-400 text-sm mb-4">View your recently submitted repositories and scanning history.</p>
              
              {isOffline ? (
                <div className="flex flex-col items-center justify-center p-12 text-center border border-dashed border-border rounded-lg bg-white/5">
                  <Database className="w-10 h-10 text-slate-500 mb-4" />
                  <h3 className="text-lg font-medium text-slate-300 mb-1">No History Data</h3>
                  <p className="text-sm text-slate-500">History records will appear here once the backend securely syncs the repository data.</p>
                </div>
              ) : (
                <div className="bg-navy-950 border border-border rounded-lg overflow-hidden">
                  <table className="w-full text-left text-sm">
                    <thead className="bg-white/5 border-b border-border text-slate-300">
                      <tr>
                        <th className="px-4 py-3 font-medium">Project Name</th>
                        <th className="px-4 py-3 font-medium">Repository URL</th>
                        <th className="px-4 py-3 font-medium">Date Submitted</th>
                        <th className="px-4 py-3 font-medium">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {recentProjects.map((project, i) => (
                        <tr key={i} className="hover:bg-white/5 transition-colors">
                          <td className="px-4 py-3 font-medium text-slate-200">{project.name}</td>
                          <td className="px-4 py-3 text-slate-400 font-mono text-xs truncate max-w-[200px]">
                            {project.url}
                          </td>
                          <td className="px-4 py-3 text-slate-400">{project.date}</td>
                          <td className="px-4 py-3">
                            <span className={cn(
                              "px-2 py-1 rounded text-xs font-medium",
                              project.status === "Active" ? "bg-green-500/10 text-green-400" : "bg-slate-500/10 text-slate-400"
                            )}>
                              {project.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {activeTab !== "General" && activeTab !== "History" && (
            <div className="text-slate-400 py-12 text-center flex flex-col items-center justify-center">
              <SettingsIcon className="w-12 h-12 text-slate-600 mb-4 opacity-50" />
              <p>Settings panel for <strong className="text-slate-300">{activeTab}</strong> is under construction.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}