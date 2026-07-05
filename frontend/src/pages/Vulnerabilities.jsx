import { useState } from "react";
import { Search, Filter, Download, MoreHorizontal, Shield, Globe, Key, FileCode, Users, TerminalSquare, UploadCloud, Link, Database } from "lucide-react";
import { cn } from "@/utils/cn";
import { useVulnerabilities } from "@/hooks/useApi";

const tabs = ["All Vulnerabilities", "Open", "In Progress", "Resolved", "Ignored"];

export default function Vulnerabilities() {
  const [activeTab, setActiveTab] = useState("All Vulnerabilities");
  
  // Use React Query for dynamic data
  const { data: vulnerabilities, isLoading, isError } = useVulnerabilities();

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row justify-between md:items-end gap-4">
        <div>
          <h1 className="text-3xl font-heading font-bold text-foreground">Vulnerabilities</h1>
          <p className="text-slate-400 mt-1">Identify and track security vulnerabilities across all your repositories</p>
        </div>
        <div className="relative w-full md:w-64">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search vulnerabilities..."
            className="w-full bg-navy-900/50 border border-border rounded-full py-1.5 pl-9 pr-4 text-sm focus:outline-none focus:border-primary/50 transition-colors"
          />
        </div>
      </div>

      <div className="flex space-x-1 border-b border-border w-full overflow-x-auto no-scrollbar">
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={cn(
              "px-4 py-2 font-medium text-sm transition-colors border-b-2 whitespace-nowrap",
              activeTab === tab
                ? "border-primary text-primary"
                : "border-transparent text-slate-400 hover:text-slate-200"
            )}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Selectors and Filters */}
      <div className="flex flex-wrap justify-between items-center gap-4 bg-white/5 p-2 rounded-lg border border-border">
        <div className="flex flex-wrap gap-3">
          {["All Severity", "All Types", "All Repositories", "All Branches"].map((opt, i) => (
            <select key={i} className="bg-navy-900 border border-border rounded-md px-3 py-1.5 text-sm text-slate-300 focus:outline-none appearance-none cursor-pointer hover:bg-white/5">
              <option>{opt}</option>
            </select>
          ))}
        </div>
        <div className="flex space-x-3">
          <button className="flex items-center space-x-2 px-3 py-1.5 border border-border rounded-md text-sm text-slate-300 hover:bg-white/5 transition-colors">
            <Filter className="w-4 h-4" />
            <span>Filter</span>
          </button>
          <button className="flex items-center space-x-2 px-3 py-1.5 border border-border rounded-md text-sm text-slate-300 hover:bg-white/5 transition-colors">
            <Download className="w-4 h-4" />
            <span>Export</span>
          </button>
        </div>
      </div>

      {/* Vulnerability Grid */}
      <div className="glass-card overflow-hidden min-h-[400px] flex flex-col">
        {isLoading ? (
          <div className="flex-1 flex flex-col items-center justify-center p-12 text-slate-400 space-y-4">
            <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
            <p>Scanning vulnerabilities...</p>
          </div>
        ) : isError || !vulnerabilities || vulnerabilities.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center p-12 text-center">
            <div className="w-16 h-16 bg-navy-800 rounded-full flex items-center justify-center mb-4">
              <Shield className="w-8 h-8 text-slate-500" />
            </div>
            <h3 className="text-lg font-medium text-foreground mb-2">No Vulnerabilities Detected</h3>
            <p className="text-sm text-slate-400 max-w-sm">
              Your ml_engine has not reported any issues yet, or the backend is offline. Run a Live Scan to detect vulnerabilities.
            </p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-border bg-white/5 text-sm font-medium text-slate-400">
                    <th className="py-3 px-4 font-medium">Vulnerability</th>
                    <th className="py-3 px-4 font-medium">Type</th>
                    <th className="py-3 px-4 font-medium">Repository</th>
                    <th className="py-3 px-4 font-medium">File</th>
                    <th className="py-3 px-4 font-medium text-center">Severity</th>
                    <th className="py-3 px-4 font-medium text-center">Status</th>
                    <th className="py-3 px-4 font-medium">Detected</th>
                    <th className="py-3 px-4 font-medium text-center">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {vulnerabilities.map((vuln) => {
                    const Icon = vuln.icon || Shield;
                    return (
                      <tr key={vuln.id} className="hover:bg-white/5 transition-colors group">
                        <td className="py-3 px-4 min-w-[200px]">
                          <div className="flex items-start space-x-3">
                            <div className={cn("p-2 rounded-lg mt-0.5", vuln.color)}>
                              <Icon className="w-5 h-5" />
                            </div>
                            <div>
                              <div className="font-medium text-slate-200 group-hover:text-primary transition-colors cursor-pointer">
                                {vuln.type}
                              </div>
                              <div className="text-xs text-slate-400 mt-0.5">{vuln.desc}</div>
                            </div>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <div className="text-sm text-slate-300">{vuln.repo}</div>
                          <div className="text-xs text-slate-500 mt-0.5">{vuln.branch}</div>
                        </td>
                        <td className="py-3 px-4">
                          <div className="text-sm text-slate-300">{vuln.repo}</div>
                        </td>
                        <td className="py-3 px-4">
                          <div className="text-sm text-slate-300 font-mono text-xs">{vuln.file}</div>
                          <div className="text-xs text-slate-500 mt-0.5">Line {vuln.line}</div>
                        </td>
                        <td className="py-3 px-4 text-center">
                          <span className={cn(
                            "px-2 py-0.5 rounded text-xs font-medium border",
                            vuln.severity === 'Critical' ? "border-red-500/30 text-red-400" :
                            vuln.severity === 'High' ? "border-orange-500/30 text-orange-400" :
                            "border-yellow-500/30 text-yellow-400"
                          )}>
                            {vuln.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-center">
                          <span className={cn(
                            "px-2 py-0.5 rounded-full text-[10px] font-medium border",
                            vuln.status === 'Open' ? "border-red-500/50 text-red-400 bg-red-400/10" :
                            vuln.status === 'In Progress' ? "border-blue-500/50 text-blue-400 bg-blue-400/10" :
                            "border-green-500/50 text-green-400 bg-green-400/10"
                          )}>
                            {vuln.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-sm text-slate-400">
                          {vuln.detected}
                        </td>
                        <td className="py-3 px-4 text-center">
                          <button className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-white/10 rounded-md transition-colors">
                            <MoreHorizontal className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="p-4 border-t border-border flex justify-between items-center text-sm text-slate-400">
              <span>Showing {vulnerabilities.length} vulnerabilities</span>
              <div className="flex space-x-1">
                <button className="px-2 py-1 rounded bg-white/5 hover:bg-white/10 transition-colors">&lt;</button>
                <button className="px-3 py-1 rounded bg-primary text-white">1</button>
                <button className="px-2 py-1 rounded bg-white/5 hover:bg-white/10 transition-colors">&gt;</button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}