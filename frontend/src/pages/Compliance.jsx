import { Search, RefreshCw, Download, FileText, CheckCircle, XCircle, AlertTriangle, ShieldCheck, Database } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { cn } from "@/utils/cn";
import { useComplianceStatus } from "@/hooks/useApi";

const complianceStatusData = [
  { name: 'Compliant', value: 186, color: '#22c55e' },
  { name: 'Partially Compliant', value: 27, color: '#eab308' },
  { name: 'Non-Compliant', value: 61, color: '#ef4444' },
];

const frameworks = [
  { name: "OWASP Top 10", version: "2021", score: "85%", status: "Compliant", color: "text-green-400" },
  { name: "OWASP ASVS", version: "v4.0.3", score: "72%", status: "Partially Compliant", color: "text-yellow-400" },
  { name: "OWASP MASVS", version: "v2.0.0", score: "90%", status: "Compliant", color: "text-green-400" },
  { name: "OWASP SAMM", version: "v2.0", score: "68%", status: "Partially Compliant", color: "text-yellow-400" },
  { name: "OWASP API Top 10", version: "2019", score: "75%", status: "Partially Compliant", color: "text-yellow-400" },
  { name: "OWASP LLM Top 10", version: "2023", score: "80%", status: "Compliant", color: "text-green-400" }
];

const checklist = [
  { id: "CHK-001", item: "Use of parameterized queries to prevent SQL Injection", framework: "OWASP Top 10 (A03)", status: "Verified", icon: CheckCircle, color: "text-green-400", time: "2h ago" },
  { id: "CHK-002", item: "Output encoding implemented to prevent XSS", framework: "OWASP Top 10 (A07)", status: "Verified", icon: CheckCircle, color: "text-green-400", time: "3h ago" },
  { id: "CHK-003", item: "CSRF tokens implemented for state-changing requests", framework: "OWASP Top 10 (A01)", status: "Verified", icon: CheckCircle, color: "text-green-400", time: "4h ago" },
  { id: "CHK-004", item: "No hardcoded secrets in source code", framework: "OWASP Top 10 (A02)", status: "Failed", icon: XCircle, color: "text-red-400", time: "5h ago" },
  { id: "CHK-005", item: "Proper authentication mechanisms in place", framework: "OWASP ASVS (V2)", status: "Verified", icon: CheckCircle, color: "text-green-400", time: "6h ago" },
  { id: "CHK-006", item: "Access control enforced on sensitive endpoints", framework: "OWASP ASVS (V4)", status: "Failed", icon: XCircle, color: "text-red-400", time: "7h ago" },
  { id: "CHK-007", item: "Dependencies are up-to-date and free from known vulns", framework: "OWASP Dependency Check", status: "Verified", icon: CheckCircle, color: "text-green-400", time: "8h ago" },
  { id: "CHK-008", item: "Secure file upload validation implemented", framework: "OWASP Top 10 (A05)", status: "Partially Compliant", icon: AlertTriangle, color: "text-yellow-400", time: "9h ago" },
];

export default function Compliance() {
  const { data: complianceData } = useComplianceStatus();

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row justify-between md:items-end gap-4">
        <div>
          <h1 className="text-3xl font-heading font-bold text-foreground">Compliance</h1>
          <p className="text-slate-400 mt-1">Ensure your repositories meet industry security and compliance standards</p>
        </div>
        <div className="flex items-center space-x-3">
          <div className="relative w-64 hidden lg:block">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input type="text" placeholder="Search anything..." className="w-full bg-navy-900/50 border border-border rounded-full py-1.5 pl-9 pr-4 text-sm focus:outline-none focus:border-primary/50 transition-colors" />
          </div>
          <button className="flex items-center space-x-2 px-3 py-1.5 border border-border rounded-md text-sm text-slate-300 hover:bg-white/5 transition-colors">
            <RefreshCw className="w-4 h-4" />
            <span>Refresh Compliance</span>
          </button>
          <button className="flex items-center space-x-2 px-3 py-1.5 border border-border rounded-md text-sm text-slate-300 hover:bg-white/5 transition-colors">
            <Download className="w-4 h-4" />
            <span>Export Report</span>
          </button>
          <button className="flex items-center space-x-2 px-3 py-1.5 border border-border rounded-md text-sm text-slate-300 hover:bg-white/5 transition-colors">
            <FileText className="w-4 h-4" />
            <span>Audit Report</span>
          </button>
        </div>
      </div>

      {!complianceData ? (
        <div className="glass-card flex flex-col items-center justify-center p-16 text-center min-h-[400px]">
          <div className="w-20 h-20 bg-navy-800 rounded-full flex items-center justify-center mb-6">
            <Database className="w-10 h-10 text-slate-500" />
          </div>
          <h3 className="text-xl font-medium text-foreground mb-2">No Compliance Data Available</h3>
          <p className="text-slate-400 max-w-md mb-6">
            Connect the ml_engine backend to calculate compliance metrics against the CVEFixes dataset.
          </p>
        </div>
      ) : (
        <>
          {/* Top Banner Row */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            <div className="glass-card p-4 col-span-1 lg:col-span-1 flex flex-col justify-between">
              <h3 className="text-sm font-medium text-slate-400 mb-2">Overall Compliance Score</h3>
              <div className="flex-1 flex flex-col items-center justify-center relative">
                <div className="h-[100px] w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={[{ value: 78, color: '#22c55e' }, { value: 22, color: '#1f2937' }]} cx="50%" cy="100%" startAngle={180} endAngle={0} innerRadius={35} outerRadius={50} stroke="none" dataKey="value">
                        {[{ color: '#22c55e' }, { color: '#1f2937' }].map((e, i) => <Cell key={`c-${i}`} fill={e.color} />)}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="absolute bottom-0 text-center flex flex-col items-center">
                  <span className="text-3xl font-bold">78<span className="text-sm text-slate-400">%</span></span>
                  <span className="text-xs text-green-400 font-medium px-2 py-0.5 border border-green-500/30 rounded mt-1">Compliant</span>
                </div>
              </div>
            </div>

            {[
              { title: "Frameworks Assessed", val: "6", sub: "Active Frameworks", icon: ShieldCheck, color: "text-blue-400", bg: "bg-blue-400/10" },
              { title: "Passed Checks", val: "186", sub: "68%", icon: CheckCircle, color: "text-green-400", bg: "bg-green-400/10" },
              { title: "Failed Checks", val: "61", sub: "22%", icon: XCircle, color: "text-red-400", bg: "bg-red-400/10" },
              { title: "Total Checks", val: "274", sub: "Across all frameworks", icon: FileText, color: "text-purple-400", bg: "bg-purple-400/10" }
            ].map((item, i) => (
              <div key={i} className="glass-card p-4 flex flex-col justify-center items-center text-center">
                <h3 className="text-sm font-medium text-slate-400 mb-2">{item.title}</h3>
                <div className={cn("p-3 rounded-full mb-2 border border-white/5", item.bg)}>
                  <item.icon className={cn("w-6 h-6", item.color)} />
                </div>
                <div className="text-3xl font-bold text-foreground">{item.val}</div>
                <div className="text-xs text-slate-500 mt-1">{item.sub}</div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Frameworks Grid */}
            <div className="lg:col-span-2">
              <h3 className="text-base font-heading font-medium text-foreground mb-4">Compliance Frameworks (OWASP)</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {frameworks.map((fw, i) => (
                  <div key={i} className="glass-card p-4 hover:bg-white/5 transition-colors cursor-pointer border-t border-t-blue-500/30">
                    <div className="flex justify-between items-start mb-4">
                      <div className="flex items-center space-x-2">
                        <ShieldCheck className="w-5 h-5 text-primary" />
                        <div>
                          <div className="text-sm font-medium text-slate-200">{fw.name}</div>
                          <div className="text-xs text-slate-500">{fw.version}</div>
                        </div>
                      </div>
                    </div>
                    <div className="text-2xl font-bold text-foreground mb-1">{fw.score}</div>
                    <div className={cn("text-xs font-medium", fw.color)}>{fw.status}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Status Overview Donut */}
            <div className="glass-card p-5 lg:col-span-1 flex flex-col">
              <h3 className="text-base font-medium text-foreground mb-4">Compliance Status Overview</h3>
              <div className="flex-1 flex items-center justify-between">
                <div className="w-1/2 flex flex-col space-y-4">
                  {complianceStatusData.map((d, i) => (
                    <div key={i}>
                      <div className="flex items-center mb-1"><span className="w-2 h-2 rounded-full mr-2" style={{ backgroundColor: d.color }}></span><span className="text-xs text-slate-300">{d.name}</span></div>
                      <div className="text-sm font-medium text-slate-400 ml-4">{d.value} ({Math.round((d.value / 274) * 100)}%)</div>
                    </div>
                  ))}
                </div>
                <div className="w-1/2 h-full relative">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={complianceStatusData} innerRadius={40} outerRadius={60} dataKey="value" stroke="none" paddingAngle={2}>
                        {complianceStatusData.map((e, i) => <Cell key={`c-${i}`} fill={e.color} />)}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center mt-2">
                    <span className="text-xl font-bold">274</span>
                    <span className="text-[10px] text-slate-400 leading-tight">Total Checks</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Compliance Checklist and Areas */}
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            <div className="lg:col-span-3 glass-card overflow-hidden flex flex-col">
              <div className="p-4 border-b border-border flex justify-between items-center">
                <h3 className="text-base font-medium text-foreground">Compliance Checklist</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-white/5 text-slate-400">
                    <tr>
                      <th className="py-2 px-4 font-medium">ID</th>
                      <th className="py-2 px-4 font-medium">Checklist Item</th>
                      <th className="py-2 px-4 font-medium">Framework (OWASP)</th>
                      <th className="py-2 px-4 font-medium">Status</th>
                      <th className="py-2 px-4 font-medium">Evidence</th>
                      <th className="py-2 px-4 font-medium text-right">Last Audit</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border text-slate-300">
                    {checklist.map((c) => (
                      <tr key={c.id} className="hover:bg-white/5 transition-colors">
                        <td className="py-3 px-4 font-mono text-xs">{c.id}</td>
                        <td className="py-3 px-4">{c.item}</td>
                        <td className="py-3 px-4 text-xs text-slate-400">{c.framework}</td>
                        <td className="py-3 px-4">
                          <div className="flex items-center space-x-1.5">
                            <c.icon className={cn("w-4 h-4", c.color)} />
                            <span className={cn("text-xs font-medium", c.color)}>{c.status}</span>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <button className="p-1.5 text-slate-400 hover:text-slate-200 transition-colors bg-white/5 rounded"><FileText className="w-3.5 h-3.5" /></button>
                        </td>
                        <td className="py-3 px-4 text-right text-xs text-slate-500">{c.time}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="lg:col-span-1 space-y-4">
              <h3 className="text-base font-medium text-foreground">Top Non-Compliant Areas</h3>
              {[
                { id: "A02 - Cryptographic Failures", count: 7 },
                { id: "A01 - Broken Access Control", count: 5 },
                { id: "A07 - Identification & Auth Failures", count: 4 },
                { id: "A03 - Injection", count: 3 }
              ].map((area, i) => (
                <div key={i} className="p-3 bg-red-950/20 border border-red-500/20 rounded-lg flex flex-col border-l-2 border-l-red-500">
                  <span className="text-sm font-medium text-red-200">{area.id}</span>
                  <span className="text-xs text-red-400 mt-1">{area.count} Failed Checks</span>
                </div>
              ))}
              <button className="w-full flex items-center justify-center space-x-2 py-2 mt-4 bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 rounded-lg text-sm transition-colors">
                <FileText className="w-4 h-4" />
                <span>View Full Audit Report</span>
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}