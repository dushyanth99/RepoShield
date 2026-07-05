import { Search, RefreshCw, Download, Activity, Target, Shield, Briefcase, DollarSign, Bot, ArrowUpCircle } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip } from 'recharts';
import { cn } from "@/utils/cn";
import { useBusinessRisk } from "@/hooks/useApi";

const riskDistributionData = [
  { name: 'Critical', value: 18, color: '#ef4444' },
  { name: 'High', value: 32, color: '#f97316' },
  { name: 'Medium', value: 25, color: '#eab308' },
  { name: 'Low', value: 25, color: '#22c55e' },
];

const trendData = [
  { date: 'May 13', risk: 30 }, { date: 'May 20', risk: 45 }, 
  { date: 'May 27', risk: 55 }, { date: 'Jun 03', risk: 65 }, 
  { date: 'Jun 10', risk: 72 }
];

export default function BusinessRisk() {
  const { data: businessRisk } = useBusinessRisk();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between md:items-end gap-4">
        <div>
          <h1 className="text-3xl font-heading font-bold text-foreground">Business Risk</h1>
          <p className="text-slate-400 mt-1">Analyze and prioritize business risks across your repositories</p>
        </div>
        <div className="flex items-center space-x-3">
          <div className="relative w-64">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input type="text" placeholder="Search anything..." className="w-full bg-navy-900/50 border border-border rounded-full py-1.5 pl-9 pr-4 text-sm focus:outline-none focus:border-primary/50 transition-colors" />
          </div>
          <button className="flex items-center space-x-2 px-3 py-1.5 border border-border rounded-md text-sm text-slate-300 hover:bg-white/5 transition-colors">
            <RefreshCw className="w-4 h-4" />
            <span>Refresh Risk Analysis</span>
          </button>
          <button className="flex items-center space-x-2 px-3 py-1.5 border border-border rounded-md text-sm text-slate-300 hover:bg-white/5 transition-colors">
            <Download className="w-4 h-4" />
            <span>Export Report</span>
          </button>
        </div>
      </div>

      {!businessRisk ? (
        <div className="glass-card flex flex-col items-center justify-center p-16 text-center min-h-[400px]">
          <div className="w-20 h-20 bg-navy-800 rounded-full flex items-center justify-center mb-6">
            <Activity className="w-10 h-10 text-slate-500" />
          </div>
          <h3 className="text-xl font-medium text-foreground mb-2">No Risk Data Available</h3>
          <p className="text-slate-400 max-w-md mb-6">
            Connect the ml_engine to load the Business Risk analysis based on the CVEFixes dataset.
          </p>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            <div className="glass-card p-4 col-span-1 lg:col-span-1 flex flex-col justify-between">
               <h3 className="text-sm font-medium text-slate-400 mb-2">Business Risk Score</h3>
               <div className="flex-1 flex flex-col items-center justify-center relative">
                 <div className="h-[100px] w-full">
                   <ResponsiveContainer width="100%" height="100%">
                     <PieChart>
                       <Pie data={riskDistributionData} cx="50%" cy="100%" startAngle={180} endAngle={0} innerRadius={35} outerRadius={50} stroke="none" dataKey="value">
                         {riskDistributionData.map((e, i) => <Cell key={`c-${i}`} fill={e.color} />)}
                       </Pie>
                     </PieChart>
                   </ResponsiveContainer>
                 </div>
                 <div className="absolute bottom-0 text-center flex flex-col items-center">
                    <span className="text-3xl font-bold">72<span className="text-sm text-slate-400">/100</span></span>
                    <span className="text-xs text-orange-400 font-medium px-2 py-0.5 border border-orange-500/30 rounded mt-1">High Risk</span>
                 </div>
               </div>
            </div>

            <div className="glass-card p-4 flex flex-col">
              <h3 className="text-sm font-medium text-slate-400 mb-4">Risk Distribution</h3>
              <div className="flex items-center justify-center h-full gap-4">
                <div className="w-20 h-20">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={riskDistributionData} innerRadius={20} outerRadius={40} dataKey="value" stroke="none">
                        {riskDistributionData.map((e, i) => <Cell key={`c-${i}`} fill={e.color} />)}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="text-xs space-y-1">
                  {riskDistributionData.map(d => (
                    <div key={d.name} className="flex items-center"><span className="w-2 h-2 rounded-full mr-2" style={{backgroundColor: d.color}}></span><span className="w-12 text-slate-300">{d.name}</span><span className="text-slate-400">{d.value}%</span></div>
                  ))}
                </div>
              </div>
            </div>

            <div className="glass-card p-4 flex flex-col justify-center items-center text-center">
              <h3 className="text-sm font-medium text-slate-400 mb-2">Critical Risk</h3>
              <Activity className="w-8 h-8 text-red-500 mb-2" />
              <span className="text-3xl font-bold text-foreground">12</span>
            </div>
            
            <div className="glass-card p-4 flex flex-col justify-center items-center text-center">
              <h3 className="text-sm font-medium text-slate-400 mb-2">High Risk</h3>
              <Target className="w-8 h-8 text-orange-500 mb-2" />
              <span className="text-3xl font-bold text-foreground">21</span>
            </div>

            <div className="glass-card p-4 flex flex-col justify-center items-center text-center">
              <h3 className="text-sm font-medium text-slate-400 mb-2">Medium Risk</h3>
              <Shield className="w-8 h-8 text-yellow-500 mb-2" />
              <span className="text-3xl font-bold text-foreground">15</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              { title: "Revenue Impact", val: "$ 248K", sub: "Potential Loss", icon: DollarSign, color: "text-green-400", bg: "bg-green-400/10" },
              { title: "Reputation Impact", val: "High", sub: "Public Exposure", icon: Briefcase, color: "text-purple-400", bg: "bg-purple-400/10" },
              { title: "Compliance Impact", val: "Medium", sub: "Regulatory Risk", icon: Shield, color: "text-blue-400", bg: "bg-blue-400/10" },
              { title: "Financial Loss", val: "$ 186K", sub: "Est. Financial Loss", icon: DollarSign, color: "text-emerald-400", bg: "bg-emerald-400/10" }
            ].map((item, i) => (
              <div key={i} className="glass-card p-4 flex items-center space-x-4">
                <div className={cn("p-3 rounded-xl border border-white/5", item.bg)}>
                  <item.icon className={cn("w-6 h-6", item.color)} />
                </div>
                <div>
                  <h4 className="text-xs font-medium text-slate-400">{item.title}</h4>
                  <div className={cn("text-xl font-bold mt-1", item.color)}>{item.val}</div>
                  <div className="text-[10px] text-slate-500">{item.sub}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="glass-card p-5 lg:col-span-1 h-[250px] flex flex-col">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-base font-medium text-foreground">Risk Trend</h3>
                <select className="bg-transparent border border-border rounded text-xs text-slate-400 p-1"><option>Last 30 Days</option></select>
              </div>
              <div className="flex-1 -ml-4">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trendData}>
                    <defs>
                      <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="date" tick={{fill: '#64748b', fontSize: 10}} stroke="#334155" />
                    <YAxis tick={{fill: '#64748b', fontSize: 10}} stroke="#334155" domain={[0, 100]} />
                    <RechartsTooltip contentStyle={{backgroundColor: '#111827', borderColor: '#1f2937'}} />
                    <Area type="monotone" dataKey="risk" stroke="#3b82f6" strokeWidth={3} fillOpacity={1} fill="url(#colorRisk)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="glass-card p-5 lg:col-span-1 flex flex-col justify-between">
              <div className="flex items-start space-x-3">
                <div className="p-2 bg-primary/10 text-primary rounded-lg">
                  <Bot className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-medium text-foreground">AI Recommendation</h3>
                  <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                    Your overall business risk is High and trending upward. Focus on resolving critical SQL Injection and Authentication vulnerabilities in payment-gateway and auth-service repositories first.
                  </p>
                </div>
              </div>
              <div className="mt-4">
                 <div className="flex justify-between text-xs mb-1"><span className="text-slate-400">Confidence Score</span><span className="text-primary font-bold">92%</span></div>
                 <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                   <div className="h-full bg-primary w-[92%] shadow-[0_0_8px_rgba(59,130,246,0.5)]"></div>
                 </div>
              </div>
            </div>

            <div className="glass-card p-5 lg:col-span-1 flex flex-col items-center justify-center text-center">
              <ArrowUpCircle className="w-12 h-12 text-red-400 mb-4" />
              <h3 className="text-base font-medium text-foreground">Priority Action</h3>
              <p className="text-xs text-slate-400 mt-2 mb-4">Fix critical vulnerabilities in payment-gateway to reduce the highest business impact.</p>
              <button className="px-4 py-1.5 border border-red-500/30 text-red-400 rounded-md text-sm hover:bg-red-400/10 transition-colors">Priority: Critical</button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}