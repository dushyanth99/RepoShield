import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { Info } from 'lucide-react';

const defaultData = [
  { name: 'Low', value: 25, color: '#22c55e' },
  { name: 'Medium', value: 25, color: '#eab308' },
  { name: 'High', value: 25, color: '#f97316' },
  { name: 'Critical', value: 25, color: '#ef4444' },
];

const offlineData = [
  { name: 'N/A', value: 100, color: '#1e293b' }
];

export default function RiskOverviewGauge({ isOffline }) {
  const data = isOffline ? offlineData : defaultData;

  return (
    <div className="glass-card p-5 h-[300px] flex flex-col relative">
      <div className="flex justify-between items-start mb-2">
        <h3 className="text-lg font-heading font-medium">Risk Overview</h3>
        <Info className="w-4 h-4 text-slate-400 cursor-pointer" />
      </div>
      
      <div className="flex-1 relative mt-4">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="70%"
              startAngle={180}
              endAngle={0}
              innerRadius={70}
              outerRadius={100}
              paddingAngle={isOffline ? 0 : 1}
              dataKey="value"
              stroke="none"
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        
        {/* Gauge Needle / Score Display */}
        <div className="absolute top-[65%] left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center">
          <span className="text-4xl font-bold text-foreground">{isOffline ? "0" : "72"}</span>
          <span className="text-sm text-slate-400">/ 100</span>
          <span className={`text-sm font-medium mt-1 ${isOffline ? 'text-slate-500' : 'text-orange-400'}`}>
            {isOffline ? 'N/A' : 'Medium Risk'}
          </span>
        </div>
      </div>
      
      <div className="text-center text-xs text-slate-400 mt-4">
        {isOffline ? "Awaiting first scan to calculate risk." : "Keep going! Fix critical issues to improve score."}
      </div>
    </div>
  );
}
