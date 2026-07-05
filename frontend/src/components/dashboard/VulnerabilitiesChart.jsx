import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const defaultData = [
  { name: 'Critical', value: 18, color: '#ef4444' }, // red
  { name: 'High', value: 30, color: '#f97316' },     // orange
  { name: 'Medium', value: 34, color: '#eab308' },   // yellow
  { name: 'Low', value: 18, color: '#22c55e' },      // green
];

const offlineData = [
  { name: 'N/A', value: 1, color: '#1e293b' }
];

export default function VulnerabilitiesChart({ isOffline }) {
  const data = isOffline ? offlineData : defaultData;

  return (
    <div className="glass-card p-5 h-[300px] flex flex-col">
      <h3 className="text-lg font-heading font-medium mb-4">Vulnerabilities by Severity</h3>
      <div className="flex-1 flex items-center justify-between">
        <div className="h-full w-1/2 relative">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={80}
                paddingAngle={isOffline ? 0 : 2}
                dataKey="value"
                stroke="none"
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              {!isOffline && (
                <Tooltip 
                  contentStyle={{ backgroundColor: '#111827', borderColor: '#1f2937', color: '#f8fafc' }}
                  itemStyle={{ color: '#f8fafc' }}
                />
              )}
            </PieChart>
          </ResponsiveContainer>
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-2xl font-bold">{isOffline ? "0" : "156"}</span>
            <span className="text-xs text-slate-400">Total</span>
          </div>
        </div>
        
        {/* Legend */}
        <div className="w-1/2 flex flex-col justify-center space-y-3 pl-4">
          {defaultData.map((item, i) => (
            <div key={i} className="flex items-center justify-between text-sm">
              <div className="flex items-center">
                <span className={`w-3 h-3 rounded-full mr-2 ${isOffline ? 'bg-slate-700' : ''}`} style={{ backgroundColor: isOffline ? '' : item.color }}></span>
                <span className={isOffline ? "text-slate-500" : "text-slate-300"}>{item.name}</span>
              </div>
              <span className={`font-medium ${isOffline ? "text-slate-600" : "text-slate-400"}`}>
                {isOffline ? "0%" : `${item.value}%`}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
