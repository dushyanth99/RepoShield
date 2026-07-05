import { useState } from "react";
import { Search, TrendingUp, AlertTriangle, Activity, Target } from "lucide-react";
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip as RechartsTooltip } from 'recharts';

export default function PredictiveAnalytics() {
  const isBackendConnected = localStorage.getItem('demoMode') === 'true';

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row justify-between md:items-end gap-4">
        <div>
          <h1 className="text-3xl font-heading font-bold text-foreground">Predictive Analytics</h1>
          <p className="text-slate-400 mt-1">Forecast future risks and vulnerabilities based on ml_engine trends</p>
        </div>
      </div>

      {!isBackendConnected ? (
        <div className="glass-card flex flex-col items-center justify-center p-16 text-center min-h-[400px]">
          <div className="w-20 h-20 bg-navy-800 rounded-full flex items-center justify-center mb-6">
            <TrendingUp className="w-10 h-10 text-slate-500" />
          </div>
          <h3 className="text-xl font-medium text-foreground mb-2">Insufficient Data</h3>
          <p className="text-slate-400 max-w-md mb-6">
            Predictive modeling requires the ml_engine backend to analyze historical CVEFixes data. Connect the backend to generate forecasts.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 glass-card p-6 h-[400px] flex flex-col">
            <h3 className="text-base font-medium text-foreground mb-4">Risk Forecast (Next 30 Days)</h3>
            <div className="flex-1 w-full">
              {/* Chart Placeholder for when backend connects */}
            </div>
          </div>
          <div className="lg:col-span-1 space-y-4">
            <div className="glass-card p-5">
               <h3 className="text-sm font-medium text-slate-400 mb-2">Projected Critical Vulnerabilities</h3>
               <div className="text-3xl font-bold text-red-400 flex items-center">
                 14 <TrendingUp className="w-5 h-5 ml-2 text-red-500" />
               </div>
            </div>
            <div className="glass-card p-5">
               <h3 className="text-sm font-medium text-slate-400 mb-2">Predicted Target Vectors</h3>
               <div className="space-y-3 mt-4 text-sm">
                 <div className="flex justify-between text-slate-300"><span>Authentication</span><span className="text-orange-400">High Risk</span></div>
                 <div className="flex justify-between text-slate-300"><span>API Endpoints</span><span className="text-orange-400">High Risk</span></div>
                 <div className="flex justify-between text-slate-300"><span>Dependencies</span><span className="text-yellow-400">Medium Risk</span></div>
               </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}