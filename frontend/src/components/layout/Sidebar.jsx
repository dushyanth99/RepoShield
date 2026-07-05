import { NavLink } from "react-router-dom";
import { 
  LayoutDashboard, 
  FolderGit2, 
  Activity, 
  ShieldAlert, 
  Bot, 
  Briefcase, 
  ShieldCheck, 
  LineChart, 
  FileText, 
  Settings,
  LogOut
} from "lucide-react";
import { cn } from "@/utils/cn";

const navItems = [
  { name: "Dashboard", path: "/", icon: LayoutDashboard },
  { name: "Repository", path: "/repository", icon: FolderGit2 },
  { name: "Live Scan", path: "/live-scan", icon: Activity },
  { name: "Vulnerabilities", path: "/vulnerabilities", icon: ShieldAlert },
  { name: "AI Agent", path: "/ai-agent", icon: Bot },
  { name: "Business Risk", path: "/business-risk", icon: Briefcase },
  { name: "Compliance", path: "/compliance", icon: ShieldCheck },
  { name: "Predictive Analytics", path: "/predictive-analytics", icon: LineChart },
  { name: "Reports", path: "/reports", icon: FileText },
  { name: "Settings", path: "/settings", icon: Settings },
];

import { useAuth } from "@/context/AuthContext";
import { useNavigate } from "react-router-dom";

export default function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <aside className="w-64 h-screen bg-navy-900 border-r border-border flex flex-col fixed left-0 top-0">
      {/* Logo */}
      <div className="h-16 flex items-center px-6 border-b border-border">
        <ShieldCheck className="w-6 h-6 text-primary mr-2" />
        <span className="font-heading font-bold text-xl text-foreground">RepoShield</span>
      </div>

      {/* Nav Items */}
      <div className="flex-1 overflow-y-auto py-6 px-3">
        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.name}
                to={item.path}
                className={({ isActive }) =>
                  cn(
                    "flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200",
                    isActive
                      ? "bg-primary/10 text-primary border border-primary/20 shadow-[0_0_15px_rgba(59,130,246,0.15)]"
                      : "text-slate-400 hover:bg-white/5 hover:text-slate-200"
                  )
                }
              >
                <Icon className="w-5 h-5 mr-3" />
                {item.name}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* User Profile */}
      <div className="p-4 border-t border-border mt-auto">
        <div className="flex items-center justify-between glass-card p-3">
          <div className="flex items-center">
            <div className="w-8 h-8 rounded-full bg-primary/20 text-primary flex items-center justify-center font-bold text-sm border border-primary/30">
              {user?.email ? user.email.charAt(0).toUpperCase() : "U"}
            </div>
            <span className="ml-3 font-medium text-sm truncate w-24" title={user?.email || "User"}>
              {user?.email || "User"}
            </span>
          </div>
          <button 
            onClick={handleLogout}
            className="text-slate-400 hover:text-red-400 transition-colors" 
            title="Sign Out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  );
}
