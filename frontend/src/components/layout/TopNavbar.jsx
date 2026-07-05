import { useState, useRef, useEffect } from "react";
import { Search, Bell, GitPullRequest, Sun, Moon, LogOut, User as UserIcon, Settings as SettingsIcon } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { useNavigate } from "react-router-dom";

export default function TopNavbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);
  const [isDarkMode, setIsDarkMode] = useState(true);

  const profileRef = useRef();
  const notificationsRef = useRef();

  // Handle click outside to close dropdowns
  useEffect(() => {
    function handleClickOutside(event) {
      if (profileRef.current && !profileRef.current.contains(event.target)) {
        setIsProfileOpen(false);
      }
      if (notificationsRef.current && !notificationsRef.current.contains(event.target)) {
        setIsNotificationsOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const handleThemeToggle = () => {
    setIsDarkMode(!isDarkMode);
    if (isDarkMode) {
      document.body.classList.add('light-theme');
    } else {
      document.body.classList.remove('light-theme');
    }
  };

  const userInitial = user?.email ? user.email.charAt(0).toUpperCase() : "U";

  const [notifications, setNotifications] = useState([
    {
      id: 1,
      title: "New Vulnerability Detected",
      message: "Critical SQL Injection found in payment-gateway.",
      time: "2 mins ago"
    },
    {
      id: 2,
      title: "Scan Completed",
      message: "auth-service scan finished. 0 issues found.",
      time: "1 hour ago"
    }
  ]);

  const handleMarkAllRead = () => {
    setNotifications([]);
  };

  const hasUnread = notifications.length > 0;

  return (
    <header className="h-16 border-b border-border bg-navy-900/80 backdrop-blur-md flex items-center justify-between px-6 sticky top-0 z-10">
      {/* Search Bar */}
      <div className="flex-1 max-w-xl relative">
        <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
        <input
          type="text"
          placeholder="Search anything..."
          className="w-full bg-white/5 border border-border rounded-full py-1.5 pl-10 pr-4 text-sm text-foreground focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50 transition-all placeholder:text-slate-500"
        />
      </div>

      {/* Action Utilities */}
      <div className="flex items-center space-x-4">
        {/* Notifications */}
        <div className="relative" ref={notificationsRef}>
          <button 
            onClick={() => {
              setIsNotificationsOpen(!isNotificationsOpen);
              setIsProfileOpen(false);
            }}
            className="relative p-2 text-slate-400 hover:text-slate-200 transition-colors rounded-full hover:bg-white/5"
          >
            <Bell className="w-5 h-5" />
            {hasUnread && (
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full border border-navy-900"></span>
            )}
          </button>

          {isNotificationsOpen && (
            <div className="absolute right-0 mt-2 w-80 bg-navy-950 border border-border rounded-lg shadow-xl overflow-hidden py-2 z-50">
              <div className="px-4 py-2 border-b border-border">
                <h3 className="font-medium text-foreground">Notifications</h3>
              </div>
              <div className="max-h-64 overflow-y-auto">
                {hasUnread ? (
                  notifications.map((notif) => (
                    <div key={notif.id} className="px-4 py-3 hover:bg-white/5 transition-colors cursor-pointer border-b border-border">
                      <div className="text-sm font-medium text-slate-200">{notif.title}</div>
                      <div className="text-xs text-slate-400 mt-1">{notif.message}</div>
                      <div className="text-[10px] text-slate-500 mt-1">{notif.time}</div>
                    </div>
                  ))
                ) : (
                  <div className="px-4 py-6 text-center text-slate-500 text-sm">
                    No new notifications.
                  </div>
                )}
              </div>
              {hasUnread && (
                <div className="px-4 py-2 text-center border-t border-border">
                  <button 
                    onClick={handleMarkAllRead}
                    className="text-xs text-primary hover:text-primary-dark transition-colors font-medium"
                  >
                    Mark all as read
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
        
        {/* GitHub Integration / Repositories shortcut */}
        <button 
          onClick={() => navigate("/repository")}
          className="p-2 text-slate-400 hover:text-slate-200 transition-colors rounded-full hover:bg-white/5"
          title="Repositories"
        >
          <GitPullRequest className="w-5 h-5" />
        </button>

        {/* Demo Mode Toggle */}
        <button
          onClick={() => {
            const current = localStorage.getItem('demoMode') === 'true';
            localStorage.setItem('demoMode', (!current).toString());
            window.location.reload();
          }}
          className={`px-3 py-1.5 text-xs font-bold rounded-md border transition-all ${
            localStorage.getItem('demoMode') === 'true'
              ? 'bg-primary/20 text-primary border-primary/50'
              : 'bg-white/5 text-slate-400 border-border hover:bg-white/10 hover:text-white'
          }`}
          title="Toggle Hackathon Demo Mode"
        >
          {localStorage.getItem('demoMode') === 'true' ? 'DEMO ON' : 'DEMO OFF'}
        </button>

        {/* Theme Toggle */}
        <button 
          onClick={handleThemeToggle}
          className="p-2 text-slate-400 hover:text-slate-200 transition-colors rounded-full hover:bg-white/5"
          title={isDarkMode ? "Switch to Light Mode" : "Switch to Dark Mode"}
        >
          {isDarkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
        </button>

        {/* User Profile Dropdown */}
        <div className="relative ml-2" ref={profileRef}>
          <button 
            onClick={() => {
              setIsProfileOpen(!isProfileOpen);
              setIsNotificationsOpen(false);
            }}
            className="w-8 h-8 rounded-full bg-primary/20 text-primary border border-primary/30 flex items-center justify-center text-sm font-bold hover:bg-primary/30 transition-colors"
          >
            {userInitial}
          </button>

          {isProfileOpen && (
            <div className="absolute right-0 mt-2 w-56 bg-navy-950 border border-border rounded-lg shadow-xl overflow-hidden py-1 z-50">
              <div className="px-4 py-3 border-b border-border">
                <p className="text-sm font-medium text-foreground truncate">{user?.email || "User"}</p>
                <p className="text-xs text-slate-500 truncate">Administrator</p>
              </div>
              <div className="py-1">
                <button 
                  onClick={() => {
                    setIsProfileOpen(false);
                    navigate("/settings");
                  }}
                  className="w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-white/5 hover:text-white transition-colors flex items-center"
                >
                  <SettingsIcon className="w-4 h-4 mr-2" />
                  Account Settings
                </button>
              </div>
              <div className="border-t border-border py-1">
                <button 
                  onClick={handleLogout}
                  className="w-full text-left px-4 py-2 text-sm text-red-400 hover:bg-red-400/10 transition-colors flex items-center"
                >
                  <LogOut className="w-4 h-4 mr-2" />
                  Sign Out
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
