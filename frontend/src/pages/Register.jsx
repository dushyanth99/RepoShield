import { useState } from "react";
import { Shield, Key, Mail, User as UserIcon, ArrowRight, CheckCircle, Eye, EyeOff } from "lucide-react";
import { api } from "@/services/api";
import { useNavigate, Link } from "react-router-dom";

export default function Register() {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isSuccess, setIsSuccess] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);
    
    try {
      await api.registerUser({
        full_name: fullName,
        email,
        password
      });
      setIsSuccess(true);
      setTimeout(() => navigate("/login"), 3000);
    } catch (err) {
      setError(err.message || "Failed to register. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  if (isSuccess) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-navy-950 p-4">
        <div className="glass-card p-12 flex flex-col items-center text-center max-w-md">
          <div className="w-16 h-16 bg-green-500/20 text-green-500 rounded-full flex items-center justify-center mb-6">
            <CheckCircle className="w-8 h-8" />
          </div>
          <h2 className="text-2xl font-bold text-white mb-2">Registration Successful</h2>
          <p className="text-slate-400">Your account has been created. Redirecting you to login...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-navy-950 p-4">
      <div className="w-full max-w-md">
        <div className="flex justify-center mb-8">
          <div className="flex items-center space-x-2">
            <div className="p-2 bg-primary/20 rounded-lg">
              <Shield className="w-8 h-8 text-primary" />
            </div>
            <span className="text-3xl font-heading font-bold text-white tracking-tight">RepoShield</span>
          </div>
        </div>

        <div className="glass-card p-8">
          <h2 className="text-2xl font-bold text-white mb-2">Create Account</h2>
          <p className="text-slate-400 text-sm mb-6">Sign up to analyze your repositories using the CVEFixes ml_engine.</p>

          {error && (
            <div className="bg-red-500/10 border border-red-500/50 text-red-400 text-sm p-3 rounded-lg mb-6">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-300">Full Name</label>
              <div className="relative">
                <UserIcon className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  className="w-full bg-navy-900 border border-border rounded-lg py-2.5 pl-9 pr-4 text-sm text-foreground focus:outline-none focus:border-primary/50 transition-all placeholder:text-slate-600"
                  placeholder="Alice Nguyen"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-300">Email Address</label>
              <div className="relative">
                <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-navy-900 border border-border rounded-lg py-2.5 pl-9 pr-4 text-sm text-foreground focus:outline-none focus:border-primary/50 transition-all placeholder:text-slate-600"
                  placeholder="alice@example.com"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-300">Password</label>
              <div className="relative">
                <Key className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type={showPassword ? "text" : "password"}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-navy-900 border border-border rounded-lg py-2.5 pl-9 pr-10 text-sm text-foreground focus:outline-none focus:border-primary/50 transition-all placeholder:text-slate-600"
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  onMouseDown={() => setShowPassword(true)}
                  onMouseUp={() => setShowPassword(false)}
                  onMouseLeave={() => setShowPassword(false)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <p className="text-[10px] text-slate-500">Min 8 chars, 1 uppercase, 1 number, 1 special char.</p>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full flex items-center justify-center space-x-2 bg-primary hover:bg-primary-dark text-white py-2.5 rounded-lg font-medium transition-all shadow-[0_0_15px_rgba(59,130,246,0.3)] mt-6 disabled:opacity-50"
            >
              {isLoading ? (
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <>
                  <span>Create Account</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          <div className="mt-6 text-center text-sm text-slate-400">
            Already have an account?{" "}
            <Link to="/login" className="text-primary hover:text-primary-dark transition-colors font-medium">
              Sign In
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
