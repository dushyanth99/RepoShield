import { useState } from "react";
import { X, GitPullRequest, Link, Key, Check } from "lucide-react";

import { useQueryClient } from '@tanstack/react-query';
import { api } from '@/services/api';

import { useAuth } from '@/context/AuthContext';

export default function AddRepositoryModal({ isOpen, onClose }) {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const [step, setStep] = useState(1);
  const [connectionMethod, setConnectionMethod] = useState('github');
  const [repoUrl, setRepoUrl] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    
    try {
      const parts = repoUrl.split('/');
      const repoName = parts[parts.length - 1] || 'new-repo';
      const payload = {
        user_id: user?.id || "unknown",
        repo_name: repoName.replace('.git', ''),
        installation_id: 123456
      };
      await api.linkRepository(payload);
      queryClient.invalidateQueries({ queryKey: ['repositories'] });
      setIsSubmitting(false);
      setIsSuccess(true);
      setTimeout(() => {
        onClose();
        setIsSuccess(false);
        setStep(1);
        setRepoUrl("");
      }, 1500);
    } catch (error) {
      console.error(error);
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-navy-900 border border-border w-full max-w-lg rounded-xl shadow-2xl overflow-hidden animate-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-white/5">
          <h2 className="text-lg font-heading font-bold text-foreground flex items-center">
            <GitPullRequest className="w-5 h-5 mr-2" />
            Add Repository
          </h2>
          <button 
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-white/10 rounded-md transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6">
          {isSuccess ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <div className="w-16 h-16 bg-green-500/20 text-green-500 rounded-full flex items-center justify-center mb-4">
                <Check className="w-8 h-8" />
              </div>
              <h3 className="text-xl font-bold text-white mb-2">Repository Added!</h3>
              <p className="text-slate-400">The ml_engine is now initiating a live scan.</p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-6">
              
              {/* Connection Type */}
              <div className="space-y-3">
                <label className="text-sm font-medium text-slate-300">Connection Method</label>
                <div className="grid grid-cols-2 gap-3">
                  <button 
                    type="button" 
                    onClick={() => setConnectionMethod('github')}
                    className={`flex items-center justify-center space-x-2 p-3 rounded-lg transition-colors ${connectionMethod === 'github' ? 'border-2 border-primary bg-primary/10 text-white' : 'border border-border bg-white/5 text-slate-400 hover:text-white'}`}
                  >
                    <GitPullRequest className="w-4 h-4" />
                    <span className="text-sm font-medium">GitHub App</span>
                  </button>
                  <button 
                    type="button" 
                    onClick={() => setConnectionMethod('https')}
                    className={`flex items-center justify-center space-x-2 p-3 rounded-lg transition-colors ${connectionMethod === 'https' ? 'border-2 border-primary bg-primary/10 text-white' : 'border border-border bg-white/5 text-slate-400 hover:text-white'}`}
                  >
                    <Link className="w-4 h-4" />
                    <span className="text-sm font-medium">HTTPS / SSH URL</span>
                  </button>
                </div>
              </div>

              {/* URL Input */}
              <div className="space-y-2">
                <label className="text-sm font-medium text-slate-300">Repository URL</label>
                <div className="relative">
                  <Link className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input 
                    type="text" 
                    required
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/organization/repo"
                    className="w-full bg-navy-950 border border-border rounded-lg py-2.5 pl-9 pr-4 text-sm text-foreground focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50 transition-all placeholder:text-slate-600"
                  />
                </div>
              </div>

              {/* Auth / Tokens */}
              <div className="space-y-2">
                <label className="text-sm font-medium text-slate-300 flex justify-between">
                  <span>Personal Access Token</span>
                  <span className="text-xs text-slate-500 font-normal">Optional for public repos</span>
                </label>
                <div className="relative">
                  <Key className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input 
                    type="password" 
                    placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                    className="w-full bg-navy-950 border border-border rounded-lg py-2.5 pl-9 pr-4 text-sm text-foreground focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50 transition-all placeholder:text-slate-600"
                  />
                </div>
              </div>

              {/* Footer Actions */}
              <div className="flex justify-end space-x-3 pt-4 border-t border-border">
                <button 
                  type="button" 
                  onClick={onClose}
                  className="px-4 py-2 rounded-lg text-sm font-medium text-slate-300 hover:text-white hover:bg-white/5 transition-colors"
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  disabled={isSubmitting || !repoUrl}
                  className="flex items-center justify-center space-x-2 px-6 py-2 rounded-lg text-sm font-medium bg-primary hover:bg-primary-dark text-white disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-[0_0_15px_rgba(59,130,246,0.3)]"
                >
                  {isSubmitting ? (
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  ) : (
                    <span>Add to RepoShield</span>
                  )}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
