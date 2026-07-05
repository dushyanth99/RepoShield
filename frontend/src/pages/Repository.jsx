import { useState } from "react";
import { Search, Plus, Filter, MoreHorizontal, GitMerge, GitBranch, GitPullRequest, FileCode, Users, Database } from "lucide-react";
import { cn } from "@/utils/cn";
import { useRepositories } from "@/hooks/useApi";
import AddRepositoryModal from "@/components/repository/AddRepositoryModal";

export default function Repository() {
  const [activeTab, setActiveTab] = useState("All Repositories");
  const [isModalOpen, setIsModalOpen] = useState(false);
  
  // Use React Query to fetch repositories.
  const { data: repos, isLoading, isError } = useRepositories();
  
  const tabs = ["All Repositories", "Favorites", "Private", "Archived"];

  return (
    <div className="space-y-6">
      {/* Header & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-heading font-bold text-foreground">Repositories</h1>
          <p className="text-slate-400 mt-1">Manage and monitor your connected codebases</p>
        </div>
        <button 
          onClick={() => setIsModalOpen(true)}
          className="flex items-center space-x-2 bg-primary hover:bg-primary-dark text-white px-4 py-2 rounded-lg font-medium transition-colors shadow-[0_0_15px_rgba(59,130,246,0.3)]"
        >
          <Plus className="w-4 h-4" />
          <span>Add Repository</span>
        </button>
      </div>

      {/* Filter Tabs & Search */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div className="flex space-x-1 border-b border-border w-full md:w-auto">
          {tabs.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={cn(
                "px-4 py-2 font-medium text-sm transition-colors border-b-2",
                activeTab === tab
                  ? "border-primary text-primary"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              )}
            >
              {tab}
            </button>
          ))}
        </div>
        
        <div className="flex items-center space-x-3 w-full md:w-auto">
          <div className="relative w-full md:w-64">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search repositories..."
              className="w-full bg-white/5 border border-border rounded-lg py-1.5 pl-9 pr-4 text-sm text-foreground focus:outline-none focus:border-primary/50 transition-colors"
            />
          </div>
          <button className="p-2 border border-border bg-white/5 rounded-lg text-slate-400 hover:text-slate-200 transition-colors">
            <Filter className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Data Table */}
      <div className="glass-card overflow-hidden min-h-[400px] flex flex-col">
        {isLoading ? (
          <div className="flex-1 flex flex-col items-center justify-center p-12 text-slate-400 space-y-4">
            <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
            <p>Loading repositories...</p>
          </div>
        ) : isError || !repos || repos.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center p-12 text-center">
            <div className="w-16 h-16 bg-navy-800 rounded-full flex items-center justify-center mb-4">
              <Database className="w-8 h-8 text-slate-500" />
            </div>
            <h3 className="text-lg font-medium text-foreground mb-2">No Repositories Found</h3>
            <p className="text-sm text-slate-400 max-w-sm mb-6">
              Connect your backend and ml_engine to load the CVEFixes dataset results, or manually add a repository to begin a live scan.
            </p>
            <button 
              onClick={() => setIsModalOpen(true)}
              className="flex items-center space-x-2 bg-white/5 hover:bg-white/10 text-white px-4 py-2 rounded-lg font-medium transition-colors border border-border"
            >
              <Plus className="w-4 h-4" />
              <span>Add Repository</span>
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-border bg-white/5 text-sm font-medium text-slate-400">
                  <th className="py-3 px-4 font-medium">Repository</th>
                  <th className="py-3 px-4 font-medium">Branch</th>
                  <th className="py-3 px-4 font-medium">Last Commit</th>
                  <th className="py-3 px-4 font-medium">Stats</th>
                  <th className="py-3 px-4 font-medium">Status</th>
                  <th className="py-3 px-4 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {repos.map((repo) => (
                  <tr key={repo.id} className="hover:bg-white/5 transition-colors group">
                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-3">
                        <div className="p-2 bg-white/5 rounded-lg">
                          <GitMerge className="w-5 h-5 text-slate-300" />
                        </div>
                        <div>
                          <div className="font-medium text-slate-200 group-hover:text-primary transition-colors cursor-pointer">
                            {repo.name}
                          </div>
                          <div className="flex items-center mt-1">
                            <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-medium", repo.langColor)}>
                              {repo.language}
                            </span>
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center text-sm text-slate-300">
                        <GitBranch className="w-4 h-4 mr-1.5 text-slate-500" />
                        {repo.branch}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="text-sm text-slate-300">{repo.commitTime}</div>
                      <div className="text-xs text-slate-500 truncate max-w-[200px]">{repo.commitMsg}</div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-3 text-xs text-slate-400">
                        <div className="flex items-center" title="Pull Requests">
                          <GitPullRequest className="w-3.5 h-3.5 mr-1" />
                          {repo.prs}
                        </div>
                        <div className="flex items-center" title="Files">
                          <FileCode className="w-3.5 h-3.5 mr-1" />
                          {repo.files}
                        </div>
                        <div className="flex items-center" title="Contributors">
                          <Users className="w-3.5 h-3.5 mr-1" />
                          3
                        </div>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span className={cn("px-2.5 py-1 rounded-full text-xs font-medium", repo.statusColor)}>
                        {repo.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-white/10 rounded-md transition-colors">
                        <MoreHorizontal className="w-5 h-5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      
      <AddRepositoryModal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} />
    </div>
  );
}