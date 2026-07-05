const API_BASE_URL = 'https://unmendable-lala-complexly.ngrok-free.dev';

let authToken = null;

// Utility to handle fetch requests
async function fetchApi(endpoint, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    'ngrok-skip-browser-warning': 'true',
    ...options.headers,
  };

  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `API error: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error(`Failed fetching ${endpoint}:`, error);
    throw error;
  }
}

let mockRepos = [
  { id: 1, name: 'payment-gateway', language: 'TypeScript', langColor: 'bg-blue-500/20 text-blue-400', branch: 'main', commitTime: '2 hours ago', commitMsg: 'Update payment processor SDK', prs: 3, files: 142, status: 'Active', statusColor: 'bg-green-500/20 text-green-400' },
  { id: 2, name: 'auth-service', language: 'Go', langColor: 'bg-cyan-500/20 text-cyan-400', branch: 'main', commitTime: '5 hours ago', commitMsg: 'Fix JWT token expiry issue', prs: 1, files: 86, status: 'Active', statusColor: 'bg-green-500/20 text-green-400' },
  { id: 3, name: 'user-service', language: 'Python', langColor: 'bg-yellow-500/20 text-yellow-400', branch: 'develop', commitTime: '1 day ago', commitMsg: 'Add user profile endpoints', prs: 5, files: 215, status: 'Archived', statusColor: 'bg-slate-500/20 text-slate-400' }
];

export const api = {
  setAuthToken: (token) => {
    authToken = token;
  },

  // Auth
  registerUser: (userData) => fetchApi('/auth/register', { method: 'POST', body: JSON.stringify(userData) }),
  loginUser: (email, password) => fetchApi('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),

  // Repositories & Scans
  getRepositories: () => {
    if (localStorage.getItem('demoMode') === 'true') {
      return Promise.resolve([...mockRepos]);
    }
    return fetchApi('/repositories');
  },
  
  linkRepository: (payload) => {
    if (localStorage.getItem('demoMode') === 'true') {
      const name = payload.repo_name || 'new-repo';
      mockRepos.unshift({
        id: mockRepos.length + 1,
        name: name,
        language: 'JavaScript',
        langColor: 'bg-yellow-500/20 text-yellow-400',
        branch: 'main',
        commitTime: 'just now',
        commitMsg: 'Linked via App',
        prs: 0,
        files: 0,
        status: 'Active',
        statusColor: 'bg-green-500/20 text-green-400'
      });
      return Promise.resolve({ success: true });
    }
    return fetchApi('/api/v1/repositories/', { method: 'POST', body: JSON.stringify(payload) });
  },
  
  getVulnerabilities: () => {
    if (localStorage.getItem('demoMode') === 'true') {
      return Promise.resolve([
        { id: 1, type: 'SQL Injection', desc: 'Improper neutralization of special elements in query.', repo: 'payment-gateway', branch: 'main', file: 'src/db/queries.ts', line: 142, severity: 'Critical', status: 'Open', detected: '2 hours ago', color: 'bg-red-500/20 text-red-400' },
        { id: 2, type: 'Cross-Site Scripting (XSS)', desc: 'Stored XSS in user profile biography field.', repo: 'user-service', branch: 'develop', file: 'api/controllers/user.py', line: 89, severity: 'High', status: 'In Progress', detected: '1 day ago', color: 'bg-orange-500/20 text-orange-400' },
        { id: 3, type: 'Hardcoded Secret', desc: 'AWS API Key found in environment config file.', repo: 'auth-service', branch: 'main', file: 'config/aws.go', line: 12, severity: 'Critical', status: 'Resolved', detected: '3 days ago', color: 'bg-red-500/20 text-red-400' },
        { id: 4, type: 'Insecure Direct Object Reference', desc: 'Missing authorization check on invoice endpoint.', repo: 'payment-gateway', branch: 'main', file: 'src/api/invoices.ts', line: 256, severity: 'Medium', status: 'Open', detected: '4 hours ago', color: 'bg-yellow-500/20 text-yellow-400' }
      ]);
    }
    return fetchApi('/vulnerabilities');
  },
  
  getDashboardMetrics: () => {
    if (localStorage.getItem('demoMode') === 'true') {
      return Promise.resolve({ success: true, dummy: true });
    }
    return fetchApi('/dashboard/metrics');
  },
  
  getBusinessRisk: () => {
    if (localStorage.getItem('demoMode') === 'true') {
      return Promise.resolve({ success: true, dummy: true });
    }
    return fetchApi('/business-risk');
  },
  
  getComplianceStatus: () => {
    if (localStorage.getItem('demoMode') === 'true') {
      return Promise.resolve({ success: true, dummy: true });
    }
    return fetchApi('/compliance');
  },

  // Jobs & Agent Polling
  triggerManualScan: (repositoryId) => {
    if (localStorage.getItem('demoMode') === 'true') {
      return Promise.resolve({ job_id: 'demo-job-123', status: 'PENDING', file_path: 'app/main.py', category: 'Security', business_risk_score: 95, message: 'Scan accepted' });
    }
    return fetchApi('/api/v1/jobs/scan/manual', { method: 'POST', body: JSON.stringify({ repository_id: repositoryId }) });
  },
  
  pollJobStatus: (jobId) => {
    if (localStorage.getItem('demoMode') === 'true') {
      return Promise.resolve({ job_id: jobId, status: 'VERIFIED', progress: 100 });
    }
    return fetchApi(`/api/v1/jobs/${jobId}`);
  },
};
