import { createContext, useContext, useState } from 'react';

const GlobalContext = createContext();

export function GlobalProvider({ children }) {
  const [repositories, setRepositories] = useState([
    { id: '1', name: 'payment-gateway', language: 'JavaScript', branch: 'main', status: 'Critical', lastCommit: '2m ago' },
    { id: '2', name: 'auth-service', language: 'Python', branch: 'main', status: 'High', lastCommit: '15m ago' },
  ]);

  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [scanProgressQueue, setScanProgressQueue] = useState([]);
  
  // Method to simulate adding task to reasoning log
  const queueTask = (task) => {
    setScanProgressQueue(prev => [...prev, { ...task, id: Date.now().toString(), status: 'Pending' }]);
  };

  const value = {
    repositories,
    setRepositories,
    vulnerabilities,
    setVulnerabilities,
    isAddModalOpen,
    setIsAddModalOpen,
    scanProgressQueue,
    queueTask,
  };

  return (
    <GlobalContext.Provider value={value}>
      {children}
    </GlobalContext.Provider>
  );
}

export function useGlobalContext() {
  const context = useContext(GlobalContext);
  if (!context) {
    throw new Error('useGlobalContext must be used within a GlobalProvider');
  }
  return context;
}
