import { createContext, useContext, useState, useEffect } from 'react';
import { api } from '@/services/api';

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check localStorage on mount
    const storedToken = localStorage.getItem('access_token');
    const storedUser = localStorage.getItem('user_id');
    
    if (storedToken && storedUser) {
      setToken(storedToken);
      setUser({ id: storedUser });
      api.setAuthToken(storedToken);
    }
    setIsLoading(false);
  }, []);

  const login = async (email, password) => {
    try {
      const data = await api.loginUser(email, password);
      const { access_token, user_id } = data;
      
      localStorage.setItem('access_token', access_token);
      localStorage.setItem('user_id', user_id);
      
      setToken(access_token);
      setUser({ id: user_id, email });
      api.setAuthToken(access_token);
      
      return data;
    } catch (error) {
      throw error;
    }
  };

  const logout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_id');
    setToken(null);
    setUser(null);
    api.setAuthToken(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, isLoading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
