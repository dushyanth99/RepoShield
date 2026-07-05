import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import AppLayout from "@/components/layout/AppLayout";
import { AuthProvider, useAuth } from "@/context/AuthContext";

// Import Pages
import Dashboard from "@/pages/Dashboard";
import Repository from "@/pages/Repository";
import LiveScan from "@/pages/LiveScan";
import Vulnerabilities from "@/pages/Vulnerabilities";
import AIAgent from "@/pages/AIAgent";
import BusinessRisk from "@/pages/BusinessRisk";
import Compliance from "@/pages/Compliance";
import PredictiveAnalytics from "@/pages/PredictiveAnalytics";
import Reports from "@/pages/Reports";
import Settings from "@/pages/Settings";
import Login from "@/pages/Login";
import Register from "@/pages/Register";

// Protected Route Wrapper
const ProtectedRoute = ({ children }) => {
  const { token, isLoading } = useAuth();
  
  if (isLoading) {
    return <div className="min-h-screen bg-navy-950 flex items-center justify-center">Loading...</div>;
  }
  
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  
  return children;
};

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          
          {/* Protected Routes */}
          <Route path="/" element={<ProtectedRoute><AppLayout /></ProtectedRoute>}>
            <Route index element={<Dashboard />} />
            <Route path="repository" element={<Repository />} />
            <Route path="live-scan" element={<LiveScan />} />
            <Route path="vulnerabilities" element={<Vulnerabilities />} />
            <Route path="ai-agent" element={<AIAgent />} />
            <Route path="business-risk" element={<BusinessRisk />} />
            <Route path="compliance" element={<Compliance />} />
            <Route path="predictive-analytics" element={<PredictiveAnalytics />} />
            <Route path="reports" element={<Reports />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
