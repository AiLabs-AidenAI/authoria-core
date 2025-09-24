import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AuthProvider } from "@/contexts/AuthContext";
import Index from "./pages/Index";
import NotFound from "./pages/NotFound";
import Login from "./pages/auth/Login";
import Signup from "./pages/auth/Signup";
import SignupSuccess from "./pages/auth/SignupSuccess";
import PendingApproval from "./pages/auth/PendingApproval";
import Documentation from "./pages/Documentation";
import IntegrationGuide from "./pages/IntegrationGuide";
import AuthConfig from "@/pages/admin/AuthConfig";
import PendingRequests from "@/pages/admin/PendingRequests";
import Users from "@/pages/admin/Users";
import AuditLog from "@/pages/admin/AuditLog";
import TenantsManagement from "@/pages/admin/TenantsManagement";
import ProtectedRoute from "./components/ProtectedRoute";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <AuthProvider>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="/login" element={<Login />} />
            <Route path="/auth/login" element={<Login />} />
            <Route path="/signup" element={<Signup />} />
            <Route path="/auth/signup" element={<Signup />} />
            <Route path="/auth/signup-success" element={<SignupSuccess />} />
            <Route path="/auth/pending-approval" element={<PendingApproval />} />
            <Route path="/documentation" element={
              <ProtectedRoute>
                <Documentation />
              </ProtectedRoute>
            } />
            <Route path="/integration-guide" element={
              <ProtectedRoute>
                <IntegrationGuide />
              </ProtectedRoute>
            } />
            <Route path="/admin/auth-config" element={
              <ProtectedRoute requireAdmin>
                <AuthConfig />
              </ProtectedRoute>
            } />
            <Route path="/admin/pending-requests" element={
              <ProtectedRoute requireAdmin>
                <PendingRequests />
              </ProtectedRoute>
            } />
            <Route path="/admin/users" element={
              <ProtectedRoute requireAdmin>
                <Users />
              </ProtectedRoute>
            } />
            <Route path="/admin/audit-log" element={
              <ProtectedRoute requireAdmin>
                <AuditLog />
              </ProtectedRoute>
            } />
            <Route path="/admin/tenants" element={
              <ProtectedRoute requireAdmin>
                <TenantsManagement />
              </ProtectedRoute>
            } />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </AuthProvider>
  </QueryClientProvider>
);

export default App;
