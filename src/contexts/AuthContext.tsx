/**
 * Authentication context and provider
 */

import React, { createContext, useContext, useState, useEffect } from 'react';
import { User, AuthContextType, AuthResult, SignupRequest, MessageResponse } from '@/types/auth';
import { authAPI } from '@/lib/api-client';
import { toast } from '@/hooks/use-toast';

const AuthContext = createContext<AuthContextType | null>(null);

interface AuthProviderProps {
  children: React.ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Initialize auth state
  useEffect(() => {
    initializeAuth();
  }, []);

  // Helpers: decode JWT and build user from claims or introspection
  const decodeJwtPayload = (token: string): any | null => {
    try {
      const payload = token.split('.')[1];
      if (!payload) return null;
      const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
      const json = decodeURIComponent(
        atob(base64)
          .split('')
          .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      );
      return JSON.parse(json);
    } catch {
      return null;
    }
  };

  const buildUserFromClaims = (claims: any, fallback: Partial<User> = {}): User => {
    const isAdmin = !!(
      claims?.is_admin ||
      claims?.admin ||
      claims?.role === 'admin' ||
      (Array.isArray(claims?.roles) && claims.roles.includes('admin'))
    );
    return {
      id: String(claims?.sub || fallback.id || ''),
      email: String(claims?.email || fallback.email || ''),
      displayName: (fallback.displayName as string) || claims?.name || '',
      role: isAdmin ? 'admin' : 'user',
      isActive: true,
      isApproved: true,
      isAdmin,
      tenantId: (claims?.tenant_id as string) || fallback.tenantId,
      createdAt: new Date().toISOString(),
    };
  };

  const fetchUserFromToken = async (token: string, fallbackEmail?: string): Promise<User> => {
    try {
      const info = await authAPI.introspectToken(token);
      const isAdmin = !!(
        info?.is_admin ||
        info?.admin ||
        info?.role === 'admin' ||
        (Array.isArray(info?.roles) && info.roles.includes('admin'))
      );
      return {
        id: String(info?.sub || info?.user_id || ''),
        email: String(info?.email || fallbackEmail || ''),
        displayName: info?.name || '',
        role: isAdmin ? 'admin' : 'user',
        isActive: true,
        isApproved: true,
        isAdmin,
        tenantId: info?.tenant_id,
        createdAt: new Date().toISOString(),
      };
    } catch {
      const claims = decodeJwtPayload(token);
      return buildUserFromClaims(claims, { email: fallbackEmail });
    }
  };

  const initializeAuth = async () => {
    try {
      const storedToken = localStorage.getItem('access_token');
      const storedUser = localStorage.getItem('auth_user');

      if (storedToken) {
        authAPI.setAccessToken(storedToken);
        if (storedUser) {
          setUser(JSON.parse(storedUser));
          setIsAuthenticated(true);
        } else {
          const inferredUser = await fetchUserFromToken(storedToken);
          setAuthState(inferredUser, storedToken);
        }
      }

      // Attempt refresh (uses cookie if available)
      await refresh().catch(() => {});
    } catch (error) {
      console.error('Failed to initialize auth:', error);
      clearAuthState();
    } finally {
      setIsLoading(false);
    }
  };

  const clearAuthState = () => {
    setUser(null);
    setIsAuthenticated(false);
    authAPI.setAccessToken(null);
    localStorage.removeItem('auth_user');
    localStorage.removeItem('access_token');
  };

  const setAuthState = (userData: User, accessToken: string) => {
    setUser(userData);
    setIsAuthenticated(true);
    authAPI.setAccessToken(accessToken);
    try { localStorage.setItem('access_token', accessToken); } catch {}
    localStorage.setItem('auth_user', JSON.stringify(userData));
  };

  const login = async (email: string, password: string): Promise<AuthResult> => {
    try {
      setIsLoading(true);
      const response = await authAPI.login(email, password);

      // Persist token immediately so subsequent requests include Authorization
      authAPI.setAccessToken(response.accessToken);
      try { localStorage.setItem('access_token', response.accessToken); } catch {}

      // Build user from token (introspect or decode)
      const userData = await fetchUserFromToken(response.accessToken, response.email);

      setAuthState(userData, response.accessToken);

      toast({
        title: "Login successful",
        description: `Welcome back${userData.isAdmin ? ', Admin' : ''}!`
      });

      return {
        success: true,
        accessToken: response.accessToken,
        userId: response.userId,
        email: response.email
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Login failed';
      toast({ title: "Login failed", description: errorMessage, variant: "destructive" });
      return { success: false, errorMessage };
    } finally {
      setIsLoading(false);
    }
  };
  const loginWithOTP = async (email: string, otp: string): Promise<AuthResult> => {
    try {
      setIsLoading(true);
      const response = await authAPI.verifyOTP(email, otp);

      // Persist token and build user from token
      authAPI.setAccessToken(response.accessToken);
      try { localStorage.setItem('access_token', response.accessToken); } catch {}
      const userData = await fetchUserFromToken(response.accessToken, response.email);

      setAuthState(userData, response.accessToken);

      toast({ title: "OTP verification successful", description: "Welcome!" });

      return {
        success: true,
        accessToken: response.accessToken,
        userId: response.userId,
        email: response.email,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'OTP verification failed';

      if (errorMessage.includes('pending approval')) {
        toast({
          title: "Account pending approval",
          description: "Your account is awaiting admin approval. You'll be notified when it's ready.",
        });
        return { success: false, requiresApproval: true, errorMessage };
      }

      toast({ title: "OTP verification failed", description: errorMessage, variant: "destructive" });
      return { success: false, errorMessage };
    } finally {
      setIsLoading(false);
    }
  };
  const signup = async (data: SignupRequest): Promise<MessageResponse> => {
    try {
      setIsLoading(true);
      const response = await authAPI.signup(data);

      toast({
        title: "Signup request submitted",
        description: "Your request is pending admin approval. You'll be notified when your account is ready."
      });

      return response;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Signup failed';
      
      toast({
        title: "Signup failed",
        description: errorMessage,
        variant: "destructive"
      });

      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async (): Promise<void> => {
    try {
      await authAPI.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      clearAuthState();
      
      toast({
        title: "Logged out",
        description: "You have been successfully logged out."
      });
    }
  };

  const refresh = async (): Promise<boolean> => {
    try {
      const response = await authAPI.refreshToken();

      // Persist new access token and rebuild user from token
      authAPI.setAccessToken(response.accessToken);
      try { localStorage.setItem('access_token', response.accessToken); } catch {}
      const userData = await fetchUserFromToken(response.accessToken, response.email);

      setAuthState(userData, response.accessToken);
      return true;
    } catch (error) {
      console.error('Token refresh failed:', error);
      clearAuthState();
      return false;
    }
  };
  const linkProvider = async (provider: string, code?: string): Promise<boolean> => {
    try {
      if (!user) return false;

      // For OAuth providers, redirect to OAuth start URL
      if (provider === 'google' || provider === 'azure') {
        const state = JSON.stringify({
          provider,
          action: 'link',
          userId: user.id,
          returnUrl: window.location.pathname
        });

        const oauthUrl = authAPI.getOAuthStartUrl(provider, state);
        window.location.href = oauthUrl;
        return true;
      }

      // For other providers, handle linking directly
      await authAPI.linkProviderToUser(user.id, provider, { code });
      
      toast({
        title: "Provider linked",
        description: `${provider} has been linked to your account.`
      });

      return true;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to link provider';
      
      toast({
        title: "Link failed",
        description: errorMessage,
        variant: "destructive"
      });

      return false;
    }
  };

  const unlinkProvider = async (provider: string): Promise<boolean> => {
    try {
      if (!user) return false;

      await authAPI.unlinkProviderFromUser(user.id, provider);
      
      toast({
        title: "Provider unlinked",
        description: `${provider} has been unlinked from your account.`
      });

      return true;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to unlink provider';
      
      toast({
        title: "Unlink failed",
        description: errorMessage,
        variant: "destructive"
      });

      return false;
    }
  };

  // Auto-refresh token before expiration
  useEffect(() => {
    if (!isAuthenticated) return;

    const refreshInterval = setInterval(async () => {
      await refresh();
    }, 14 * 60 * 1000); // Refresh every 14 minutes (token expires in 15)

    return () => clearInterval(refreshInterval);
  }, [isAuthenticated]);

  const contextValue: AuthContextType = {
    user,
    isAuthenticated,
    isLoading,
    login,
    loginWithOTP,
    signup,
    logout,
    refresh,
    linkProvider,
    unlinkProvider
  };

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};