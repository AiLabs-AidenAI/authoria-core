/**
 * API client for authentication service
 */

import { 
  User, 
  PendingSignup, 
  AuthResult, 
  SignupRequest, 
  LoginRequest, 
  OTPRequest, 
  OTPVerifyRequest,
  TokenResponse, 
  MessageResponse,
  PendingSignupFilters,
  UserFilters,
  AuditLogFilters,
  PaginatedResponse,
  UserWithLoginModes,
  AuditLog,
  ApprovalRequest,
  BulkApprovalRequest,
  AuthProvider
} from '@/types/auth';

class AuthAPIClient {
  private baseUrl: string;
  private accessToken: string | null = null;

  constructor(baseUrl = 'http://localhost:8000') {
    this.baseUrl = baseUrl;
    console.log('AuthAPIClient initialized with baseUrl:', baseUrl);
  }

  setAccessToken(token: string | null) {
    this.accessToken = token;
  }

  private async request<T>(
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...options.headers as Record<string, string>
    };

    if (this.accessToken) {
      headers.Authorization = `Bearer ${this.accessToken}`;
    }

    const response = await fetch(url, {
      ...options,
      headers,
      credentials: 'include' // Include cookies for refresh tokens
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `HTTP ${response.status}`);
    }

    return response.json();
  }

  // Authentication endpoints

  async signup(data: SignupRequest): Promise<MessageResponse> {
    return this.request<MessageResponse>('/v1/auth/signup', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  async login(email: string, password: string): Promise<TokenResponse> {
    const data: LoginRequest = { email, password };
    return this.request<TokenResponse>('/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  async requestOTP(email: string): Promise<MessageResponse> {
    const data: OTPRequest = { email };
    return this.request<MessageResponse>('/v1/auth/otp/request', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  async verifyOTP(email: string, otp: string): Promise<TokenResponse> {
    const data: OTPVerifyRequest = { email, otp };
    return this.request<TokenResponse>('/v1/auth/otp/verify', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  async refreshToken(): Promise<TokenResponse> {
    return this.request<TokenResponse>('/v1/auth/refresh', {
      method: 'POST'
    });
  }

  async logout(): Promise<MessageResponse> {
    return this.request<MessageResponse>('/v1/auth/logout', {
      method: 'POST'
    });
  }

  async introspectToken(token: string): Promise<any> {
    return this.request('/v1/auth/introspect', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  // OAuth endpoints

  getOAuthStartUrl(provider: string, state?: string): string {
    const params = new URLSearchParams();
    if (state) params.set('state', state);
    
    const queryString = params.toString();
    return `${this.baseUrl}/v1/auth/oauth/${provider}/start${queryString ? '?' + queryString : ''}`;
  }

  // Admin endpoints

  async getPendingSignups(filters?: PendingSignupFilters): Promise<PaginatedResponse<PendingSignup>> {
    const params = new URLSearchParams();
    
    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          params.set(key, value.toString());
        }
      });
    }

    const queryString = params.toString();
    const endpoint = `/v1/admin/pending-signups${queryString ? '?' + queryString : ''}`;
    
    return this.request<PaginatedResponse<PendingSignup>>(endpoint);
  }

  async approvePendingSignup(id: string, data?: { assignRoleId?: string }): Promise<MessageResponse> {
    return this.request<MessageResponse>(`/v1/admin/pending-signups/${id}/approve`, {
      method: 'POST',
      body: JSON.stringify(data || {})
    });
  }

  async bulkApprovePendingSignups(request: BulkApprovalRequest): Promise<MessageResponse> {
    return this.request<MessageResponse>('/v1/admin/pending-signups/bulk-approve', {
      method: 'POST',
      body: JSON.stringify(request)
    });
  }

  async rejectPendingSignup(id: string, reason?: string): Promise<MessageResponse> {
    return this.request<MessageResponse>(`/v1/admin/pending-signups/${id}/reject`, {
      method: 'POST',
      body: JSON.stringify({ reason })
    });
  }

  async bulkRejectPendingSignups(signupIds: string[], reason?: string): Promise<MessageResponse> {
    return this.request<MessageResponse>('/v1/admin/pending-signups/bulk-reject', {
      method: 'POST',
      body: JSON.stringify({ signupIds, reason })
    });
  }

  // User management endpoints

  async getUsers(filters?: UserFilters): Promise<PaginatedResponse<UserWithLoginModes>> {
    const params = new URLSearchParams();
    
    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          params.set(key, value.toString());
        }
      });
    }

    const queryString = params.toString();
    const endpoint = `/v1/admin/users${queryString ? '?' + queryString : ''}`;
    
    return this.request<PaginatedResponse<UserWithLoginModes>>(endpoint);
  }

  async getUser(id: string): Promise<UserWithLoginModes> {
    return this.request<UserWithLoginModes>(`/v1/admin/users/${id}`);
  }

  async updateUser(id: string, data: Partial<User>): Promise<User> {
    return this.request<User>(`/v1/admin/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }

  async disableUser(id: string, reason?: string): Promise<MessageResponse> {
    return this.request<MessageResponse>(`/v1/admin/users/${id}/disable`, {
      method: 'POST',
      body: JSON.stringify({ reason })
    });
  }

  async enableUser(id: string): Promise<MessageResponse> {
    return this.request<MessageResponse>(`/v1/admin/users/${id}/enable`, {
      method: 'POST'
    });
  }

  async linkProviderToUser(userId: string, provider: string, data?: any): Promise<MessageResponse> {
    return this.request<MessageResponse>(`/v1/admin/users/${userId}/link-provider`, {
      method: 'POST',
      body: JSON.stringify({ provider, ...data })
    });
  }

  async unlinkProviderFromUser(userId: string, provider: string): Promise<MessageResponse> {
    return this.request<MessageResponse>(`/v1/admin/users/${userId}/unlink-provider`, {
      method: 'POST',
      body: JSON.stringify({ provider })
    });
  }

  async toggleUserLoginMode(userId: string, provider: string, enabled: boolean): Promise<MessageResponse> {
    return this.request<MessageResponse>(`/v1/admin/users/${userId}/toggle-login-mode`, {
      method: 'POST',
      body: JSON.stringify({ provider, enabled })
    });
  }

  async createUser(data: {
    email: string;
    display_name: string;
    password?: string;
    is_admin?: boolean;
  }): Promise<User> {
    return this.request<User>('/v1/admin/users', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  // Audit endpoints

  async getAuditLogs(filters?: AuditLogFilters): Promise<PaginatedResponse<AuditLog>> {
    const params = new URLSearchParams();
    
    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          params.set(key, value.toString());
        }
      });
    }

    const queryString = params.toString();
    const endpoint = `/v1/admin/audit${queryString ? '?' + queryString : ''}`;
    
    return this.request<PaginatedResponse<AuditLog>>(endpoint);
  }

  // Provider management

  // Auth Config CRUD operations
  
  async getAuthProviders(): Promise<any[]> {
    return this.request<any[]>('/v1/admin/config/providers');
  }

  async createAuthProvider(data: any): Promise<any> {
    return this.request<any>('/v1/admin/config/providers', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  async updateAuthProvider(id: string, data: any): Promise<any> {
    return this.request<any>(`/v1/admin/config/providers/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }

  async deleteAuthProvider(id: string): Promise<MessageResponse> {
    return this.request<MessageResponse>(`/v1/admin/config/providers/${id}`, {
      method: 'DELETE'
    });
  }

  // SMTP Config operations
  
  async getSMTPConfigs(): Promise<any[]> {
    return this.request<any[]>('/v1/admin/config/smtp');
  }

  async createSMTPConfig(data: any): Promise<any> {
    return this.request<any>('/v1/admin/config/smtp', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  async updateSMTPConfig(id: string, data: any): Promise<any> {
    return this.request<any>(`/v1/admin/config/smtp/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }

  async deleteSMTPConfig(id: string): Promise<MessageResponse> {
    return this.request<MessageResponse>(`/v1/admin/config/smtp/${id}`, {
      method: 'DELETE'
    });
  }

  // Client Application operations
  
  async getClientApplications(): Promise<any[]> {
    return this.request<any[]>('/v1/admin/config/clients');
  }

  async createClientApplication(data: any): Promise<any> {
    return this.request<any>('/v1/admin/config/clients', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  async updateClientApplication(id: string, data: any): Promise<any> {
    return this.request<any>(`/v1/admin/config/clients/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }

  async deleteClientApplication(id: string): Promise<MessageResponse> {
    return this.request<MessageResponse>(`/v1/admin/config/clients/${id}`, {
      method: 'DELETE'
    });
  }

  async regenerateClientSecret(id: string): Promise<{client_secret: string}> {
    return this.request<{client_secret: string}>(`/v1/admin/config/clients/${id}/regenerate-secret`, {
      method: 'POST'
    });
  }

  // Auth Settings operations
  
  async getAuthSettings(): Promise<any> {
    return this.request<any>('/v1/admin/config/settings');
  }

  async updateAuthSettings(data: any): Promise<any> {
    return this.request<any>('/v1/admin/config/settings', {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }

  // Bulk operations

  async exportPendingSignups(filters?: PendingSignupFilters): Promise<Blob> {
    const params = new URLSearchParams();
    
    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          params.set(key, value.toString());
        }
      });
    }

    const queryString = params.toString();
    const endpoint = `/v1/admin/pending-signups/export${queryString ? '?' + queryString : ''}`;
    
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      headers: this.accessToken ? { Authorization: `Bearer ${this.accessToken}` } : {},
      credentials: 'include'
    });

    if (!response.ok) {
      throw new Error('Failed to export data');
    }

    return response.blob();
  }

  async bulkToggleLoginModes(userIds: string[], provider: string, enabled: boolean): Promise<MessageResponse> {
    return this.request<MessageResponse>('/v1/admin/users/bulk-toggle-login-mode', {
      method: 'POST',
      body: JSON.stringify({ userIds, provider, enabled })
    });
  }
}

// Create singleton instance
export const authAPI = new AuthAPIClient();

// Helper functions for common operations
export const downloadFile = (blob: Blob, filename: string) => {
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
};

export const formatLoginModes = (modes: Record<string, boolean>): string[] => {
  return Object.entries(modes)
    .filter(([_, enabled]) => enabled)
    .map(([mode, _]) => mode);
};

export const getProviderIcon = (provider: string): string => {
  const icons: Record<string, string> = {
    'local_password': '🔑',
    'email_otp': '📧',
    'google': '🟦',
    'azure': '🟦',
    'github': '⚫',
    'saml': '🔐'
  };
  return icons[provider] || '❓';
};