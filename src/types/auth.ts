/**
 * Authentication-related TypeScript interfaces and types
 */

export interface User {
  id: string;
  email: string;
  displayName: string;
  firstName?: string;
  lastName?: string;
  role: 'admin' | 'user';
  isActive: boolean;
  isApproved: boolean;
  isAdmin: boolean;
  tenantId?: string;
  createdAt: string;
  lastLogin?: string;
  metadata?: Record<string, any>;
}

export interface AuthProvider {
  id: string;
  name: string;
  displayName: string;
  type: 'local_password' | 'email_otp' | 'google' | 'azure' | 'github' | 'saml';
  isEnabled: boolean;
  supportsSignup: boolean;
  supportsLogin: boolean;
  supportsLinking: boolean;
  icon?: string;
}

export interface AuthProviderLink {
  id: string;
  userId: string;
  providerName: string;
  externalId?: string;
  isEnabled: boolean;
  linkedAt: string;
  metadata?: Record<string, any>;
}

export interface PendingSignup {
  id: string;
  tenantId?: string;
  email: string;
  displayName: string;
  providerRequested: string;
  status: 'pending' | 'approved' | 'rejected';
  requestedAppId?: string;
  requestedByIp?: string;
  createdAt: string;
  processedAt?: string;
  processedBy?: string;
  rejectionReason?: string;
  payload?: Record<string, any>;
}

export interface LoginAttempt {
  id: string;
  userId?: string;
  email: string;
  ipAddress: string;
  provider: string;
  success: boolean;
  failureReason?: string;
  userAgent?: string;
  timestamp: string;
}

export interface AuditLog {
  id: string;
  actorUserId?: string;
  actionType: string;
  targetType: string;
  targetId?: string;
  payload?: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
  timestamp: string;
  // Extended properties for UI compatibility
  event_type?: string;
  user_email?: string;  
  ip_address?: string;
  user_agent?: string;
  details?: Record<string, any>;
  severity?: 'info' | 'warning' | 'error' | 'success';
}

// API Request/Response Types

export interface SignupRequest {
  email: string;
  password?: string;
  displayName: string;
  tenantId?: string;
  requestedAppId?: string;
  provider?: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface OTPRequest {
  email: string;
}

export interface OTPVerifyRequest {
  email: string;
  otp: string;
}

export interface TokenResponse {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  userId: string;
  email: string;
  refreshToken?: string;
}

export interface MessageResponse {
  message: string;
  data?: Record<string, any>;
}

export interface AuthResult {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  userId?: string;
  email?: string;
  errorMessage?: string;
  requiresApproval?: boolean;
}

// Admin-specific types

export interface ApprovalRequest {
  signupIds: string[];
  assignRoleId?: string;
  notifyUser?: boolean;
  reason?: string;
}

export interface BulkApprovalRequest {
  signupIds: string[];
  assignRoleId?: string;
  notifyUsers?: boolean;
}

export interface UserWithLoginModes extends User {
  loginModes: {
    password: boolean;
    otp: boolean;
    google: boolean;
    azure: boolean;
    github: boolean;
  };
  providers: AuthProviderLink[];
}

export interface PendingSignupWithDetails extends PendingSignup {
  providerMetadata?: {
    emailVerified?: boolean;
    avatarUrl?: string;
    domainMatch?: boolean;
  };
}

// Filter and pagination types

export interface PendingSignupFilters {
  tenantId?: string;
  provider?: string;
  status?: 'pending' | 'approved' | 'rejected';
  search?: string;
  page?: number;
  limit?: number;
}

export interface UserFilters {
  tenantId?: string;
  isActive?: boolean;
  isApproved?: boolean;
  provider?: string;
  search?: string;
  q?: string;
  page?: number;
  limit?: number;
}

export interface AuditLogFilters {
  actorUserId?: string;
  actionType?: string;
  targetType?: string;
  startDate?: string;
  endDate?: string;
  search?: string;
  event_type?: string;
  severity?: string;
  page?: number;
  limit?: number;
}

// Context and Hook types

export interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<AuthResult>;
  loginWithOTP: (email: string, otp: string) => Promise<AuthResult>;
  signup: (data: SignupRequest) => Promise<MessageResponse>;
  logout: () => Promise<void>;
  refresh: () => Promise<boolean>;
  linkProvider: (provider: string, code?: string) => Promise<boolean>;
  unlinkProvider: (provider: string) => Promise<boolean>;
}

// OAuth-specific types

export interface OAuthState {
  provider: string;
  returnUrl?: string;
  action: 'login' | 'signup' | 'link';
  userId?: string;
}

export interface OAuthStartResponse {
  success: boolean;
  redirectUrl?: string;
  errorMessage?: string;
}

// Provider configuration types

export interface ProviderConfig {
  google?: {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
  };
  azure?: {
    clientId: string;
    clientSecret: string;
    tenantId: string;
    redirectUri: string;
  };
  email?: {
    smtpHost: string;
    smtpPort: number;
    smtpUser: string;
    fromEmail: string;
  };
}

// Rate limiting types

export interface RateLimitConfig {
  login: number;
  signup: number;
  otpRequest: number;
  refresh: number;
}

// Security settings types

export interface SecuritySettings {
  passwordPolicy: {
    minLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSpecial: boolean;
  };
  session: {
    accessTokenExpireMinutes: number;
    refreshTokenExpireDays: number;
    maxRefreshTokens: number;
  };
  otp: {
    length: number;
    expireMinutes: number;
    maxAttempts: number;
  };
  rateLimit: RateLimitConfig;
}

// Tenant-specific types

export interface TenantClient {
  id: string;
  name: string;
  domain?: string;
  autoApprove: boolean;
  defaultRoleId?: string;
  settings: Record<string, any>;
  createdAt: string;
  isActive: boolean;
}

// API client types

export interface APIError {
  message: string;
  code?: string;
  details?: Record<string, any>;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}