import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Copy, ExternalLink, Server, Code, Settings, Key, CheckCircle2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

const IntegrationGuide: React.FC = () => {
  const { toast } = useToast();
  const [copiedSection, setCopiedSection] = useState<string>('');

  const copyToClipboard = (text: string, section: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(section);
    toast({
      title: "Copied to clipboard",
      description: `${section} code copied successfully`,
    });
    setTimeout(() => setCopiedSection(''), 2000);
  };

  const CodeBlock = ({ children, language = "bash", section }: { children: string; language?: string; section: string }) => (
    <div className="relative">
      <pre className="bg-muted p-4 rounded-lg text-sm overflow-x-auto border">
        <code className={`language-${language}`}>{children}</code>
      </pre>
      <Button
        size="sm"
        variant="outline"
        className="absolute top-2 right-2 h-8 w-8 p-0"
        onClick={() => copyToClipboard(children, section)}
      >
        <Copy className="h-4 w-4" />
      </Button>
      {copiedSection === section && (
        <div className="absolute top-2 right-12 text-sm text-green-600 bg-background px-2 py-1 rounded border">
          Copied!
        </div>
      )}
    </div>
  );

  return (
    <div className="container mx-auto py-8 px-4 max-w-6xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-4 flex items-center gap-2">
          <Code className="h-8 w-8 text-primary" />
          Authentication Service Integration Guide
        </h1>
        <p className="text-muted-foreground text-lg">
          Complete guide to integrate this authentication service into your applications
        </p>
        
        <Alert className="mt-4 border-green-200 bg-green-50 dark:bg-green-950/20">
          <CheckCircle2 className="h-4 w-4 text-green-600" />
          <AlertTitle className="text-green-800 dark:text-green-300">✅ Issues Fixed & Ready</AlertTitle>
          <AlertDescription className="text-green-700 dark:text-green-400">
            <div className="space-y-1 mt-2">
              <div>🔧 Azure SSO `link_account` method fixed</div>
              <div>📧 OTP email service properly configured (console fallback included)</div>
              <div>👤 Admin credentials created: <code>admin@example.com</code> / <code>admin123</code></div>
              <div>🔒 All OAuth providers and type hints corrected</div>
              <div>🚀 Backend ready at: <code>http://localhost:8000</code></div>
            </div>
          </AlertDescription>
        </Alert>
      </div>

      <Tabs defaultValue="setup" className="w-full">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="setup">Setup</TabsTrigger>
          <TabsTrigger value="frontend">Frontend</TabsTrigger>
          <TabsTrigger value="backend">Backend</TabsTrigger>
          <TabsTrigger value="examples">Examples</TabsTrigger>
          <TabsTrigger value="api">API Docs</TabsTrigger>
        </TabsList>

        <TabsContent value="setup" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Server className="h-5 w-5" />
                Starting the Auth Service
              </CardTitle>
              <CardDescription>
                Follow these steps to start the authentication backend service
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <h4 className="font-semibold mb-2">1. Navigate to auth service directory</h4>
                <CodeBlock section="navigate" language="bash">cd auth-service</CodeBlock>
              </div>
              
              <div>
                <h4 className="font-semibold mb-2">2. Create virtual environment (optional but recommended)</h4>
                <CodeBlock section="venv" language="bash">{`python -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate`}</CodeBlock>
              </div>

              <div>
                <h4 className="font-semibold mb-2">3. Install dependencies</h4>
                <CodeBlock section="install" language="bash">pip install -r requirements.txt</CodeBlock>
              </div>

              <div>
                <h4 className="font-semibold mb-2">4. Setup environment variables</h4>
                <CodeBlock section="env" language="bash">cp .env.example .env</CodeBlock>
                <p className="text-sm text-muted-foreground mt-2">
                  Edit the .env file with your database and service configurations
                </p>
              </div>

              <div>
                <h4 className="font-semibold mb-2">5. Start the service</h4>
                <CodeBlock section="start" language="bash">{`# Using the startup script (recommended)
python start_service.py

# Or directly with uvicorn
uvicorn main:app --host 0.0.0.0 --port 8000 --reload`}</CodeBlock>
                <div className="flex items-center gap-2 mt-2">
                  <Badge variant="secondary">Default Port: 8000</Badge>
                  <Badge variant="outline">Health Check: GET /health</Badge>
                </div>
              </div>

              <div className="mt-6 p-4 border rounded-lg bg-blue-50 dark:bg-blue-950/20">
                <h4 className="font-semibold mb-2 flex items-center gap-2">
                  <Key className="h-4 w-4" />
                  Default Admin Credentials
                </h4>
                <div className="space-y-2">
                  <div className="flex items-center gap-4">
                    <code className="bg-background px-2 py-1 rounded">Email: admin@example.com</code>
                    <code className="bg-background px-2 py-1 rounded">Password: admin123</code>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    ⚠️ <strong>Important:</strong> Change these credentials immediately after first login!
                  </p>
                </div>
              </div>

              <div className="mt-4">
                <h4 className="font-semibold mb-2">Service URLs</h4>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">API Base</Badge>
                    <code className="text-sm">http://localhost:8000</code>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">API Docs</Badge>
                    <code className="text-sm">http://localhost:8000/docs</code>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">ReDoc</Badge>
                    <code className="text-sm">http://localhost:8000/redoc</code>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                Environment Configuration
              </CardTitle>
            </CardHeader>
            <CardContent>
              <CodeBlock section="env-config" language="bash">{`# Required Settings
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/auth_db
SECRET_KEY=your-secret-key-minimum-32-characters
DEBUG=true

# CORS Origins (add your app's origin)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173,https://yourdomain.com

# Email Configuration (for OTP and notifications)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
FROM_EMAIL=noreply@yourapp.com

# Google OAuth (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Azure OAuth (optional)
AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-client-secret
AZURE_TENANT_ID=your-azure-tenant-id`}</CodeBlock>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="frontend" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>React Integration Template</CardTitle>
              <CardDescription>
                Complete React integration with TypeScript support
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <h4 className="font-semibold mb-2">1. Install Dependencies</h4>
                <CodeBlock section="react-deps" language="bash">{`npm install axios
# or
npm install fetch`}</CodeBlock>
              </div>

              <div>
                <h4 className="font-semibold mb-2">2. API Client (api-client.ts)</h4>
                <CodeBlock section="api-client" language="typescript">{`class AuthAPIClient {
  private baseUrl: string;
  private accessToken: string | null = null;

  constructor(baseUrl: string = 'http://localhost:8000') {
    this.baseUrl = baseUrl;
  }

  setAccessToken(token: string | null) {
    this.accessToken = token;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = \`\${this.baseUrl}\${endpoint}\`;
    
    const config: RequestInit = {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(this.accessToken && { Authorization: \`Bearer \${this.accessToken}\` }),
        ...options.headers,
      },
      credentials: 'include', // Important for refresh token cookies
    };

    const response = await fetch(url, config);
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Request failed' }));
      throw new Error(error.detail || \`HTTP \${response.status}\`);
    }

    return response.json();
  }

  // Authentication Methods
  async login(email: string, password: string) {
    return this.request('/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async signup(userData: { email: string; full_name: string; password: string }) {
    return this.request('/v1/auth/signup', {
      method: 'POST',
      body: JSON.stringify(userData),
    });
  }

  async refreshToken() {
    return this.request('/v1/auth/refresh', { method: 'POST' });
  }

  async logout() {
    return this.request('/v1/auth/logout', { method: 'POST' });
  }

  async requestOTP(email: string) {
    return this.request('/v1/auth/request-otp', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  async verifyOTP(email: string, otp: string) {
    return this.request('/v1/auth/verify-otp', {
      method: 'POST',
      body: JSON.stringify({ email, otp }),
    });
  }

  // OAuth Methods  
  getOAuthStartUrl(provider: 'google' | 'azure', redirectUri?: string) {
    const params = new URLSearchParams();
    if (redirectUri) params.append('redirect_uri', redirectUri);
    return \`\${this.baseUrl}/v1/auth/\${provider}/start?\${params}\`;
  }
}

export const authAPI = new AuthAPIClient();`}</CodeBlock>
              </div>

              <div>
                <h4 className="font-semibold mb-2">3. Auth Context (AuthContext.tsx)</h4>
                <CodeBlock section="auth-context" language="typescript">{`import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { authAPI } from './api-client';

interface User {
  id: string;
  email: string;
  full_name: string;
  is_admin: boolean;
  is_active: boolean;
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<any>;
  loginWithOTP: (email: string, otp: string) => Promise<any>;
  signup: (userData: any) => Promise<any>;
  logout: () => Promise<void>;
  refreshToken: () => Promise<boolean>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const login = async (email: string, password: string) => {
    const result = await authAPI.login(email, password);
    authAPI.setAccessToken(result.access_token);
    setUser(result.user);
    localStorage.setItem('auth_user', JSON.stringify(result.user));
    return result;
  };

  const loginWithOTP = async (email: string, otp: string) => {
    const result = await authAPI.verifyOTP(email, otp);
    authAPI.setAccessToken(result.access_token);
    setUser(result.user);
    localStorage.setItem('auth_user', JSON.stringify(result.user));
    return result;
  };

  const signup = async (userData: any) => {
    return authAPI.signup(userData);
  };

  const logout = async () => {
    try {
      await authAPI.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      authAPI.setAccessToken(null);
      setUser(null);
      localStorage.removeItem('auth_user');
    }
  };

  const refreshToken = async (): Promise<boolean> => {
    try {
      const result = await authAPI.refreshToken();
      authAPI.setAccessToken(result.access_token);
      if (result.user) {
        setUser(result.user);
        localStorage.setItem('auth_user', JSON.stringify(result.user));
      }
      return true;
    } catch (error) {
      authAPI.setAccessToken(null);
      setUser(null);
      localStorage.removeItem('auth_user');
      return false;
    }
  };

  useEffect(() => {
    const initializeAuth = async () => {
      const storedUser = localStorage.getItem('auth_user');
      if (storedUser) {
        const success = await refreshToken();
        if (!success) {
          localStorage.removeItem('auth_user');
        }
      }
      setIsLoading(false);
    };

    initializeAuth();
  }, []);

  const value: AuthContextType = {
    user,
    isAuthenticated: !!user,
    isLoading,
    login,
    loginWithOTP,
    signup,
    logout,
    refreshToken,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};`}</CodeBlock>
              </div>

              <div>
                <h4 className="font-semibold mb-2">4. Protected Route Component</h4>
                <CodeBlock section="protected-route" language="typescript">{`import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './AuthContext';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requireAdmin?: boolean;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ 
  children, 
  requireAdmin = false 
}) => {
  const { user, isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requireAdmin && !user?.is_admin) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
};

export default ProtectedRoute;`}</CodeBlock>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="backend" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Backend Integration Templates</CardTitle>
              <CardDescription>
                Integration examples for different backend frameworks
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h4 className="font-semibold mb-2 flex items-center gap-2">
                  Node.js/Express Middleware
                  <Badge variant="secondary">JavaScript</Badge>
                </h4>
                <CodeBlock section="express-middleware" language="javascript">{`const axios = require('axios');

// Middleware to verify JWT token with auth service
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    
    // Verify token with auth service
    const response = await axios.post('http://localhost:8000/v1/auth/introspect', {}, {
      headers: { Authorization: \`Bearer \${token}\` }
    });

    if (response.data.active) {
      req.user = response.data.user;
      next();
    } else {
      res.status(401).json({ error: 'Invalid token' });
    }
  } catch (error) {
    res.status(401).json({ error: 'Authentication failed' });
  }
};

// Admin-only middleware
const adminMiddleware = (req, res, next) => {
  if (!req.user?.is_admin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Usage
app.get('/protected', authMiddleware, (req, res) => {
  res.json({ message: 'Protected route', user: req.user });
});

app.get('/admin-only', authMiddleware, adminMiddleware, (req, res) => {
  res.json({ message: 'Admin only route' });
});`}</CodeBlock>
              </div>

              <div>
                <h4 className="font-semibold mb-2 flex items-center gap-2">
                  Python/FastAPI Integration
                  <Badge variant="secondary">Python</Badge>
                </h4>
                <CodeBlock section="fastapi-integration" language="python">{`import httpx
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()
AUTH_SERVICE_URL = "http://localhost:8000"

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token with auth service"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{AUTH_SERVICE_URL}/v1/auth/introspect",
                headers={"Authorization": f"Bearer {credentials.credentials}"}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("active"):
                    return data["user"]
            
            raise HTTPException(status_code=401, detail="Invalid token")
            
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Auth service unavailable")

async def require_admin(user: dict = Depends(verify_token)):
    """Require admin privileges"""
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# Usage
@app.get("/protected")
async def protected_route(user: dict = Depends(verify_token)):
    return {"message": "Protected route", "user": user}

@app.get("/admin-only")
async def admin_route(user: dict = Depends(require_admin)):
    return {"message": "Admin only route"}`}</CodeBlock>
              </div>

              <div>
                <h4 className="font-semibold mb-2 flex items-center gap-2">
                  Next.js API Routes
                  <Badge variant="secondary">TypeScript</Badge>
                </h4>
                <CodeBlock section="nextjs-api" language="typescript">{`// utils/auth.ts
export async function verifyToken(token: string) {
  try {
    const response = await fetch('http://localhost:8000/v1/auth/introspect', {
      method: 'POST',
      headers: {
        'Authorization': \`Bearer \${token}\`,
        'Content-Type': 'application/json'
      }
    });

    if (response.ok) {
      const data = await response.json();
      return data.active ? data.user : null;
    }
  } catch (error) {
    console.error('Token verification failed:', error);
  }
  return null;
}

// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  const token = request.headers.get('authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const user = await verifyToken(token);
  if (!user) {
    return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
  }

  // Add user to headers for API routes
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-user', JSON.stringify(user));

  return NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });
}

export const config = {
  matcher: '/api/protected/:path*',
};`}</CodeBlock>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="examples" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Complete Integration Examples</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h4 className="font-semibold mb-2">Login Component Example</h4>
                <CodeBlock section="login-component" language="typescript">{`import React, { useState } from 'react';
import { useAuth } from './AuthContext';
import { useNavigate } from 'react-router-dom';

const LoginForm: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [useOTP, setUseOTP] = useState(false);
  const [otp, setOTP] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const { login, loginWithOTP } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (useOTP) {
        await loginWithOTP(email, otp);
      } else {
        await login(email, password);
      }
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const requestOTP = async () => {
    try {
      await authAPI.requestOTP(email);
      setUseOTP(true);
      // Show success message
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <input
        type="email"
        placeholder="Email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        required
        className="w-full p-2 border rounded"
      />
      
      {!useOTP ? (
        <>
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="w-full p-2 border rounded"
          />
          <button type="button" onClick={requestOTP}>
            Use OTP instead
          </button>
        </>
      ) : (
        <input
          type="text"
          placeholder="Enter OTP"
          value={otp}
          onChange={(e) => setOTP(e.target.value)}
          required
          className="w-full p-2 border rounded"
        />
      )}
      
      {error && <div className="text-red-500">{error}</div>}
      
      <button 
        type="submit" 
        disabled={loading}
        className="w-full p-2 bg-blue-500 text-white rounded disabled:opacity-50"
      >
        {loading ? 'Logging in...' : 'Login'}
      </button>
    </form>
  );
};

export default LoginForm;`}</CodeBlock>
              </div>

              <div>
                <h4 className="font-semibold mb-2">OAuth Integration Example</h4>
                <CodeBlock section="oauth-example" language="typescript">{`import { authAPI } from './api-client';

const OAuthButtons: React.FC = () => {
  const handleGoogleLogin = () => {
    const redirectUri = \`\${window.location.origin}/auth/callback\`;
    const oauthUrl = authAPI.getOAuthStartUrl('google', redirectUri);
    window.location.href = oauthUrl;
  };

  const handleAzureLogin = () => {
    const redirectUri = \`\${window.location.origin}/auth/callback\`;
    const oauthUrl = authAPI.getOAuthStartUrl('azure', redirectUri);
    window.location.href = oauthUrl;
  };

  return (
    <div className="space-y-2">
      <button 
        onClick={handleGoogleLogin}
        className="w-full p-2 border border-gray-300 rounded flex items-center justify-center gap-2"
      >
        <img src="/google-icon.png" alt="Google" className="w-5 h-5" />
        Continue with Google
      </button>
      
      <button 
        onClick={handleAzureLogin}
        className="w-full p-2 border border-gray-300 rounded flex items-center justify-center gap-2"
      >
        <img src="/microsoft-icon.png" alt="Microsoft" className="w-5 h-5" />
        Continue with Microsoft
      </button>
    </div>
  );
};

// OAuth Callback Handler
const OAuthCallback: React.FC = () => {
  const navigate = useNavigate();
  
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    const error = urlParams.get('error');
    
    if (token) {
      // Token is automatically set in cookie by backend
      // Trigger auth refresh to get user data
      window.location.href = '/dashboard';
    } else if (error) {
      navigate('/login?error=' + encodeURIComponent(error));
    }
  }, [navigate]);

  return <div>Processing authentication...</div>;
};`}</CodeBlock>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="api" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Key className="h-5 w-5" />
                API Endpoints Reference
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div>
                  <h4 className="font-semibold mb-3">Authentication Endpoints</h4>
                  <div className="space-y-2 text-sm">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">POST</Badge>
                      <code>/v1/auth/signup</code>
                      <span className="text-muted-foreground">- User registration</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">POST</Badge>
                      <code>/v1/auth/login</code>
                      <span className="text-muted-foreground">- Email/password login</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">POST</Badge>
                      <code>/v1/auth/request-otp</code>
                      <span className="text-muted-foreground">- Request OTP for email</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">POST</Badge>
                      <code>/v1/auth/verify-otp</code>
                      <span className="text-muted-foreground">- Verify OTP and login</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">POST</Badge>
                      <code>/v1/auth/refresh</code>
                      <span className="text-muted-foreground">- Refresh access token</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">POST</Badge>
                      <code>/v1/auth/logout</code>
                      <span className="text-muted-foreground">- User logout</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">POST</Badge>
                      <code>/v1/auth/introspect</code>
                      <span className="text-muted-foreground">- Verify token validity</span>
                    </div>
                  </div>
                </div>

                <Separator />

                <div>
                  <h4 className="font-semibold mb-3">OAuth Endpoints</h4>
                  <div className="space-y-2 text-sm">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">GET</Badge>
                      <code>/v1/auth/google/start</code>
                      <span className="text-muted-foreground">- Start Google OAuth flow</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">GET</Badge>
                      <code>/v1/auth/google/callback</code>
                      <span className="text-muted-foreground">- Handle Google OAuth callback</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">GET</Badge>
                      <code>/v1/auth/azure/start</code>
                      <span className="text-muted-foreground">- Start Azure OAuth flow</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">GET</Badge>
                      <code>/v1/auth/azure/callback</code>
                      <span className="text-muted-foreground">- Handle Azure OAuth callback</span>
                    </div>
                  </div>
                </div>

                <Separator />

                <div>
                  <h4 className="font-semibold mb-3">Admin Endpoints (Requires Admin Token)</h4>
                  <div className="space-y-2 text-sm">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">GET</Badge>
                      <code>/v1/admin/pending-signups</code>
                      <span className="text-muted-foreground">- List pending user approvals</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">POST</Badge>
                      <code>/v1/admin/approve-signup/&#123;signup_id&#125;</code>
                      <span className="text-muted-foreground">- Approve user signup</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">GET</Badge>
                      <code>/v1/users</code>
                      <span className="text-muted-foreground">- List all users</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">PUT</Badge>
                      <code>/v1/users/&#123;user_id&#125;</code>
                      <span className="text-muted-foreground">- Update user</span>
                    </div>
                  </div>
                </div>

                <Separator />

                <div>
                  <h4 className="font-semibold mb-3">Response Format</h4>
                  <CodeBlock section="response-format" language="json">{`{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "full_name": "John Doe",
    "is_active": true,
    "is_admin": false,
    "created_at": "2024-01-01T00:00:00Z"
  }
}`}</CodeBlock>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <Card className="mt-8">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ExternalLink className="h-5 w-5" />
            Quick Start Checklist
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm">
            <div className="flex items-center gap-2">
              <input type="checkbox" id="backend-running" />
              <label htmlFor="backend-running">Auth service backend is running on port 8000</label>
            </div>
            <div className="flex items-center gap-2">
              <input type="checkbox" id="env-configured" />
              <label htmlFor="env-configured">Environment variables configured (.env file)</label>
            </div>
            <div className="flex items-center gap-2">
              <input type="checkbox" id="cors-configured" />
              <label htmlFor="cors-configured">CORS origins include your app's domain</label>
            </div>
            <div className="flex items-center gap-2">
              <input type="checkbox" id="api-client" />
              <label htmlFor="api-client">API client implemented with proper base URL</label>
            </div>
            <div className="flex items-center gap-2">
              <input type="checkbox" id="auth-context" />
              <label htmlFor="auth-context">Auth context provider wraps your app</label>
            </div>
            <div className="flex items-center gap-2">
              <input type="checkbox" id="protected-routes" />
              <label htmlFor="protected-routes">Protected routes implemented</label>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default IntegrationGuide;