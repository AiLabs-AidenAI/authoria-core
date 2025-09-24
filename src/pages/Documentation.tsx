/**
 * Comprehensive documentation for the Authentication Service
 */

import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { 
  Book, 
  Code, 
  Shield, 
  Settings, 
  Zap, 
  Globe, 
  Key, 
  Copy,
  Check,
  ExternalLink
} from 'lucide-react';
import { AppLayout } from '@/components/Layout/AppLayout';
import { toast } from '@/hooks/use-toast';

const CodeBlock = ({ children, language = 'javascript' }: { children: string; language?: string }) => {
  const [copied, setCopied] = useState(false);
  
  const copyToClipboard = () => {
    navigator.clipboard.writeText(children);
    setCopied(true);
    toast({ title: "Code copied to clipboard" });
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative">
      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
        <code className={`language-${language}`}>{children}</code>
      </pre>
      <Button
        size="sm"
        variant="outline"
        onClick={copyToClipboard}
        className="absolute top-2 right-2"
      >
        {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
      </Button>
    </div>
  );
};

export const Documentation = () => {
  return (
    <AppLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Book className="h-8 w-8" />
            Authentication Service Documentation
          </h1>
          <p className="text-muted-foreground">
            Complete guide for integrating and using the authentication service
          </p>
        </div>

        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList className="grid w-full grid-cols-6">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="quickstart">Quick Start</TabsTrigger>
            <TabsTrigger value="api">API Reference</TabsTrigger>
            <TabsTrigger value="integration">Integration</TabsTrigger>
            <TabsTrigger value="security">Security</TabsTrigger>
            <TabsTrigger value="examples">Examples</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Service Overview
                </CardTitle>
                <CardDescription>
                  A comprehensive FastAPI-based authentication service with multiple provider support
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold">Features</h3>
                    <ul className="space-y-2 text-sm">
                      <li className="flex items-center gap-2">
                        <Badge variant="outline">🔐</Badge>
                        Local password authentication
                      </li>
                      <li className="flex items-center gap-2">
                        <Badge variant="outline">📧</Badge>
                        Email OTP authentication
                      </li>
                      <li className="flex items-center gap-2">
                        <Badge variant="outline">🔑</Badge>
                        OAuth2 (Google, Microsoft Azure)
                      </li>
                      <li className="flex items-center gap-2">
                        <Badge variant="outline">👥</Badge>
                        Admin approval workflow
                      </li>
                      <li className="flex items-center gap-2">
                        <Badge variant="outline">📊</Badge>
                        Admin dashboard & user management
                      </li>
                      <li className="flex items-center gap-2">
                        <Badge variant="outline">🔒</Badge>
                        JWT token-based authentication
                      </li>
                      <li className="flex items-center gap-2">
                        <Badge variant="outline">📝</Badge>
                        Comprehensive audit logging
                      </li>
                      <li className="flex items-center gap-2">
                        <Badge variant="outline">⚡</Badge>
                        Rate limiting & security features
                      </li>
                    </ul>
                  </div>
                  
                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold">Architecture</h3>
                    <div className="text-sm space-y-2">
                      <p><strong>Backend:</strong> FastAPI, PostgreSQL, Redis</p>
                      <p><strong>Frontend:</strong> React, TypeScript, Tailwind CSS</p>
                      <p><strong>Authentication:</strong> JWT with refresh tokens</p>
                      <p><strong>Security:</strong> Rate limiting, input validation, audit logging</p>
                      <p><strong>Deployment:</strong> Docker-ready, environment-configurable</p>
                    </div>
                  </div>
                </div>

                <Separator />

                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Use Cases</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 border rounded-lg">
                      <h4 className="font-medium">Microservices Authentication</h4>
                      <p className="text-sm text-muted-foreground mt-1">
                        Centralized authentication for multiple applications and services
                      </p>
                    </div>
                    <div className="p-4 border rounded-lg">
                      <h4 className="font-medium">Enterprise SSO</h4>
                      <p className="text-sm text-muted-foreground mt-1">
                        Integrate with existing identity providers like Azure AD
                      </p>
                    </div>
                    <div className="p-4 border rounded-lg">
                      <h4 className="font-medium">Admin-Controlled Access</h4>
                      <p className="text-sm text-muted-foreground mt-1">
                        Require admin approval for new user registrations
                      </p>
                    </div>
                    <div className="p-4 border rounded-lg">
                      <h4 className="font-medium">Audit & Compliance</h4>
                      <p className="text-sm text-muted-foreground mt-1">
                        Complete audit trail for regulatory compliance
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="quickstart" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Quick Start Guide
                </CardTitle>
                <CardDescription>
                  Get the authentication service up and running in minutes
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">1. Prerequisites</h3>
                  <ul className="list-disc list-inside space-y-1 text-sm ml-4">
                    <li>Python 3.8+</li>
                    <li>PostgreSQL 12+</li>
                    <li>Node.js 16+ (for frontend)</li>
                  </ul>
                </div>

                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">2. Backend Setup</h3>
                  <CodeBlock language="bash">
{`# Clone and setup
cd auth-service
pip install -r requirements.txt

# Configure environment (optional)
cp .env.example .env
# Edit .env with your database URL

# Start the service
python main.py

# Service will be available at:
# API: http://localhost:8000
# Docs: http://localhost:8000/docs`}
                  </CodeBlock>
                </div>

                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">3. Frontend Setup</h3>
                  <CodeBlock language="bash">
{`# Install dependencies
npm install

# Start development server
npm run dev

# Frontend will be available at:
# http://localhost:5173`}
                  </CodeBlock>
                </div>

                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">4. Default Admin Access</h3>
                  <div className="p-4 bg-muted rounded-lg">
                    <p className="font-medium">Default Admin Credentials:</p>
                    <p className="text-sm">Email: <code>admin@example.com</code></p>
                    <p className="text-sm">Password: <code>admin123</code></p>
                    <p className="text-xs text-muted-foreground mt-2">
                      ⚠️ Change these credentials immediately in production!
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="api" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Code className="h-5 w-5" />
                  API Reference
                </CardTitle>
                <CardDescription>
                  Complete API endpoint documentation
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-6">
                  <div>
                    <h3 className="text-lg font-semibold mb-4">Authentication Endpoints</h3>
                    <div className="space-y-4">
                      <div className="border rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant="default">POST</Badge>
                          <code className="text-sm">/v1/auth/login</code>
                        </div>
                        <p className="text-sm text-muted-foreground mb-3">Authenticate with email and password</p>
                        <CodeBlock>
{`{
  "email": "user@example.com",
  "password": "securepassword"
}`}
                        </CodeBlock>
                      </div>

                      <div className="border rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant="default">POST</Badge>
                          <code className="text-sm">/v1/auth/otp/request</code>
                        </div>
                        <p className="text-sm text-muted-foreground mb-3">Request OTP for email authentication</p>
                        <CodeBlock>
{`{
  "email": "user@example.com"
}`}
                        </CodeBlock>
                      </div>

                      <div className="border rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant="default">POST</Badge>
                          <code className="text-sm">/v1/auth/otp/verify</code>
                        </div>
                        <p className="text-sm text-muted-foreground mb-3">Verify OTP and authenticate</p>
                        <CodeBlock>
{`{
  "email": "user@example.com",
  "otp": "123456"
}`}
                        </CodeBlock>
                      </div>

                      <div className="border rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant="outline">GET</Badge>
                          <code className="text-sm">/v1/auth/oauth/&#123;provider&#125;/start</code>
                        </div>
                        <p className="text-sm text-muted-foreground">Start OAuth flow (google, azure)</p>
                      </div>

                      <div className="border rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant="default">POST</Badge>
                          <code className="text-sm">/v1/auth/refresh</code>
                        </div>
                        <p className="text-sm text-muted-foreground">Refresh access token using refresh token</p>
                      </div>
                    </div>
                  </div>

                  <Separator />

                  <div>
                    <h3 className="text-lg font-semibold mb-4">Admin Endpoints</h3>
                    <div className="space-y-4">
                      <div className="border rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant="outline">GET</Badge>
                          <code className="text-sm">/v1/admin/pending-signups</code>
                        </div>
                        <p className="text-sm text-muted-foreground">List pending user signup requests</p>
                      </div>

                      <div className="border rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant="default">POST</Badge>
                          <code className="text-sm">/v1/admin/pending-signups/&#123;id&#125;/approve</code>
                        </div>
                        <p className="text-sm text-muted-foreground">Approve user signup request</p>
                      </div>

                      <div className="border rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant="outline">GET</Badge>
                          <code className="text-sm">/v1/admin/users</code>
                        </div>
                        <p className="text-sm text-muted-foreground">List all users with pagination and filtering</p>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="integration" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Settings className="h-5 w-5" />
                  Integration Guide
                </CardTitle>
                <CardDescription>
                  How to integrate the authentication service with your applications
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-6">
                  <div>
                    <h3 className="text-lg font-semibold mb-4">JavaScript/React Integration</h3>
                    <CodeBlock>
{`// API Client Setup
class AuthAPIClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
    this.accessToken = null;
  }

  setAccessToken(token) {
    this.accessToken = token;
  }

  async request(endpoint, options = {}) {
    const url = \`\${this.baseURL}\${endpoint}\`;
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };

    if (this.accessToken) {
      headers.Authorization = \`Bearer \${this.accessToken}\`;
    }

    const response = await fetch(url, {
      ...options,
      headers,
      credentials: 'include' // Include cookies for refresh token
    });

    if (!response.ok) {
      throw new Error(\`HTTP \${response.status}: \${response.statusText}\`);
    }

    return response.json();
  }

  // Authentication methods
  async login(email, password) {
    return this.request('/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
  }

  async refreshToken() {
    return this.request('/v1/auth/refresh', {
      method: 'POST'
    });
  }

  async logout() {
    return this.request('/v1/auth/logout', {
      method: 'POST'
    });
  }
}

// Usage
const authAPI = new AuthAPIClient('http://localhost:8000');

// Login
const loginResult = await authAPI.login('user@example.com', 'password');
authAPI.setAccessToken(loginResult.access_token);`}
                    </CodeBlock>
                  </div>

                  <div>
                    <h3 className="text-lg font-semibold mb-4">Token Validation Middleware</h3>
                    <CodeBlock>
{`// Express.js Middleware
const validateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    
    // Validate with auth service
    const response = await fetch('http://localhost:8000/v1/auth/introspect', {
      headers: { Authorization: \`Bearer \${token}\` }
    });

    if (!response.ok) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const tokenData = await response.json();
    if (!tokenData.active) {
      return res.status(401).json({ error: 'Token expired' });
    }

    req.user = {
      id: tokenData.user_id,
      email: tokenData.email
    };
    
    next();
  } catch (error) {
    res.status(500).json({ error: 'Token validation failed' });
  }
};

// Usage
app.get('/protected-route', validateToken, (req, res) => {
  res.json({ message: 'Access granted', user: req.user });
});`}
                    </CodeBlock>
                  </div>

                  <div>
                    <h3 className="text-lg font-semibold mb-4">Python Integration</h3>
                    <CodeBlock language="python">
{`import requests
import jwt
from typing import Optional

class AuthClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()

    def login(self, email: str, password: str) -> dict:
        response = self.session.post(
            f"{self.base_url}/v1/auth/login",
            json={"email": email, "password": password}
        )
        response.raise_for_status()
        
        data = response.json()
        self.session.headers.update({
            'Authorization': f"Bearer {data['access_token']}"
        })
        return data

    def validate_token(self, token: str) -> Optional[dict]:
        try:
            response = requests.post(
                f"{self.base_url}/v1/auth/introspect",
                headers={'Authorization': f'Bearer {token}'}
            )
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return None

# Usage
auth_client = AuthClient('http://localhost:8000')
login_result = auth_client.login('user@example.com', 'password')

# Validate token
token_data = auth_client.validate_token(login_result['access_token'])
if token_data and token_data.get('active'):
    print(f"Valid user: {token_data['email']}")
else:
    print("Invalid or expired token")`}
                    </CodeBlock>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="security" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Security Considerations
                </CardTitle>
                <CardDescription>
                  Important security features and best practices
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-6">
                  <div>
                    <h3 className="text-lg font-semibold mb-4">Built-in Security Features</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="border rounded-lg p-4">
                        <h4 className="font-medium flex items-center gap-2">
                          <Key className="h-4 w-4" />
                          Token Security
                        </h4>
                        <ul className="text-sm text-muted-foreground mt-2 space-y-1">
                          <li>• JWT with short expiration (15 minutes)</li>
                          <li>• HTTPOnly refresh token cookies</li>
                          <li>• Automatic token rotation</li>
                          <li>• Secure token storage</li>
                        </ul>
                      </div>
                      
                      <div className="border rounded-lg p-4">
                        <h4 className="font-medium flex items-center gap-2">
                          <Shield className="h-4 w-4" />
                          Rate Limiting
                        </h4>
                        <ul className="text-sm text-muted-foreground mt-2 space-y-1">
                          <li>• Login attempts: 5/minute</li>
                          <li>• Signup requests: 3/minute</li>
                          <li>• OTP requests: 3/minute</li>
                          <li>• Per-IP enforcement</li>
                        </ul>
                      </div>
                      
                      <div className="border rounded-lg p-4">
                        <h4 className="font-medium">Input Validation</h4>
                        <ul className="text-sm text-muted-foreground mt-2 space-y-1">
                          <li>• Pydantic schema validation</li>
                          <li>• Email format checking</li>
                          <li>• Password strength requirements</li>
                          <li>• SQL injection prevention</li>
                        </ul>
                      </div>
                      
                      <div className="border rounded-lg p-4">
                        <h4 className="font-medium">Audit Logging</h4>
                        <ul className="text-sm text-muted-foreground mt-2 space-y-1">
                          <li>• All authentication events logged</li>
                          <li>• IP address and user agent tracking</li>
                          <li>• Failed attempt monitoring</li>
                          <li>• Admin action audit trail</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <Separator />

                  <div>
                    <h3 className="text-lg font-semibold mb-4">Production Security Checklist</h3>
                    <div className="space-y-3">
                      <div className="flex items-start gap-3">
                        <div className="w-4 h-4 rounded border-2 mt-0.5"></div>
                        <div>
                          <p className="font-medium">Change Default Credentials</p>
                          <p className="text-sm text-muted-foreground">
                            Update admin@example.com password immediately
                          </p>
                        </div>
                      </div>
                      
                      <div className="flex items-start gap-3">
                        <div className="w-4 h-4 rounded border-2 mt-0.5"></div>
                        <div>
                          <p className="font-medium">Environment Variables</p>
                          <p className="text-sm text-muted-foreground">
                            Set strong JWT_SECRET, database credentials
                          </p>
                        </div>
                      </div>
                      
                      <div className="flex items-start gap-3">
                        <div className="w-4 h-4 rounded border-2 mt-0.5"></div>
                        <div>
                          <p className="font-medium">HTTPS Configuration</p>
                          <p className="text-sm text-muted-foreground">
                            Enable TLS for all communication
                          </p>
                        </div>
                      </div>
                      
                      <div className="flex items-start gap-3">
                        <div className="w-4 h-4 rounded border-2 mt-0.5"></div>
                        <div>
                          <p className="font-medium">OAuth Provider Setup</p>
                          <p className="text-sm text-muted-foreground">
                            Configure Google/Azure OAuth credentials
                          </p>
                        </div>
                      </div>
                      
                      <div className="flex items-start gap-3">
                        <div className="w-4 h-4 rounded border-2 mt-0.5"></div>
                        <div>
                          <p className="font-medium">Database Security</p>
                          <p className="text-sm text-muted-foreground">
                            Enable SSL, restrict network access
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="examples" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  Integration Examples
                </CardTitle>
                <CardDescription>
                  Real-world examples for different frameworks and scenarios
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-6">
                  <div>
                    <h3 className="text-lg font-semibold mb-4">React Hook for Authentication</h3>
                    <CodeBlock>
{`import { useState, useEffect, useContext, createContext } from 'react';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const login = async (email, password) => {
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        credentials: 'include'
      });
      
      if (response.ok) {
        const data = await response.json();
        setUser({ id: data.user_id, email: data.email });
        return { success: true };
      }
      return { success: false, error: 'Login failed' };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const logout = async () => {
    await fetch('/api/auth/logout', { 
      method: 'POST', 
      credentials: 'include' 
    });
    setUser(null);
  };

  // Auto-refresh token
  useEffect(() => {
    const refreshToken = async () => {
      try {
        const response = await fetch('/api/auth/refresh', {
          method: 'POST',
          credentials: 'include'
        });
        if (response.ok) {
          const data = await response.json();
          setUser({ id: data.user_id, email: data.email });
        }
      } catch (error) {
        console.error('Token refresh failed:', error);
      } finally {
        setLoading(false);
      }
    };

    refreshToken();
    const interval = setInterval(refreshToken, 14 * 60 * 1000); // 14 minutes
    return () => clearInterval(interval);
  }, []);

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};`}
                    </CodeBlock>
                  </div>

                  <div>
                    <h3 className="text-lg font-semibold mb-4">Next.js API Route Integration</h3>
                    <CodeBlock>
{`// pages/api/auth/[...auth].js
import { NextApiRequest, NextApiResponse } from 'next';

const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://localhost:8000';

export default async function handler(req, res) {
  const { auth: segments } = req.query;
  const path = segments.join('/');
  
  try {
    const response = await fetch(\`\${AUTH_SERVICE_URL}/v1/auth/\${path}\`, {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        ...req.headers,
      },
      body: req.method !== 'GET' ? JSON.stringify(req.body) : undefined,
    });

    const data = await response.json();
    
    // Forward cookies from auth service
    const cookies = response.headers.get('set-cookie');
    if (cookies) {
      res.setHeader('Set-Cookie', cookies);
    }

    res.status(response.status).json(data);
  } catch (error) {
    res.status(500).json({ error: 'Authentication service unavailable' });
  }
}

// Middleware for protected routes
// middleware.js
import { NextResponse } from 'next/server';

export async function middleware(request) {
  const token = request.cookies.get('access_token')?.value;
  
  if (!token) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // Validate token with auth service
  try {
    const response = await fetch(\`\${AUTH_SERVICE_URL}/v1/auth/introspect\`, {
      headers: { Authorization: \`Bearer \${token}\` }
    });
    
    if (!response.ok) {
      return NextResponse.redirect(new URL('/login', request.url));
    }
    
    return NextResponse.next();
  } catch {
    return NextResponse.redirect(new URL('/login', request.url));
  }
}

export const config = {
  matcher: ['/dashboard/:path*', '/admin/:path*']
};`}
                    </CodeBlock>
                  </div>

                  <div>
                    <h3 className="text-lg font-semibold mb-4">FastAPI Service Integration</h3>
                    <CodeBlock language="python">
{`from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
import os

app = FastAPI()
security = HTTPBearer()

AUTH_SERVICE_URL = os.getenv('AUTH_SERVICE_URL', 'http://localhost:8000')

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{AUTH_SERVICE_URL}/v1/auth/introspect",
                headers={"Authorization": f"Bearer {credentials.credentials}"}
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials"
                )
            
            token_data = response.json()
            if not token_data.get('active'):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token expired"
                )
            
            return {
                'user_id': token_data['user_id'],
                'email': token_data['email']
            }
        except httpx.RequestError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable"
            )

@app.get("/protected")
async def protected_route(current_user: dict = Depends(verify_token)):
    return {
        "message": "Access granted",
        "user": current_user
    }

@app.get("/user-profile")
async def get_user_profile(current_user: dict = Depends(verify_token)):
    # Use current_user['user_id'] to fetch user-specific data
    return {
        "user_id": current_user['user_id'],
        "email": current_user['email'],
        "profile_data": "..."
    }`}
                    </CodeBlock>
                  </div>
                </div>

                <div className="flex items-center gap-2 p-4 bg-muted rounded-lg">
                  <ExternalLink className="h-4 w-4" />
                  <span className="text-sm">
                    More examples and tutorials available in the 
                    <Button variant="link" className="p-0 ml-1 h-auto">
                      GitHub repository
                    </Button>
                  </span>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </AppLayout>
  );
};

export default Documentation;