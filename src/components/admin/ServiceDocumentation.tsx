import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Code, Copy, ExternalLink, Shield, Users, Key, Database } from 'lucide-react';
import { toast } from '@/hooks/use-toast';

export function ServiceDocumentation() {
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to clipboard",
      description: "Code snippet has been copied to your clipboard."
    });
  };

  const integrationExamples = {
    curl: `# Login Example
curl -X POST http://localhost:8000/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email": "user@example.com", "password": "password123"}'

# Get Users (Admin)
curl -X GET http://localhost:8000/v1/admin/users \\
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Approve Signup
curl -X POST http://localhost:8000/v1/admin/pending-signups/{id}/approve \\
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"default_role_id": "user", "notify_user": true}'`,

    javascript: `// JavaScript Integration Example
const AuthService = {
  async login(email, password) {
    const response = await fetch('http://localhost:8000/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
      credentials: 'include'
    });
    
    if (!response.ok) throw new Error('Login failed');
    return response.json();
  },

  async getUsers(page = 1, limit = 50) {
    const token = localStorage.getItem('auth_token');
    const response = await fetch(\`http://localhost:8000/v1/admin/users?page=\${page}&limit=\${limit}\`, {
      headers: { 'Authorization': \`Bearer \${token}\` },
      credentials: 'include'
    });
    
    return response.json();
  },

  async approveSignup(signupId, defaultRole = null) {
    const token = localStorage.getItem('auth_token');
    const response = await fetch(\`http://localhost:8000/v1/admin/pending-signups/\${signupId}/approve\`, {
      method: 'POST',
      headers: {
        'Authorization': \`Bearer \${token}\`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ 
        default_role_id: defaultRole,
        notify_user: true 
      }),
      credentials: 'include'
    });
    
    return response.json();
  }
};`,

    python: `# Python Integration Example
import requests
import json

class AuthClient:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.access_token = None
    
    def login(self, email, password):
        response = self.session.post(
            f"{self.base_url}/v1/auth/login",
            json={"email": email, "password": password}
        )
        response.raise_for_status()
        
        data = response.json()
        self.access_token = data["access_token"]
        self.session.headers.update({
            "Authorization": f"Bearer {self.access_token}"
        })
        return data
    
    def get_users(self, page=1, limit=50):
        response = self.session.get(
            f"{self.base_url}/v1/admin/users",
            params={"page": page, "limit": limit}
        )
        response.raise_for_status()
        return response.json()
    
    def approve_signup(self, signup_id, default_role=None):
        response = self.session.post(
            f"{self.base_url}/v1/admin/pending-signups/{signup_id}/approve",
            json={
                "default_role_id": default_role,
                "notify_user": True
            }
        )
        response.raise_for_status()
        return response.json()

# Usage
auth = AuthClient()
auth.login("admin@example.com", "password")
users = auth.get_users()`,

    react: `// React Hook Example
import { useState, useEffect } from 'react';

export function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  const login = async (email, password) => {
    const response = await fetch('http://localhost:8000/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
      credentials: 'include'
    });
    
    if (!response.ok) throw new Error('Login failed');
    
    const data = await response.json();
    localStorage.setItem('auth_token', data.access_token);
    setUser({ id: data.user_id, email: data.email });
    
    return data;
  };
  
  const logout = async () => {
    await fetch('http://localhost:8000/v1/auth/logout', {
      method: 'POST',
      credentials: 'include'
    });
    
    localStorage.removeItem('auth_token');
    setUser(null);
  };
  
  useEffect(() => {
    // Check for existing token on mount
    const token = localStorage.getItem('auth_token');
    if (token) {
      // Verify token with backend
      fetch('http://localhost:8000/v1/auth/introspect', {
        headers: { 'Authorization': \`Bearer \${token}\` }
      })
      .then(res => res.json())
      .then(data => {
        if (data.active) {
          setUser({ id: data.user_id, email: data.email });
        } else {
          localStorage.removeItem('auth_token');
        }
      })
      .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);
  
  return { user, login, logout, loading };
}`
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Authentication Service Documentation</h1>
          <p className="text-muted-foreground mt-2">
            Complete guide for integrating with the authentication service
          </p>
        </div>
        <Button variant="outline" className="gap-2">
          <ExternalLink className="h-4 w-4" />
          API Reference
        </Button>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Base URL</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">localhost:8000</div>
            <p className="text-xs text-muted-foreground">FastAPI Backend</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Auth Methods</CardTitle>
            <Key className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">4</div>
            <p className="text-xs text-muted-foreground">Password, OTP, Google, Azure</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Admin Features</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">Full</div>
            <p className="text-xs text-muted-foreground">User & approval management</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">High</div>
            <p className="text-xs text-muted-foreground">Argon2, JWT, Rate limiting</p>
          </CardContent>
        </Card>
      </div>

      {/* API Endpoints */}
      <Card>
        <CardHeader>
          <CardTitle>API Endpoints</CardTitle>
          <CardDescription>Available authentication and admin endpoints</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <h4 className="font-semibold mb-2">Authentication Endpoints</h4>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Badge variant="secondary">POST</Badge>
                  <code className="text-sm">/v1/auth/signup</code>
                  <span className="text-sm text-muted-foreground">- Create signup request</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="secondary">POST</Badge>
                  <code className="text-sm">/v1/auth/login</code>
                  <span className="text-sm text-muted-foreground">- Email/password login</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="secondary">POST</Badge>
                  <code className="text-sm">/v1/auth/otp/request</code>
                  <span className="text-sm text-muted-foreground">- Request OTP</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="secondary">POST</Badge>
                  <code className="text-sm">/v1/auth/otp/verify</code>
                  <span className="text-sm text-muted-foreground">- Verify OTP</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline">GET</Badge>
                  <code className="text-sm">/v1/auth/oauth/google/start</code>
                  <span className="text-sm text-muted-foreground">- Start OAuth flow</span>
                </div>
              </div>
            </div>

            <div>
              <h4 className="font-semibold mb-2">Admin Endpoints</h4>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Badge variant="outline">GET</Badge>
                  <code className="text-sm">/v1/admin/pending-signups</code>
                  <span className="text-sm text-muted-foreground">- Get pending requests</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="secondary">POST</Badge>
                  <code className="text-sm">/v1/admin/pending-signups/ID/approve</code>
                  <span className="text-sm text-muted-foreground">- Approve signup</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline">GET</Badge>
                  <code className="text-sm">/v1/admin/users</code>
                  <span className="text-sm text-muted-foreground">- Get users</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="secondary">POST</Badge>
                  <code className="text-sm">/v1/admin/users</code>
                  <span className="text-sm text-muted-foreground">- Create user manually</span>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Integration Examples */}
      <Card>
        <CardHeader>
          <CardTitle>Integration Examples</CardTitle>
          <CardDescription>Code examples for different platforms and languages</CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="javascript" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="javascript">JavaScript</TabsTrigger>
              <TabsTrigger value="python">Python</TabsTrigger>
              <TabsTrigger value="react">React</TabsTrigger>
              <TabsTrigger value="curl">cURL</TabsTrigger>
            </TabsList>

            {Object.entries(integrationExamples).map(([key, code]) => (
              <TabsContent key={key} value={key}>
                <div className="relative">
                  <Button
                    size="sm"
                    variant="outline"
                    className="absolute top-2 right-2 z-10"
                    onClick={() => copyToClipboard(code)}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                  <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                    <code>{code}</code>
                  </pre>
                </div>
              </TabsContent>
            ))}
          </Tabs>
        </CardContent>
      </Card>

      {/* Security Features */}
      <Card>
        <CardHeader>
          <CardTitle>Security Features</CardTitle>
          <CardDescription>Built-in security measures and best practices</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="font-semibold mb-2">Password Security</h4>
              <ul className="space-y-1 text-sm text-muted-foreground">
                <li>• Argon2id hashing (industry standard)</li>
                <li>• Configurable password policy</li>
                <li>• Minimum length: 8 characters</li>
                <li>• Requires uppercase, lowercase, numbers, symbols</li>
              </ul>
            </div>

            <div>
              <h4 className="font-semibold mb-2">Token Management</h4>
              <ul className="space-y-1 text-sm text-muted-foreground">
                <li>• Short-lived access tokens (15 min)</li>
                <li>• Rotating refresh tokens (30 days)</li>
                <li>• httpOnly secure cookies</li>
                <li>• Token introspection for services</li>
              </ul>
            </div>

            <div>
              <h4 className="font-semibold mb-2">Rate Limiting</h4>
              <ul className="space-y-1 text-sm text-muted-foreground">
                <li>• Login attempts: 5 per minute</li>
                <li>• Signup requests: 3 per minute</li>
                <li>• OTP requests: 3 per minute</li>
                <li>• Redis-based tracking</li>
              </ul>
            </div>

            <div>
              <h4 className="font-semibold mb-2">Audit & Monitoring</h4>
              <ul className="space-y-1 text-sm text-muted-foreground">
                <li>• Complete audit trail</li>
                <li>• Login attempt logging</li>
                <li>• Admin action tracking</li>
                <li>• IP address recording</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Setup Instructions */}
      <Card>
        <CardHeader>
          <CardTitle>Setup Instructions</CardTitle>
          <CardDescription>How to run and configure the authentication service</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <h4 className="font-semibold mb-2">1. Backend Setup</h4>
              <div className="relative">
                <Button
                  size="sm"
                  variant="outline"
                  className="absolute top-2 right-2 z-10"
                  onClick={() => copyToClipboard(`cd auth-service
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000`)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
                <pre className="bg-muted p-4 rounded-lg text-sm">
                  <code>{`cd auth-service
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000`}</code>
                </pre>
              </div>
            </div>

            <div>
              <h4 className="font-semibold mb-2">2. Environment Variables</h4>
              <div className="relative">
                <Button
                  size="sm"
                  variant="outline"
                  className="absolute top-2 right-2 z-10"
                  onClick={() => copyToClipboard(`DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/auth_db
REDIS_URL=redis://localhost:6379
SECRET_KEY=your-secret-key-change-in-production
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-client-secret
AZURE_TENANT_ID=your-azure-tenant-id`)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
                <pre className="bg-muted p-4 rounded-lg text-sm">
                  <code>{`DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/auth_db
REDIS_URL=redis://localhost:6379
SECRET_KEY=your-secret-key-change-in-production
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-client-secret
AZURE_TENANT_ID=your-azure-tenant-id`}</code>
                </pre>
              </div>
            </div>

            <div>
              <h4 className="font-semibold mb-2">3. Database Migration</h4>
              <div className="relative">
                <Button
                  size="sm"
                  variant="outline"
                  className="absolute top-2 right-2 z-10"
                  onClick={() => copyToClipboard(`cd auth-service
alembic upgrade head`)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
                <pre className="bg-muted p-4 rounded-lg text-sm">
                  <code>{`cd auth-service
alembic upgrade head`}</code>
                </pre>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}