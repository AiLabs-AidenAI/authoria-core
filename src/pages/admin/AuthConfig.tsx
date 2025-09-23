/**
 * Authentication Configuration Page
 */

import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { toast } from '@/hooks/use-toast';
import { Plus, Settings, Shield, Mail, Users, Key, Trash2, Copy, Eye, EyeOff } from 'lucide-react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';

interface AuthProvider {
  id: string;
  name: string;
  displayName: string;
  providerType: string;
  clientId?: string;
  clientSecret?: string;
  authorizationUrl?: string;
  tokenUrl?: string;
  userinfoUrl?: string;
  scope: string;
  autoApproveDomains: string[];
  requireEmailVerification: boolean;
  enabled: boolean;
  iconUrl?: string;
  description?: string;
}

interface SMTPConfig {
  id: string;
  name: string;
  host: string;
  port: number;
  username?: string;
  password?: string;
  useTls: boolean;
  useSsl: boolean;
  fromEmail: string;
  fromName?: string;
  replyTo?: string;
  maxEmailsPerHour: number;
  enabled: boolean;
  isDefault: boolean;
}

interface ClientApplication {
  id: string;
  name: string;
  description?: string;
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  allowedOrigins: string[];
  allowedScopes: string[];
  allowedGrantTypes: string[];
  enabled: boolean;
  logoUrl?: string;
  websiteUrl?: string;
  contactEmail?: string;
}

import { AppLayout } from '@/components/Layout/AppLayout';

const AuthConfig: React.FC = () => {
  const [activeTab, setActiveTab] = useState('providers');
  const [showPassword, setShowPassword] = useState<{[key: string]: boolean}>({});
  const [newProviderOpen, setNewProviderOpen] = useState(false);
  const [newSMTPOpen, setNewSMTPOpen] = useState(false);
  const [newClientOpen, setNewClientOpen] = useState(false);

  // Mock data - replace with actual API calls
  const [authProviders, setAuthProviders] = useState<AuthProvider[]>([
    {
      id: '1',
      name: 'google',
      displayName: 'Google OAuth',
      providerType: 'oauth2',
      clientId: 'your-google-client-id',
      clientSecret: 'your-google-client-secret',
      authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUrl: 'https://oauth2.googleapis.com/token',
      userinfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
      scope: 'openid profile email',
      autoApproveDomains: ['company.com'],
      requireEmailVerification: true,
      enabled: true,
      iconUrl: 'https://developers.google.com/identity/images/g-logo.png',
      description: 'Sign in with Google account'
    }
  ]);

  const [smtpConfigs, setSMTPConfigs] = useState<SMTPConfig[]>([
    {
      id: '1',
      name: 'Primary SMTP',
      host: 'smtp.gmail.com',
      port: 587,
      username: 'auth@company.com',
      password: 'app-password',
      useTls: true,
      useSsl: false,
      fromEmail: 'auth@company.com',
      fromName: 'Auth Service',
      replyTo: 'noreply@company.com',
      maxEmailsPerHour: 100,
      enabled: true,
      isDefault: true
    }
  ]);

  const [clientApps, setClientApps] = useState<ClientApplication[]>([
    {
      id: '1',
      name: 'Web Application',
      description: 'Main web application',
      clientId: 'client_web_app_123',
      clientSecret: 'secret_456',
      redirectUris: ['https://app.company.com/auth/callback'],
      allowedOrigins: ['https://app.company.com'],
      allowedScopes: ['openid', 'profile', 'email'],
      allowedGrantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      logoUrl: 'https://app.company.com/logo.png',
      websiteUrl: 'https://app.company.com',
      contactEmail: 'admin@company.com'
    }
  ])

  const togglePasswordVisibility = (id: string) => {
    setShowPassword(prev => ({...prev, [id]: !prev[id]}));
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to clipboard",
      description: "Value has been copied to your clipboard."
    });
  };

  const ProviderCard = ({ provider }: { provider: AuthProvider }) => (
    <Card className="mb-4">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {provider.iconUrl && (
              <img src={provider.iconUrl} alt={provider.displayName} className="w-8 h-8" />
            )}
            <div>
              <CardTitle className="text-lg">{provider.displayName}</CardTitle>
              <CardDescription>{provider.description}</CardDescription>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <Badge variant={provider.enabled ? "default" : "secondary"}>
              {provider.enabled ? "Enabled" : "Disabled"}
            </Badge>
            <Badge variant="outline">{provider.providerType}</Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label className="text-sm font-medium">Client ID</Label>
            <div className="flex items-center space-x-2 mt-1">
              <Input 
                value={provider.clientId || ''} 
                readOnly 
                className="font-mono text-sm"
              />
              <Button 
                size="sm" 
                variant="outline"
                onClick={() => copyToClipboard(provider.clientId || '')}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
          
          <div>
            <Label className="text-sm font-medium">Client Secret</Label>
            <div className="flex items-center space-x-2 mt-1">
              <Input 
                type={showPassword[provider.id] ? "text" : "password"}
                value={provider.clientSecret || ''} 
                readOnly 
                className="font-mono text-sm"
              />
              <Button 
                size="sm" 
                variant="outline"
                onClick={() => togglePasswordVisibility(provider.id)}
              >
                {showPassword[provider.id] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </Button>
              <Button 
                size="sm" 
                variant="outline"
                onClick={() => copyToClipboard(provider.clientSecret || '')}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
          
          <div>
            <Label className="text-sm font-medium">Authorization URL</Label>
            <Input 
              value={provider.authorizationUrl || ''} 
              readOnly 
              className="font-mono text-sm mt-1"
            />
          </div>
          
          <div>
            <Label className="text-sm font-medium">Token URL</Label>
            <Input 
              value={provider.tokenUrl || ''} 
              readOnly 
              className="font-mono text-sm mt-1"
            />
          </div>
          
          <div>
            <Label className="text-sm font-medium">Scope</Label>
            <Input 
              value={provider.scope} 
              readOnly 
              className="font-mono text-sm mt-1"
            />
          </div>
          
          <div>
            <Label className="text-sm font-medium">Auto-approve Domains</Label>
            <div className="flex flex-wrap gap-1 mt-1">
              {provider.autoApproveDomains.map(domain => (
                <Badge key={domain} variant="secondary" className="text-xs">
                  {domain}
                </Badge>
              ))}
            </div>
          </div>
        </div>
        
        <div className="flex items-center justify-between mt-4 pt-4 border-t">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Switch checked={provider.enabled} />
              <Label className="text-sm">Enabled</Label>
            </div>
            <div className="flex items-center space-x-2">
              <Switch checked={provider.requireEmailVerification} />
              <Label className="text-sm">Require Email Verification</Label>
            </div>
          </div>
          <div className="flex space-x-2">
            <Button variant="outline" size="sm">
              <Settings className="h-4 w-4 mr-1" />
              Configure
            </Button>
            <Button variant="destructive" size="sm">
              <Trash2 className="h-4 w-4 mr-1" />
              Delete
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );

  const SMTPCard = ({ config }: { config: SMTPConfig }) => (
    <Card className="mb-4">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-lg">{config.name}</CardTitle>
            <CardDescription>SMTP Configuration</CardDescription>
          </div>
          <div className="flex items-center space-x-2">
            <Badge variant={config.enabled ? "default" : "secondary"}>
              {config.enabled ? "Enabled" : "Disabled"}
            </Badge>
            {config.isDefault && (
              <Badge variant="outline">Default</Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label className="text-sm font-medium">Host</Label>
            <Input value={config.host} readOnly className="mt-1" />
          </div>
          <div>
            <Label className="text-sm font-medium">Port</Label>
            <Input value={config.port.toString()} readOnly className="mt-1" />
          </div>
          <div>
            <Label className="text-sm font-medium">Username</Label>
            <Input value={config.username || ''} readOnly className="mt-1" />
          </div>
          <div>
            <Label className="text-sm font-medium">From Email</Label>
            <Input value={config.fromEmail} readOnly className="mt-1" />
          </div>
        </div>
        
        <div className="flex items-center justify-between mt-4 pt-4 border-t">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Switch checked={config.enabled} />
              <Label className="text-sm">Enabled</Label>
            </div>
            <div className="flex items-center space-x-2">
              <Switch checked={config.useTls} />
              <Label className="text-sm">Use TLS</Label>
            </div>
            <div className="flex items-center space-x-2">
              <Switch checked={config.isDefault} />
              <Label className="text-sm">Default</Label>
            </div>
          </div>
          <div className="flex space-x-2">
            <Button variant="outline" size="sm">
              <Settings className="h-4 w-4 mr-1" />
              Configure
            </Button>
            <Button variant="destructive" size="sm">
              <Trash2 className="h-4 w-4 mr-1" />
              Delete
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );

  const ClientCard = ({ client }: { client: ClientApplication }) => (
    <Card className="mb-4">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {client.logoUrl && (
              <img src={client.logoUrl} alt={client.name} className="w-8 h-8" />
            )}
            <div>
              <CardTitle className="text-lg">{client.name}</CardTitle>
              <CardDescription>{client.description}</CardDescription>
            </div>
          </div>
          <Badge variant={client.enabled ? "default" : "secondary"}>
            {client.enabled ? "Enabled" : "Disabled"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label className="text-sm font-medium">Client ID</Label>
            <div className="flex items-center space-x-2 mt-1">
              <Input value={client.clientId} readOnly className="font-mono text-sm" />
              <Button 
                size="sm" 
                variant="outline"
                onClick={() => copyToClipboard(client.clientId)}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
          
          <div>
            <Label className="text-sm font-medium">Client Secret</Label>
            <div className="flex items-center space-x-2 mt-1">
              <Input 
                type={showPassword[client.id] ? "text" : "password"}
                value={client.clientSecret} 
                readOnly 
                className="font-mono text-sm"
              />
              <Button 
                size="sm" 
                variant="outline"
                onClick={() => togglePasswordVisibility(client.id)}
              >
                {showPassword[client.id] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </Button>
              <Button 
                size="sm" 
                variant="outline"
                onClick={() => copyToClipboard(client.clientSecret)}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
          
          <div className="col-span-2">
            <Label className="text-sm font-medium">Redirect URIs</Label>
            <div className="flex flex-wrap gap-1 mt-1">
              {client.redirectUris.map((uri, index) => (
                <Badge key={index} variant="secondary" className="text-xs font-mono">
                  {uri}
                </Badge>
              ))}
            </div>
          </div>
          
          <div>
            <Label className="text-sm font-medium">Allowed Scopes</Label>
            <div className="flex flex-wrap gap-1 mt-1">
              {client.allowedScopes.map(scope => (
                <Badge key={scope} variant="outline" className="text-xs">
                  {scope}
                </Badge>
              ))}
            </div>
          </div>
          
          <div>
            <Label className="text-sm font-medium">Grant Types</Label>
            <div className="flex flex-wrap gap-1 mt-1">
              {client.allowedGrantTypes.map(type => (
                <Badge key={type} variant="outline" className="text-xs">
                  {type}
                </Badge>
              ))}
            </div>
          </div>
        </div>
        
        <div className="flex items-center justify-between mt-4 pt-4 border-t">
          <div className="flex items-center space-x-2">
            <Switch checked={client.enabled} />
            <Label className="text-sm">Enabled</Label>
          </div>
          <div className="flex space-x-2">
            <Button variant="outline" size="sm">
              <Key className="h-4 w-4 mr-1" />
              Regenerate Secret
            </Button>
            <Button variant="outline" size="sm">
              <Settings className="h-4 w-4 mr-1" />
              Configure
            </Button>
            <Button variant="destructive" size="sm">
              <Trash2 className="h-4 w-4 mr-1" />
              Delete
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <AppLayout>
      <div className="container mx-auto p-6 max-w-6xl">
        <div className="mb-6">
          <h1 className="text-3xl font-bold">Authentication Configuration</h1>
          <p className="text-muted-foreground">
            Configure SSO providers, SMTP settings, and client applications for your authentication service.
          </p>
        </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="providers" className="flex items-center space-x-2">
            <Shield className="h-4 w-4" />
            <span>SSO Providers</span>
          </TabsTrigger>
          <TabsTrigger value="smtp" className="flex items-center space-x-2">
            <Mail className="h-4 w-4" />
            <span>SMTP Config</span>
          </TabsTrigger>
          <TabsTrigger value="clients" className="flex items-center space-x-2">
            <Users className="h-4 w-4" />
            <span>Client Apps</span>
          </TabsTrigger>
          <TabsTrigger value="settings" className="flex items-center space-x-2">
            <Settings className="h-4 w-4" />
            <span>Settings</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="providers" className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-semibold">SSO Providers</h2>
              <p className="text-muted-foreground">Configure OAuth and SAML providers</p>
            </div>
            <Dialog open={newProviderOpen} onOpenChange={setNewProviderOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Add Provider
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>Add SSO Provider</DialogTitle>
                  <DialogDescription>
                    Configure a new OAuth2, OIDC, or SAML provider
                  </DialogDescription>
                </DialogHeader>
                {/* Add provider form would go here */}
                <DialogFooter>
                  <Button variant="outline" onClick={() => setNewProviderOpen(false)}>
                    Cancel
                  </Button>
                  <Button>Add Provider</Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>

          <div className="space-y-4">
            {authProviders.map(provider => (
              <ProviderCard key={provider.id} provider={provider} />
            ))}
          </div>
        </TabsContent>

        <TabsContent value="smtp" className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-semibold">SMTP Configuration</h2>
              <p className="text-muted-foreground">Configure email sending settings</p>
            </div>
            <Dialog open={newSMTPOpen} onOpenChange={setNewSMTPOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Add SMTP Config
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>Add SMTP Configuration</DialogTitle>
                  <DialogDescription>
                    Configure a new SMTP server for sending emails
                  </DialogDescription>
                </DialogHeader>
                {/* Add SMTP form would go here */}
                <DialogFooter>
                  <Button variant="outline" onClick={() => setNewSMTPOpen(false)}>
                    Cancel
                  </Button>
                  <Button>Add Configuration</Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>

          <div className="space-y-4">
            {smtpConfigs.map(config => (
              <SMTPCard key={config.id} config={config} />
            ))}
          </div>
        </TabsContent>

        <TabsContent value="clients" className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-semibold">Client Applications</h2>
              <p className="text-muted-foreground">Applications that consume this auth service</p>
            </div>
            <Dialog open={newClientOpen} onOpenChange={setNewClientOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Add Client App
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>Add Client Application</DialogTitle>
                  <DialogDescription>
                    Register a new application to use this auth service
                  </DialogDescription>
                </DialogHeader>
                {/* Add client form would go here */}
                <DialogFooter>
                  <Button variant="outline" onClick={() => setNewClientOpen(false)}>
                    Cancel
                  </Button>
                  <Button>Add Application</Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>

          <div className="space-y-4">
            {clientApps.map(client => (
              <ClientCard key={client.id} client={client} />
            ))}
          </div>
        </TabsContent>

        <TabsContent value="settings" className="space-y-6">
          <div>
            <h2 className="text-2xl font-semibold">General Settings</h2>
            <p className="text-muted-foreground">Configure authentication policies and security settings</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Token Settings</CardTitle>
                <CardDescription>Configure JWT token lifetimes</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label>Access Token Lifetime (minutes)</Label>
                  <Input type="number" defaultValue="15" className="mt-1" />
                </div>
                <div>
                  <Label>Refresh Token Lifetime (days)</Label>
                  <Input type="number" defaultValue="30" className="mt-1" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Password Policy</CardTitle>
                <CardDescription>Configure password requirements</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label>Minimum Length</Label>
                  <Input type="number" defaultValue="8" className="mt-1" />
                </div>
                <div className="space-y-3">
                  <div className="flex items-center space-x-2">
                    <Switch defaultChecked />
                    <Label>Require Uppercase</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Switch defaultChecked />
                    <Label>Require Numbers</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Switch defaultChecked />
                    <Label>Require Special Characters</Label>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Rate Limiting</CardTitle>
                <CardDescription>Configure rate limits for auth endpoints</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label>Login Attempts (per minute)</Label>
                  <Input type="number" defaultValue="5" className="mt-1" />
                </div>
                <div>
                  <Label>Signup Requests (per minute)</Label>
                  <Input type="number" defaultValue="3" className="mt-1" />
                </div>
                <div>
                  <Label>OTP Requests (per minute)</Label>
                  <Input type="number" defaultValue="3" className="mt-1" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Approval Settings</CardTitle>
                <CardDescription>Configure user approval workflow</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center space-x-2">
                  <Switch defaultChecked />
                  <Label>Require Admin Approval</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch />
                  <Label>Auto-approve Verified Emails</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch />
                  <Label>Enable MFA for Admins</Label>
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="flex justify-end">
            <Button>Save Settings</Button>
          </div>
        </TabsContent>
      </Tabs>
      </div>
    </AppLayout>
  );
};

export default AuthConfig;