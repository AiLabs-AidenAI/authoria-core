/**
 * Authentication Configuration Page
 */

import React, { useState, useEffect } from 'react';
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
import { Plus, Settings, Shield, Mail, Users, Key, Trash2, Copy, Eye, EyeOff, Building2 } from 'lucide-react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { AppLayout } from '@/components/Layout/AppLayout';
import { authAPI } from '@/lib/api-client';

interface AuthProvider {
  id: string;
  name: string;
  display_name: string;
  provider_type: string;
  client_id?: string;
  client_secret?: string;
  authorization_url?: string;
  token_url?: string;
  userinfo_url?: string;
  scope: string;
  auto_approve_domains: string[];
  require_email_verification: boolean;
  enabled: boolean;
  icon_url?: string;
  description?: string;
}

interface SMTPConfig {
  id: string;
  name: string;
  host: string;
  port: number;
  username?: string;
  password?: string;
  use_tls: boolean;
  use_ssl: boolean;
  from_email: string;
  from_name?: string;
  reply_to?: string;
  max_emails_per_hour: number;
  enabled: boolean;
  is_default: boolean;
}

interface ClientApplication {
  id: string;
  name: string;
  description?: string;
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  allowed_origins: string[];
  allowed_scopes: string[];
  allowed_grant_types: string[];
  enabled: boolean;
  logo_url?: string;
  website_url?: string;
  contact_email?: string;
}

const AuthConfig: React.FC = () => {
  const [activeTab, setActiveTab] = useState('providers');
  const [showPassword, setShowPassword] = useState<{[key: string]: boolean}>({});
  const [newProviderOpen, setNewProviderOpen] = useState(false);
  const [newSMTPOpen, setNewSMTPOpen] = useState(false);
  const [newClientOpen, setNewClientOpen] = useState(false);
  const [loading, setLoading] = useState(true);

  // State for actual data from API
  const [authProviders, setAuthProviders] = useState<AuthProvider[]>([]);
  const [smtpConfigs, setSMTPConfigs] = useState<SMTPConfig[]>([]);
  const [clientApps, setClientApps] = useState<ClientApplication[]>([]);
  const [authSettings, setAuthSettings] = useState<any>({});

  // Form states
  const [newProvider, setNewProvider] = useState({
    name: '',
    display_name: '',
    provider_type: 'oauth2',
    client_id: '',
    client_secret: '',
    authorization_url: '',
    token_url: '',
    userinfo_url: '',
    scope: 'openid profile email',
    auto_approve_domains: '',
    require_email_verification: true,
    enabled: false,
    icon_url: '',
    description: ''
  });

  const [newSMTP, setNewSMTP] = useState({
    name: '',
    host: '',
    port: 587,
    username: '',
    password: '',
    use_tls: true,
    use_ssl: false,
    from_email: '',
    from_name: '',
    reply_to: '',
    max_emails_per_hour: 100,
    enabled: false,
    is_default: false
  });

  const [newClient, setNewClient] = useState({
    name: '',
    description: '',
    redirect_uris: '',
    allowed_origins: '',
    allowed_scopes: 'openid,profile,email',
    allowed_grant_types: 'authorization_code,refresh_token',
    enabled: true,
    logo_url: '',
    website_url: '',
    contact_email: ''
  });

  // Load data on component mount
  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [providers, smtp, clients, settings] = await Promise.all([
        authAPI.getAuthProviders(),
        authAPI.getSMTPConfigs(),
        authAPI.getClientApplications(),
        authAPI.getAuthSettings()
      ]);

      setAuthProviders(providers);
      setSMTPConfigs(smtp);
      setClientApps(clients);
      setAuthSettings(settings);

      // If no Microsoft provider exists, create one as default
      const hasAzure = providers.some(p => p.provider_type === 'azure');
      if (!hasAzure) {
        await createDefaultAzureProvider();
      }
    } catch (error) {
      console.error('Failed to load config data:', error);
      toast({
        title: "Error",
        description: "Failed to load configuration data",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const createDefaultAzureProvider = async () => {
    const azureProvider = {
      name: 'azure',
      display_name: 'Microsoft Azure AD',
      provider_type: 'azure',
      client_id: '',
      client_secret: '',
      authorization_url: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      token_url: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
      userinfo_url: 'https://graph.microsoft.com/v1.0/me',
      scope: 'openid profile email',
      auto_approve_domains: [],
      require_email_verification: true,
      enabled: false,
      icon_url: 'https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg',
      description: 'Sign in with Microsoft Azure AD'
    };

    try {
      const created = await authAPI.createAuthProvider(azureProvider);
      setAuthProviders(prev => [...prev, created]);
      toast({
        title: "Microsoft SSO Added",
        description: "Microsoft Azure AD provider has been configured as the main SSO option",
      });
    } catch (error) {
      console.error('Failed to create Azure provider:', error);
    }
  };

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

  const handleCreateProvider = async () => {
    try {
      const providerData = {
        ...newProvider,
        auto_approve_domains: newProvider.auto_approve_domains.split(',').map(d => d.trim()).filter(d => d)
      };
      
      const created = await authAPI.createAuthProvider(providerData);
      setAuthProviders(prev => [...prev, created]);
      setNewProviderOpen(false);
      setNewProvider({
        name: '',
        display_name: '',
        provider_type: 'oauth2',
        client_id: '',
        client_secret: '',
        authorization_url: '',
        token_url: '',
        userinfo_url: '',
        scope: 'openid profile email',
        auto_approve_domains: '',
        require_email_verification: true,
        enabled: false,
        icon_url: '',
        description: ''
      });
      
      toast({
        title: "Provider created",
        description: "New authentication provider has been created successfully."
      });
    } catch (error) {
      console.error('Failed to create provider:', error);
      toast({
        title: "Error",
        description: "Failed to create provider",
        variant: "destructive"
      });
    }
  };

  const handleCreateSMTP = async () => {
    try {
      const created = await authAPI.createSMTPConfig(newSMTP);
      setSMTPConfigs(prev => [...prev, created]);
      setNewSMTPOpen(false);
      setNewSMTP({
        name: '',
        host: '',
        port: 587,
        username: '',
        password: '',
        use_tls: true,
        use_ssl: false,
        from_email: '',
        from_name: '',
        reply_to: '',
        max_emails_per_hour: 100,
        enabled: false,
        is_default: false
      });
      
      toast({
        title: "SMTP Config created",
        description: "New SMTP configuration has been created successfully."
      });
    } catch (error) {
      console.error('Failed to create SMTP config:', error);
      toast({
        title: "Error",
        description: "Failed to create SMTP configuration",
        variant: "destructive"
      });
    }
  };

  const handleCreateClient = async () => {
    try {
      const clientData = {
        ...newClient,
        redirect_uris: newClient.redirect_uris.split(',').map(u => u.trim()).filter(u => u),
        allowed_origins: newClient.allowed_origins.split(',').map(o => o.trim()).filter(o => o),
        allowed_scopes: newClient.allowed_scopes.split(',').map(s => s.trim()).filter(s => s),
        allowed_grant_types: newClient.allowed_grant_types.split(',').map(g => g.trim()).filter(g => g)
      };
      
      const created = await authAPI.createClientApplication(clientData);
      setClientApps(prev => [...prev, created]);
      setNewClientOpen(false);
      setNewClient({
        name: '',
        description: '',
        redirect_uris: '',
        allowed_origins: '',
        allowed_scopes: 'openid,profile,email',
        allowed_grant_types: 'authorization_code,refresh_token',
        enabled: true,
        logo_url: '',
        website_url: '',
        contact_email: ''
      });
      
      toast({
        title: "Client App created",
        description: "New client application has been created successfully."
      });
    } catch (error) {
      console.error('Failed to create client app:', error);
      toast({
        title: "Error",
        description: "Failed to create client application",
        variant: "destructive"
      });
    }
  };

  const handleDeleteProvider = async (id: string) => {
    try {
      await authAPI.deleteAuthProvider(id);
      setAuthProviders(prev => prev.filter(p => p.id !== id));
      toast({
        title: "Provider deleted",
        description: "Authentication provider has been deleted successfully."
      });
    } catch (error) {
      console.error('Failed to delete provider:', error);
      toast({
        title: "Error",
        description: "Failed to delete provider",
        variant: "destructive"
      });
    }
  };

  const handleDeleteSMTP = async (id: string) => {
    try {
      await authAPI.deleteSMTPConfig(id);
      setSMTPConfigs(prev => prev.filter(s => s.id !== id));
      toast({
        title: "SMTP Config deleted",
        description: "SMTP configuration has been deleted successfully."
      });
    } catch (error) {
      console.error('Failed to delete SMTP config:', error);
      toast({
        title: "Error",
        description: "Failed to delete SMTP configuration",
        variant: "destructive"
      });
    }
  };

  const handleDeleteClient = async (id: string) => {
    try {
      await authAPI.deleteClientApplication(id);
      setClientApps(prev => prev.filter(c => c.id !== id));
      toast({
        title: "Client App deleted",
        description: "Client application has been deleted successfully."
      });
    } catch (error) {
      console.error('Failed to delete client app:', error);
      toast({
        title: "Error",
        description: "Failed to delete client application",
        variant: "destructive"
      });
    }
  };

  const ProviderCard = ({ provider }: { provider: AuthProvider }) => (
    <Card className="mb-4">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {provider.provider_type === 'azure' && (
              <Building2 className="w-8 h-8 text-blue-600" />
            )}
            {provider.icon_url && provider.provider_type !== 'azure' && (
              <img src={provider.icon_url} alt={provider.display_name} className="w-8 h-8" />
            )}
            <div>
              <CardTitle className="text-lg flex items-center gap-2">
                {provider.display_name}
                {provider.provider_type === 'azure' && (
                  <Badge variant="default" className="bg-blue-600">Main SSO</Badge>
                )}
              </CardTitle>
              <CardDescription>{provider.description}</CardDescription>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <Badge variant={provider.enabled ? "default" : "secondary"}>
              {provider.enabled ? "Enabled" : "Disabled"}
            </Badge>
            <Badge variant="outline">{provider.provider_type}</Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label className="text-sm font-medium">Client ID</Label>
            <div className="flex items-center space-x-2 mt-1">
              <Input 
                value={provider.client_id || ''} 
                readOnly 
                className="font-mono text-sm"
                placeholder="Not configured"
              />
              <Button 
                size="sm" 
                variant="outline"
                onClick={() => copyToClipboard(provider.client_id || '')}
                disabled={!provider.client_id}
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
                value={provider.client_secret ? "••••••••••••••••" : ''} 
                readOnly 
                className="font-mono text-sm"
                placeholder="Not configured"
              />
              <Button 
                size="sm" 
                variant="outline"
                onClick={() => togglePasswordVisibility(provider.id)}
                disabled={!provider.client_secret}
              >
                {showPassword[provider.id] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </Button>
              <Button 
                size="sm" 
                variant="outline"
                onClick={() => copyToClipboard(provider.client_secret || '')}
                disabled={!provider.client_secret}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
          
          <div>
            <Label className="text-sm font-medium">Authorization URL</Label>
            <Input 
              value={provider.authorization_url || ''} 
              readOnly 
              className="font-mono text-sm mt-1"
            />
          </div>
          
          <div>
            <Label className="text-sm font-medium">Token URL</Label>
            <Input 
              value={provider.token_url || ''} 
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
              {provider.auto_approve_domains?.map(domain => (
                <Badge key={domain} variant="secondary" className="text-xs">
                  {domain}
                </Badge>
              )) || <span className="text-sm text-muted-foreground">None configured</span>}
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
              <Switch checked={provider.require_email_verification} />
              <Label className="text-sm">Require Email Verification</Label>
            </div>
          </div>
          <div className="flex space-x-2">
            <Button variant="outline" size="sm">
              <Settings className="h-4 w-4 mr-1" />
              Configure
            </Button>
            <Button variant="destructive" size="sm" onClick={() => handleDeleteProvider(provider.id)}>
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
            {config.is_default && (
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
            <Input value={config.from_email} readOnly className="mt-1" />
          </div>
        </div>
        
        <div className="flex items-center justify-between mt-4 pt-4 border-t">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Switch checked={config.enabled} />
              <Label className="text-sm">Enabled</Label>
            </div>
            <div className="flex items-center space-x-2">
              <Switch checked={config.use_tls} />
              <Label className="text-sm">Use TLS</Label>
            </div>
            <div className="flex items-center space-x-2">
              <Switch checked={config.is_default} />
              <Label className="text-sm">Default</Label>
            </div>
          </div>
          <div className="flex space-x-2">
            <Button variant="outline" size="sm">
              <Settings className="h-4 w-4 mr-1" />
              Configure
            </Button>
            <Button variant="destructive" size="sm" onClick={() => handleDeleteSMTP(config.id)}>
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
            {client.logo_url && (
              <img src={client.logo_url} alt={client.name} className="w-8 h-8" />
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
              <Input value={client.client_id} readOnly className="font-mono text-sm" />
              <Button 
                size="sm" 
                variant="outline"
                onClick={() => copyToClipboard(client.client_id)}
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
                value="••••••••••••••••" 
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
                onClick={() => copyToClipboard(client.client_secret)}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
          
          <div className="col-span-2">
            <Label className="text-sm font-medium">Redirect URIs</Label>
            <div className="flex flex-wrap gap-1 mt-1">
              {client.redirect_uris.map((uri, index) => (
                <Badge key={index} variant="secondary" className="text-xs font-mono">
                  {uri}
                </Badge>
              ))}
            </div>
          </div>
          
          <div>
            <Label className="text-sm font-medium">Allowed Scopes</Label>
            <div className="flex flex-wrap gap-1 mt-1">
              {client.allowed_scopes.map(scope => (
                <Badge key={scope} variant="outline" className="text-xs">
                  {scope}
                </Badge>
              ))}
            </div>
          </div>
          
          <div>
            <Label className="text-sm font-medium">Grant Types</Label>
            <div className="flex flex-wrap gap-1 mt-1">
              {client.allowed_grant_types.map(type => (
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
            <Button variant="destructive" size="sm" onClick={() => handleDeleteClient(client.id)}>
              <Trash2 className="h-4 w-4 mr-1" />
              Delete
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );

  if (loading) {
    return (
      <AppLayout>
        <div className="container mx-auto p-6 max-w-6xl">
          <div className="flex items-center justify-center h-64">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
              <p className="text-muted-foreground">Loading configuration...</p>
            </div>
          </div>
        </div>
      </AppLayout>
    );
  }

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
              <p className="text-muted-foreground">Configure single sign-on authentication providers</p>
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
                    Configure a new single sign-on authentication provider
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="provider-name">Provider Name</Label>
                      <Input
                        id="provider-name"
                        placeholder="e.g. azure, google, github"
                        value={newProvider.name}
                        onChange={(e) => setNewProvider(prev => ({...prev, name: e.target.value}))}
                      />
                    </div>
                    <div>
                      <Label htmlFor="display-name">Display Name</Label>
                      <Input
                        id="display-name"
                        placeholder="e.g. Microsoft Azure AD"
                        value={newProvider.display_name}
                        onChange={(e) => setNewProvider(prev => ({...prev, display_name: e.target.value}))}
                      />
                    </div>
                  </div>
                  
                  <div>
                    <Label htmlFor="provider-type">Provider Type</Label>
                    <Select value={newProvider.provider_type} onValueChange={(value) => setNewProvider(prev => ({...prev, provider_type: value}))}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="oauth2">OAuth 2.0</SelectItem>
                        <SelectItem value="saml">SAML</SelectItem>
                        <SelectItem value="azure">Azure AD</SelectItem>
                        <SelectItem value="google">Google</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="client-id">Client ID</Label>
                      <Input
                        id="client-id"
                        value={newProvider.client_id}
                        onChange={(e) => setNewProvider(prev => ({...prev, client_id: e.target.value}))}
                      />
                    </div>
                    <div>
                      <Label htmlFor="client-secret">Client Secret</Label>
                      <Input
                        id="client-secret"
                        type="password"
                        value={newProvider.client_secret}
                        onChange={(e) => setNewProvider(prev => ({...prev, client_secret: e.target.value}))}
                      />
                    </div>
                  </div>

                  <div>
                    <Label htmlFor="auth-url">Authorization URL</Label>
                    <Input
                      id="auth-url"
                      value={newProvider.authorization_url}
                      onChange={(e) => setNewProvider(prev => ({...prev, authorization_url: e.target.value}))}
                    />
                  </div>

                  <div>
                    <Label htmlFor="token-url">Token URL</Label>
                    <Input
                      id="token-url"
                      value={newProvider.token_url}
                      onChange={(e) => setNewProvider(prev => ({...prev, token_url: e.target.value}))}
                    />
                  </div>

                  <div>
                    <Label htmlFor="scope">Scope</Label>
                    <Input
                      id="scope"
                      value={newProvider.scope}
                      onChange={(e) => setNewProvider(prev => ({...prev, scope: e.target.value}))}
                    />
                  </div>

                  <div>
                    <Label htmlFor="domains">Auto-approve Domains (comma separated)</Label>
                    <Input
                      id="domains"
                      placeholder="company.com, partner.com"
                      value={newProvider.auto_approve_domains}
                      onChange={(e) => setNewProvider(prev => ({...prev, auto_approve_domains: e.target.value}))}
                    />
                  </div>

                  <div className="flex items-center space-x-2">
                    <Switch
                      checked={newProvider.enabled}
                      onCheckedChange={(checked) => setNewProvider(prev => ({...prev, enabled: checked}))}
                    />
                    <Label>Enable provider</Label>
                  </div>
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setNewProviderOpen(false)}>
                    Cancel
                  </Button>
                  <Button onClick={handleCreateProvider}>
                    Create Provider
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>

          <div>
            {authProviders.length === 0 ? (
              <Card>
                <CardContent className="flex items-center justify-center h-32">
                  <p className="text-muted-foreground">No SSO providers configured</p>
                </CardContent>
              </Card>
            ) : (
              authProviders.map(provider => (
                <ProviderCard key={provider.id} provider={provider} />
              ))
            )}
          </div>
        </TabsContent>

        <TabsContent value="smtp" className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-semibold">SMTP Configuration</h2>
              <p className="text-muted-foreground">Configure email server settings for notifications</p>
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
                    Configure email server settings for sending notifications
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div>
                    <Label htmlFor="smtp-name">Configuration Name</Label>
                    <Input
                      id="smtp-name"
                      placeholder="e.g. Primary SMTP"
                      value={newSMTP.name}
                      onChange={(e) => setNewSMTP(prev => ({...prev, name: e.target.value}))}
                    />
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="smtp-host">SMTP Host</Label>
                      <Input
                        id="smtp-host"
                        placeholder="smtp.gmail.com"
                        value={newSMTP.host}
                        onChange={(e) => setNewSMTP(prev => ({...prev, host: e.target.value}))}
                      />
                    </div>
                    <div>
                      <Label htmlFor="smtp-port">Port</Label>
                      <Input
                        id="smtp-port"
                        type="number"
                        value={newSMTP.port}
                        onChange={(e) => setNewSMTP(prev => ({...prev, port: parseInt(e.target.value) || 587}))}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="smtp-username">Username</Label>
                      <Input
                        id="smtp-username"
                        value={newSMTP.username}
                        onChange={(e) => setNewSMTP(prev => ({...prev, username: e.target.value}))}
                      />
                    </div>
                    <div>
                      <Label htmlFor="smtp-password">Password</Label>
                      <Input
                        id="smtp-password"
                        type="password"
                        value={newSMTP.password}
                        onChange={(e) => setNewSMTP(prev => ({...prev, password: e.target.value}))}
                      />
                    </div>
                  </div>

                  <div>
                    <Label htmlFor="from-email">From Email</Label>
                    <Input
                      id="from-email"
                      type="email"
                      placeholder="noreply@company.com"
                      value={newSMTP.from_email}
                      onChange={(e) => setNewSMTP(prev => ({...prev, from_email: e.target.value}))}
                    />
                  </div>

                  <div className="flex items-center space-x-4">
                    <div className="flex items-center space-x-2">
                      <Switch
                        checked={newSMTP.use_tls}
                        onCheckedChange={(checked) => setNewSMTP(prev => ({...prev, use_tls: checked}))}
                      />
                      <Label>Use TLS</Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Switch
                        checked={newSMTP.enabled}
                        onCheckedChange={(checked) => setNewSMTP(prev => ({...prev, enabled: checked}))}
                      />
                      <Label>Enable configuration</Label>
                    </div>
                  </div>
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setNewSMTPOpen(false)}>
                    Cancel
                  </Button>
                  <Button onClick={handleCreateSMTP}>
                    Create Configuration
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>

          <div>
            {smtpConfigs.length === 0 ? (
              <Card>
                <CardContent className="flex items-center justify-center h-32">
                  <p className="text-muted-foreground">No SMTP configurations</p>
                </CardContent>
              </Card>
            ) : (
              smtpConfigs.map(config => (
                <SMTPCard key={config.id} config={config} />
              ))
            )}
          </div>
        </TabsContent>

        <TabsContent value="clients" className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-semibold">Client Applications</h2>
              <p className="text-muted-foreground">Manage applications that can authenticate with this service</p>
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
                    Register a new application that can authenticate with this service
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div>
                    <Label htmlFor="client-name">Application Name</Label>
                    <Input
                      id="client-name"
                      placeholder="My Web Application"
                      value={newClient.name}
                      onChange={(e) => setNewClient(prev => ({...prev, name: e.target.value}))}
                    />
                  </div>
                  
                  <div>
                    <Label htmlFor="client-description">Description</Label>
                    <Textarea
                      id="client-description"
                      placeholder="Brief description of the application"
                      value={newClient.description}
                      onChange={(e) => setNewClient(prev => ({...prev, description: e.target.value}))}
                    />
                  </div>

                  <div>
                    <Label htmlFor="redirect-uris">Redirect URIs (comma separated)</Label>
                    <Input
                      id="redirect-uris"
                      placeholder="https://app.com/auth/callback, https://app.com/login"
                      value={newClient.redirect_uris}
                      onChange={(e) => setNewClient(prev => ({...prev, redirect_uris: e.target.value}))}
                    />
                  </div>

                  <div>
                    <Label htmlFor="origins">Allowed Origins (comma separated)</Label>
                    <Input
                      id="origins"
                      placeholder="https://app.com, https://www.app.com"
                      value={newClient.allowed_origins}
                      onChange={(e) => setNewClient(prev => ({...prev, allowed_origins: e.target.value}))}
                    />
                  </div>

                  <div className="flex items-center space-x-2">
                    <Switch
                      checked={newClient.enabled}
                      onCheckedChange={(checked) => setNewClient(prev => ({...prev, enabled: checked}))}
                    />
                    <Label>Enable application</Label>
                  </div>
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setNewClientOpen(false)}>
                    Cancel
                  </Button>
                  <Button onClick={handleCreateClient}>
                    Create Application
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>

          <div>
            {clientApps.length === 0 ? (
              <Card>
                <CardContent className="flex items-center justify-center h-32">
                  <p className="text-muted-foreground">No client applications configured</p>
                </CardContent>
              </Card>
            ) : (
              clientApps.map(client => (
                <ClientCard key={client.id} client={client} />
              ))
            )}
          </div>
        </TabsContent>

        <TabsContent value="settings" className="space-y-6">
          <div>
            <h2 className="text-2xl font-semibold">Authentication Settings</h2>
            <p className="text-muted-foreground">Configure general authentication and security settings</p>
          </div>

          <div className="grid gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Key className="h-5 w-5" />
                  <span>Token Settings</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Access Token Expiry (minutes)</Label>
                    <Input type="number" value={authSettings.access_token_expire_minutes || 15} />
                  </div>
                  <div>
                    <Label>Refresh Token Expiry (days)</Label>
                    <Input type="number" value={authSettings.refresh_token_expire_days || 30} />
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Shield className="h-5 w-5" />
                  <span>Password Policy</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Minimum Length</Label>
                    <Input type="number" value={authSettings.password_min_length || 8} />
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2">
                      <Switch checked={authSettings.password_require_uppercase || false} />
                      <Label>Require Uppercase</Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Switch checked={authSettings.password_require_numbers || false} />
                      <Label>Require Numbers</Label>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Rate Limiting</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <Label>Login Rate Limit</Label>
                    <Input type="number" value={authSettings.login_rate_limit || 5} />
                  </div>
                  <div>
                    <Label>Signup Rate Limit</Label>
                    <Input type="number" value={authSettings.signup_rate_limit || 3} />
                  </div>
                  <div>
                    <Label>OTP Rate Limit</Label>
                    <Input type="number" value={authSettings.otp_rate_limit || 3} />
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Approval Settings</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center space-x-2">
                  <Switch checked={authSettings.require_admin_approval || false} />
                  <Label>Require Admin Approval for New Users</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch checked={authSettings.auto_approve_verified_emails || true} />
                  <Label>Auto-approve Verified Email Addresses</Label>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
      </div>
    </AppLayout>
  );
};

export default AuthConfig;