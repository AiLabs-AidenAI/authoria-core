/**
 * Authentication Provider Configuration Form
 */

import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Plus, X } from 'lucide-react';

const providerSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100),
  displayName: z.string().min(1, 'Display name is required').max(200),
  providerType: z.enum(['oauth2', 'oidc', 'saml']),
  clientId: z.string().optional(),
  clientSecret: z.string().optional(),
  authorizationUrl: z.string().url().optional().or(z.literal('')),
  tokenUrl: z.string().url().optional().or(z.literal('')),
  userinfoUrl: z.string().url().optional().or(z.literal('')),
  scope: z.string().default('openid profile email'),
  entityId: z.string().optional(),
  ssoUrl: z.string().url().optional().or(z.literal('')),
  x509Cert: z.string().optional(),
  autoApproveDomains: z.array(z.string()),
  requireEmailVerification: z.boolean().default(true),
  enabled: z.boolean().default(false),
  iconUrl: z.string().url().optional().or(z.literal('')),
  description: z.string().optional(),
});

type ProviderFormData = z.infer<typeof providerSchema>;

interface ProviderConfigFormProps {
  initialData?: Partial<ProviderFormData>;
  onSubmit: (data: ProviderFormData) => void;
  onCancel: () => void;
  isLoading?: boolean;
}

const ProviderConfigForm: React.FC<ProviderConfigFormProps> = ({
  initialData,
  onSubmit,
  onCancel,
  isLoading = false
}) => {
  const [domainInput, setDomainInput] = useState('');
  
  const form = useForm<ProviderFormData>({
    resolver: zodResolver(providerSchema),
    defaultValues: {
      name: '',
      displayName: '',
      providerType: 'oauth2',
      scope: 'openid profile email',
      autoApproveDomains: [],
      requireEmailVerification: true,
      enabled: false,
      ...initialData,
    },
  });

  const providerType = form.watch('providerType');
  const autoApproveDomains = form.watch('autoApproveDomains');

  const addDomain = () => {
    if (domainInput.trim() && !autoApproveDomains.includes(domainInput.trim())) {
      form.setValue('autoApproveDomains', [...autoApproveDomains, domainInput.trim()]);
      setDomainInput('');
    }
  };

  const removeDomain = (domain: string) => {
    form.setValue('autoApproveDomains', autoApproveDomains.filter(d => d !== domain));
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addDomain();
    }
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <div className="grid grid-cols-2 gap-4">
          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Provider Name</FormLabel>
                <FormControl>
                  <Input placeholder="google" {...field} />
                </FormControl>
                <FormDescription>
                  Unique identifier for this provider (lowercase, no spaces)
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="displayName"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Display Name</FormLabel>
                <FormControl>
                  <Input placeholder="Google OAuth" {...field} />
                </FormControl>
                <FormDescription>
                  Human-readable name shown to users
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="providerType"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Provider Type</FormLabel>
              <Select onValueChange={field.onChange} defaultValue={field.value}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Select provider type" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="oauth2">OAuth 2.0</SelectItem>
                  <SelectItem value="oidc">OpenID Connect</SelectItem>
                  <SelectItem value="saml">SAML 2.0</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />

        {(providerType === 'oauth2' || providerType === 'oidc') && (
          <Card>
            <CardHeader>
              <CardTitle>OAuth Configuration</CardTitle>
              <CardDescription>Configure OAuth 2.0 / OpenID Connect settings</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="clientId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Client ID</FormLabel>
                      <FormControl>
                        <Input placeholder="your-client-id" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="clientSecret"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Client Secret</FormLabel>
                      <FormControl>
                        <Input type="password" placeholder="your-client-secret" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <FormField
                control={form.control}
                name="authorizationUrl"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Authorization URL</FormLabel>
                    <FormControl>
                      <Input placeholder="https://provider.com/oauth/authorize" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="tokenUrl"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Token URL</FormLabel>
                      <FormControl>
                        <Input placeholder="https://provider.com/oauth/token" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="userinfoUrl"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>User Info URL</FormLabel>
                      <FormControl>
                        <Input placeholder="https://provider.com/oauth/userinfo" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <FormField
                control={form.control}
                name="scope"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Scopes</FormLabel>
                    <FormControl>
                      <Input placeholder="openid profile email" {...field} />
                    </FormControl>
                    <FormDescription>
                      Space-separated list of OAuth scopes to request
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </CardContent>
          </Card>
        )}

        {providerType === 'saml' && (
          <Card>
            <CardHeader>
              <CardTitle>SAML Configuration</CardTitle>
              <CardDescription>Configure SAML 2.0 settings</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <FormField
                control={form.control}
                name="entityId"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Entity ID</FormLabel>
                    <FormControl>
                      <Input placeholder="https://provider.com/saml/metadata" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="ssoUrl"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>SSO URL</FormLabel>
                    <FormControl>
                      <Input placeholder="https://provider.com/saml/sso" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="x509Cert"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>X.509 Certificate</FormLabel>
                    <FormControl>
                      <Textarea
                        placeholder="-----BEGIN CERTIFICATE-----
MIIDBjCCAe4CCQDr..."
                        className="font-mono text-sm"
                        rows={6}
                        {...field}
                      />
                    </FormControl>
                    <FormDescription>
                      The public certificate used to verify SAML responses
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle>Auto-approve Domains</CardTitle>
            <CardDescription>
              Users from these domains will be automatically approved
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex space-x-2 mb-3">
              <Input
                placeholder="company.com"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                onKeyPress={handleKeyPress}
              />
              <Button type="button" onClick={addDomain} variant="outline">
                <Plus className="h-4 w-4" />
              </Button>
            </div>
            
            {autoApproveDomains.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {autoApproveDomains.map((domain) => (
                  <Badge key={domain} variant="secondary" className="flex items-center space-x-1">
                    <span>{domain}</span>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-auto p-0 ml-1"
                      onClick={() => removeDomain(domain)}
                    >
                      <X className="h-3 w-3" />
                    </Button>
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Additional Settings</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="iconUrl"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Icon URL</FormLabel>
                    <FormControl>
                      <Input placeholder="https://provider.com/icon.png" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="space-y-3">
                <FormField
                  control={form.control}
                  name="requireEmailVerification"
                  render={({ field }) => (
                    <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3">
                      <div className="space-y-0.5">
                        <FormLabel>Require Email Verification</FormLabel>
                        <FormDescription className="text-sm">
                          Require users to verify their email address
                        </FormDescription>
                      </div>
                      <FormControl>
                        <Switch
                          checked={field.value}
                          onCheckedChange={field.onChange}
                        />
                      </FormControl>
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="enabled"
                  render={({ field }) => (
                    <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3">
                      <div className="space-y-0.5">
                        <FormLabel>Enabled</FormLabel>
                        <FormDescription className="text-sm">
                          Allow users to authenticate with this provider
                        </FormDescription>
                      </div>
                      <FormControl>
                        <Switch
                          checked={field.value}
                          onCheckedChange={field.onChange}
                        />
                      </FormControl>
                    </FormItem>
                  )}
                />
              </div>
            </div>

            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Description</FormLabel>
                  <FormControl>
                    <Textarea
                      placeholder="Description shown to users..."
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </CardContent>
        </Card>

        <Separator />

        <div className="flex justify-end space-x-2">
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
          <Button type="submit" disabled={isLoading}>
            {isLoading ? 'Saving...' : 'Save Provider'}
          </Button>
        </div>
      </form>
    </Form>
  );
};

export default ProviderConfigForm;