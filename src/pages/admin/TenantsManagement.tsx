/**
 * Tenants Management Page
 */

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { toast } from '@/hooks/use-toast';
import { Plus, Building2, Trash2, Edit, Globe } from 'lucide-react';
import { AppLayout } from '@/components/Layout/AppLayout';
import { CreateTenantModal } from '@/components/admin/CreateTenantModal';
import { authAPI } from '@/lib/api-client';

interface Tenant {
  id: string;
  name: string;
  description?: string;
  domain?: string;
  enabled: boolean;
  auto_approve_domains: string[];
  created_at: string;
  updated_at?: string;
}

const TenantsManagement: React.FC = () => {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [createModalOpen, setCreateModalOpen] = useState(false);

  useEffect(() => {
    loadTenants();
  }, []);

  const loadTenants = async () => {
    try {
      setLoading(true);
      const data = await authAPI.getTenants();
      setTenants(data);
    } catch (error) {
      console.error('Failed to load tenants:', error);
      toast({
        title: "Error",
        description: "Failed to load tenants",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteTenant = async (id: string, name: string) => {
    if (!confirm(`Are you sure you want to delete "${name}"?`)) {
      return;
    }

    try {
      await authAPI.deleteTenant(id);
      setTenants(prev => prev.filter(t => t.id !== id));
      toast({
        title: "Tenant deleted",
        description: `${name} has been deleted successfully.`
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to delete tenant",
        variant: "destructive"
      });
    }
  };

  if (loading) {
    return (
      <AppLayout>
        <div className="p-6">
          <div className="animate-pulse">
            <div className="h-8 bg-muted rounded w-64 mb-4"></div>
            <div className="space-y-4">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="h-32 bg-muted rounded"></div>
              ))}
            </div>
          </div>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <div className="p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-3xl font-bold text-foreground">Organizations</h1>
            <p className="text-muted-foreground">
              Manage tenant organizations and their configurations
            </p>
          </div>
          <Button onClick={() => setCreateModalOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            Add Organization
          </Button>
        </div>

        <div className="grid gap-6">
          {tenants.map((tenant) => (
            <Card key={tenant.id}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <Building2 className="h-8 w-8 text-primary" />
                    <div>
                      <CardTitle className="text-lg flex items-center gap-2">
                        {tenant.name}
                        <Badge variant={tenant.enabled ? "default" : "secondary"}>
                          {tenant.enabled ? "Active" : "Disabled"}
                        </Badge>
                        {tenant.id === "1" && (
                          <Badge variant="outline">System Default</Badge>
                        )}
                      </CardTitle>
                      <CardDescription>{tenant.description}</CardDescription>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Button variant="outline" size="sm">
                      <Edit className="h-4 w-4" />
                    </Button>
                    {tenant.id !== "1" && (
                      <Button 
                        variant="outline" 
                        size="sm"
                        onClick={() => handleDeleteTenant(tenant.id, tenant.name)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Primary Domain</label>
                    <div className="flex items-center space-x-2 mt-1">
                      <Globe className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm">
                        {tenant.domain || 'No domain set'}
                      </span>
                    </div>
                  </div>
                  
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Auto-approve Domains</label>
                    <div className="mt-1">
                      {tenant.auto_approve_domains.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {tenant.auto_approve_domains.map((domain, index) => (
                            <Badge key={index} variant="outline" className="text-xs">
                              {domain}
                            </Badge>
                          ))}
                        </div>
                      ) : (
                        <span className="text-sm text-muted-foreground">None configured</span>
                      )}
                    </div>
                  </div>

                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Created</label>
                    <p className="text-sm mt-1">
                      {new Date(tenant.created_at).toLocaleDateString()}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {tenants.length === 0 && !loading && (
          <Card>
            <CardContent className="text-center py-12">
              <Building2 className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-medium mb-2">No organizations found</h3>
              <p className="text-muted-foreground mb-4">
                Get started by creating your first organization
              </p>
              <Button onClick={() => setCreateModalOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />
                Add Organization
              </Button>
            </CardContent>
          </Card>
        )}
      </div>

      <CreateTenantModal
        open={createModalOpen}
        onOpenChange={setCreateModalOpen}
        onSuccess={loadTenants}
      />
    </AppLayout>
  );
};

export default TenantsManagement;