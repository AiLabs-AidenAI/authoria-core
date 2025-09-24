/**
 * Create Tenant Modal Component
 */

import React, { useState } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { toast } from '@/hooks/use-toast';
import { authAPI } from '@/lib/api-client';
import { Building2 } from 'lucide-react';

interface CreateTenantModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
}

interface TenantFormData {
  name: string;
  description: string;
  domain: string;
  enabled: boolean;
  auto_approve_domains: string;
}

export const CreateTenantModal: React.FC<CreateTenantModalProps> = ({
  open,
  onOpenChange,
  onSuccess
}) => {
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState<TenantFormData>({
    name: '',
    description: '',
    domain: '',
    enabled: true,
    auto_approve_domains: ''
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!formData.name.trim()) {
      toast({
        title: "Validation Error",
        description: "Tenant name is required",
        variant: "destructive"
      });
      return;
    }

    try {
      setLoading(true);
      
      const tenantData = {
        name: formData.name,
        description: formData.description || undefined,
        domain: formData.domain || undefined,
        enabled: formData.enabled,
        auto_approve_domains: formData.auto_approve_domains
          .split(',')
          .map(d => d.trim())
          .filter(d => d)
      };

      await authAPI.createTenant(tenantData);
      
      toast({
        title: "Tenant created",
        description: `${formData.name} has been created successfully.`
      });

      // Reset form
      setFormData({
        name: '',
        description: '',
        domain: '',
        enabled: true,
        auto_approve_domains: ''
      });

      onOpenChange(false);
      onSuccess();

    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to create tenant",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Building2 className="h-5 w-5" />
            Create New Tenant
          </DialogTitle>
          <DialogDescription>
            Add a new organization/tenant to the system
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name">Tenant Name *</Label>
            <Input
              id="name"
              value={formData.name}
              onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
              placeholder="e.g., Acme Corporation"
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="description">Description</Label>
            <Textarea
              id="description"
              value={formData.description}
              onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
              placeholder="Brief description of the organization"
              rows={2}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="domain">Primary Domain</Label>
            <Input
              id="domain"
              value={formData.domain}
              onChange={(e) => setFormData(prev => ({ ...prev, domain: e.target.value }))}
              placeholder="e.g., acme.com"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="auto_approve_domains">Auto-approve Domains</Label>
            <Input
              id="auto_approve_domains"
              value={formData.auto_approve_domains}
              onChange={(e) => setFormData(prev => ({ ...prev, auto_approve_domains: e.target.value }))}
              placeholder="e.g., acme.com, subdomain.acme.com (comma-separated)"
            />
            <p className="text-xs text-muted-foreground">
              Users from these domains will be automatically approved
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <Switch
              id="enabled"
              checked={formData.enabled}
              onCheckedChange={(checked) => setFormData(prev => ({ ...prev, enabled: checked }))}
            />
            <Label htmlFor="enabled">Enable tenant</Label>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={loading}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={loading}>
              {loading ? "Creating..." : "Create Tenant"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};