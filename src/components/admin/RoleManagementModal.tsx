/**
 * Role Management Modal Component
 * Allows admins to assign/remove roles from users
 */

import React, { useState, useEffect } from 'react';
import { 
  Dialog, 
  DialogContent, 
  DialogDescription, 
  DialogFooter, 
  DialogHeader, 
  DialogTitle 
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Shield, 
  User, 
  Crown, 
  Settings,
  Check,
  X
} from 'lucide-react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { authAPI } from '@/lib/api-client';
import { toast } from '@/hooks/use-toast';
import { User as UserType } from '@/types/auth';

interface Role {
  id: string;
  name: string;
  display_name: string;
  description?: string;
  is_system_role: boolean;
  is_admin_role: boolean;
  permissions: string[];
  user_count: number;
  created_at: string;
}

interface RoleManagementModalProps {
  user: UserType | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess?: () => void;
}

const RoleIcon = ({ roleName }: { roleName: string }) => {
  switch (roleName) {
    case 'super_admin':
      return <Crown className="h-4 w-4 text-yellow-500" />;
    case 'admin':
      return <Shield className="h-4 w-4 text-red-500" />;
    case 'moderator':
      return <Settings className="h-4 w-4 text-blue-500" />;
    case 'user':
      return <User className="h-4 w-4 text-gray-500" />;
    default:
      return <User className="h-4 w-4 text-gray-500" />;
  }
};

export const RoleManagementModal: React.FC<RoleManagementModalProps> = ({
  user,
  open,
  onOpenChange,
  onSuccess
}) => {
  const [selectedRoles, setSelectedRoles] = useState<Set<string>>(new Set());
  const queryClient = useQueryClient();

  // Fetch available roles
  const { data: rolesData } = useQuery({
    queryKey: ['roles'],
    queryFn: () => authAPI.getRoles(),
    enabled: open
  });

  // Fetch user's current roles
  const { data: userRolesData } = useQuery({
    queryKey: ['user-roles', user?.id],
    queryFn: () => user ? authAPI.getUserRoles(user.id) : Promise.resolve({ items: [] }),
    enabled: open && !!user
  });

  // Assign roles mutation
  const assignRolesMutation = useMutation({
    mutationFn: ({ userId, roleIds }: { userId: string; roleIds: string[] }) =>
      authAPI.assignUserRoles(userId, roleIds),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      queryClient.invalidateQueries({ queryKey: ['user-roles'] });
      onSuccess?.();
      toast({
        title: "Success",
        description: "User roles updated successfully"
      });
      onOpenChange(false);
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to update user roles",
        variant: "destructive"
      });
    }
  });

  const roles = rolesData?.items || [];
  const currentUserRoles = userRolesData?.items || [];

  // Initialize selected roles when modal opens
  useEffect(() => {
    if (open && currentUserRoles.length > 0) {
      setSelectedRoles(new Set(currentUserRoles.map((role: Role) => role.id)));
    } else {
      setSelectedRoles(new Set());
    }
  }, [open, currentUserRoles]);

  const handleRoleToggle = (roleId: string, checked: boolean) => {
    const newSelected = new Set(selectedRoles);
    if (checked) {
      newSelected.add(roleId);
    } else {
      newSelected.delete(roleId);
    }
    setSelectedRoles(newSelected);
  };

  const handleSave = () => {
    if (!user) return;
    
    const roleIds = Array.from(selectedRoles);
    assignRolesMutation.mutate({
      userId: user.id,
      roleIds
    });
  };

  const hasChanges = () => {
    const currentRoleIds = new Set(currentUserRoles.map((role: Role) => role.id));
    return currentRoleIds.size !== selectedRoles.size || 
           !Array.from(currentRoleIds).every(id => selectedRoles.has(id));
  };

  if (!user) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Manage User Roles
          </DialogTitle>
          <DialogDescription>
            Assign or remove roles for <strong>{user.displayName}</strong> ({user.email})
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          {/* Current User Status */}
          <div className="p-4 bg-muted rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">Current Status</p>
                <div className="flex items-center gap-2 mt-1">
                  {user.isAdmin ? (
                    <Badge variant="destructive" className="flex items-center gap-1">
                      <Shield className="h-3 w-3" />
                      Administrator
                    </Badge>
                  ) : (
                    <Badge variant="secondary">Regular User</Badge>
                  )}
                  {!user.isActive && (
                    <Badge variant="outline">Inactive</Badge>
                  )}
                </div>
              </div>
            </div>
          </div>

          <Separator />

          {/* Available Roles */}
          <div>
            <Label className="text-base font-medium mb-4 block">
              Available Roles
            </Label>
            
            <ScrollArea className="h-[300px] pr-4">
              <div className="space-y-3">
                {roles.map((role: Role) => (
                  <div
                    key={role.id}
                    className="flex items-start space-x-3 p-3 border rounded-lg hover:bg-muted/50 transition-colors"
                  >
                    <Checkbox
                      id={role.id}
                      checked={selectedRoles.has(role.id)}
                      onCheckedChange={(checked) => 
                        handleRoleToggle(role.id, checked as boolean)
                      }
                      className="mt-1"
                    />
                    
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <RoleIcon roleName={role.name} />
                        <Label 
                          htmlFor={role.id}
                          className="font-medium cursor-pointer"
                        >
                          {role.display_name}
                        </Label>
                        
                        <div className="flex gap-1">
                          {role.is_system_role && (
                            <Badge variant="outline" className="text-xs">
                              System
                            </Badge>
                          )}
                          {role.is_admin_role && (
                            <Badge variant="destructive" className="text-xs">
                              Admin Access
                            </Badge>
                          )}
                        </div>
                      </div>
                      
                      {role.description && (
                        <p className="text-sm text-muted-foreground mb-2">
                          {role.description}
                        </p>
                      )}
                      
                      <div className="flex flex-wrap gap-1">
                        {role.permissions.slice(0, 3).map((permission, index) => (
                          <Badge key={index} variant="secondary" className="text-xs">
                            {permission}
                          </Badge>
                        ))}
                        {role.permissions.length > 3 && (
                          <Badge variant="secondary" className="text-xs">
                            +{role.permissions.length - 3} more
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </div>
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            onClick={handleSave}
            disabled={!hasChanges() || assignRolesMutation.isPending}
          >
            {assignRolesMutation.isPending ? (
              <>Saving...</>
            ) : (
              <>
                <Check className="h-4 w-4 mr-2" />
                Save Changes
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};