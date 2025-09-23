import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { 
  Search, 
  UserCheck, 
  UserX, 
  Eye,
  Shield,
  Key,
  Mail,
  Calendar,
  Activity
} from 'lucide-react';
import { authAPI, getProviderIcon } from '@/lib/api-client';
import { UserWithLoginModes, UserFilters } from '@/types/auth';
import { toast } from '@/hooks/use-toast';
import { AppLayout } from '@/components/Layout/AppLayout';
import { CreateUserModal } from '@/components/admin/CreateUserModal';

export default function Users() {
  const [filters, setFilters] = useState<UserFilters>({
    page: 1,
    limit: 20
  });
  const [selectedUser, setSelectedUser] = useState<UserWithLoginModes | null>(null);
  const queryClient = useQueryClient();

  const { data: usersData, isLoading, error } = useQuery({
    queryKey: ['users', filters],
    queryFn: () => authAPI.getUsers(filters),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const disableUserMutation = useMutation({
    mutationFn: ({ userId, reason }: { userId: string; reason?: string }) =>
      authAPI.disableUser(userId, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      toast({ title: "User disabled successfully" });
    },
    onError: (error: any) => {
      toast({ 
        title: "Failed to disable user", 
        description: error.message,
        variant: "destructive"
      });
    },
  });

  const enableUserMutation = useMutation({
    mutationFn: (userId: string) => authAPI.enableUser(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      toast({ title: "User enabled successfully" });
    },
    onError: (error: any) => {
      toast({ 
        title: "Failed to enable user", 
        description: error.message,
        variant: "destructive"
      });
    },
  });

  const toggleLoginModeMutation = useMutation({
    mutationFn: ({ userId, provider, enabled }: { userId: string; provider: string; enabled: boolean }) =>
      authAPI.toggleUserLoginMode(userId, provider, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      toast({ title: "Login mode updated successfully" });
    },
    onError: (error: any) => {
      toast({ 
        title: "Failed to update login mode", 
        description: error.message,
        variant: "destructive"
      });
    },
  });

  const handleSearch = (query: string) => {
    setFilters(prev => ({ ...prev, q: query, page: 1 }));
  };

  const handleStatusFilter = (status: string) => {
    setFilters(prev => ({ 
      ...prev, 
      is_active: status === 'active' ? true : status === 'inactive' ? false : undefined,
      page: 1 
    }));
  };

  const handleDisableUser = (user: UserWithLoginModes) => {
    disableUserMutation.mutate({ userId: user.id });
  };

  const handleEnableUser = (user: UserWithLoginModes) => {
    enableUserMutation.mutate(user.id);
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const getStatusBadge = (user: UserWithLoginModes) => {
    if (!user.isActive) {
      return <Badge variant="destructive">Inactive</Badge>;
    }
    if (!user.isApproved) {
      return <Badge variant="secondary">Pending</Badge>;
    }
    return <Badge variant="default">Active</Badge>;
  };

  const getLoginModesBadges = (loginModes: Record<string, boolean>) => {
    return Object.entries(loginModes)
      .filter(([_, enabled]) => enabled)
      .map(([provider, _]) => (
        <Badge key={provider} variant="outline" className="text-xs">
          {getProviderIcon(provider)} {provider.replace('_', ' ')}
        </Badge>
      ));
  };

  if (error) {
    return (
      <div className="container mx-auto py-8">
        <Card>
          <CardContent className="pt-6">
            <p className="text-destructive">Error loading users: {error.message}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <AppLayout>
      <div className="container mx-auto py-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Users Management</h1>
          <p className="text-muted-foreground">
            Manage user accounts and authentication methods
          </p>
        </div>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Search className="h-5 w-5" />
            Filters
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <div className="flex-1">
              <Input
                placeholder="Search by email or name..."
                onChange={(e) => handleSearch(e.target.value)}
                className="max-w-sm"
              />
            </div>
            
            <Select onValueChange={handleStatusFilter}>
              <SelectTrigger className="w-48">
                <SelectValue placeholder="Filter by status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Users</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="inactive">Inactive</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <UserCheck className="h-4 w-4 text-muted-foreground" />
              <div>
                <p className="text-sm font-medium">Total Users</p>
                <p className="text-2xl font-bold">{usersData?.total || 0}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <UserCheck className="h-4 w-4 text-green-500" />
              <div>
                <p className="text-sm font-medium">Active Users</p>
                <p className="text-2xl font-bold">
                  {usersData?.items?.filter(u => u.isActive && u.isApproved).length || 0}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <UserX className="h-4 w-4 text-red-500" />
              <div>
                <p className="text-sm font-medium">Inactive Users</p>
                <p className="text-2xl font-bold">
                  {usersData?.items?.filter(u => !u.isActive).length || 0}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-blue-500" />
              <div>
                <p className="text-sm font-medium">Recent Logins</p>
                <p className="text-2xl font-bold">
                  {usersData?.items?.filter(u => {
                    if (!u.lastLogin) return false;
                    const lastLogin = new Date(u.lastLogin);
                    const now = new Date();
                    return (now.getTime() - lastLogin.getTime()) < 24 * 60 * 60 * 1000; // 24 hours
                  }).length || 0}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Users Table */}
      <Card>
        <CardHeader>
          <CardTitle>Users</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8">Loading users...</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Login Methods</TableHead>
                  <TableHead>Last Login</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {usersData?.items?.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell>
                      <div>
                        <p className="font-medium">{user.displayName}</p>
                        <p className="text-sm text-muted-foreground">{user.email}</p>
                        {user.isAdmin && (
                          <Badge variant="destructive" className="mt-1">
                            <Shield className="h-3 w-3 mr-1" />
                            Admin
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    
                    <TableCell>{getStatusBadge(user)}</TableCell>
                    
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {getLoginModesBadges(user.loginModes || {})}
                      </div>
                    </TableCell>
                    
                    <TableCell>
                      {user.lastLogin ? (
                        <span className="text-sm">{formatDate(user.lastLogin)}</span>
                      ) : (
                        <span className="text-sm text-muted-foreground">Never</span>
                      )}
                    </TableCell>
                    
                    <TableCell>
                      <span className="text-sm">{formatDate(user.createdAt)}</span>
                    </TableCell>
                    
                    <TableCell>
                      <div className="flex gap-2">
                        <Dialog>
                          <DialogTrigger asChild>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => setSelectedUser(user)}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                          </DialogTrigger>
                          <DialogContent className="max-w-2xl">
                            <DialogHeader>
                              <DialogTitle>User Details</DialogTitle>
                              <DialogDescription>
                                Manage user account and authentication methods
                              </DialogDescription>
                            </DialogHeader>
                            
                            {selectedUser && (
                              <div className="space-y-4">
                                <div className="grid grid-cols-2 gap-4">
                                  <div>
                                    <Label>Email</Label>
                                    <p className="text-sm">{selectedUser.email}</p>
                                  </div>
                                  <div>
                                    <Label>Display Name</Label>
                                    <p className="text-sm">{selectedUser.displayName}</p>
                                  </div>
                                  <div>
                                    <Label>Status</Label>
                                    {getStatusBadge(selectedUser)}
                                  </div>
                                  <div>
                                    <Label>Last Login</Label>
                                    <p className="text-sm">
                                      {selectedUser.lastLogin ? formatDate(selectedUser.lastLogin) : 'Never'}
                                    </p>
                                  </div>
                                </div>
                                
                                <div>
                                  <Label>Authentication Methods</Label>
                                  <div className="space-y-2 mt-2">
                                    {Object.entries(selectedUser.loginModes || {}).map(([provider, enabled]) => (
                                      <div key={provider} className="flex items-center justify-between">
                                        <Label className="flex items-center gap-2">
                                          <span>{getProviderIcon(provider)}</span>
                                          {provider.replace('_', ' ').toUpperCase()}
                                        </Label>
                                        <Switch
                                          checked={enabled}
                                          onCheckedChange={(checked) => 
                                            toggleLoginModeMutation.mutate({
                                              userId: selectedUser.id,
                                              provider,
                                              enabled: checked
                                            })
                                          }
                                        />
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              </div>
                            )}
                          </DialogContent>
                        </Dialog>
                        
                        {user.isActive ? (
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => handleDisableUser(user)}
                            disabled={disableUserMutation.isPending}
                          >
                            <UserX className="h-4 w-4" />
                          </Button>
                        ) : (
                          <Button
                            variant="default"
                            size="sm"
                            onClick={() => handleEnableUser(user)}
                            disabled={enableUserMutation.isPending}
                          >
                            <UserCheck className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Pagination */}
      {usersData && usersData.total > usersData.limit && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {((usersData.page - 1) * usersData.limit) + 1} to{' '}
            {Math.min(usersData.page * usersData.limit, usersData.total)} of{' '}
            {usersData.total} users
          </p>
          
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setFilters(prev => ({ ...prev, page: prev.page! - 1 }))}
              disabled={usersData.page <= 1}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setFilters(prev => ({ ...prev, page: prev.page! + 1 }))}
              disabled={usersData.page >= Math.ceil(usersData.total / usersData.limit)}
            >
              Next
            </Button>
          </div>
        </div>
      )}

      <CreateUserModal 
        open={showCreateModal}
        onOpenChange={setShowCreateModal}
        onSuccess={() => {
          fetchUsers();
          toast({
            title: "Success",
            description: "User created successfully"
          });
        }}
      />
      </div>
    </AppLayout>
  );
}