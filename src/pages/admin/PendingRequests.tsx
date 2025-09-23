/**
 * Admin dashboard for managing pending signup requests
 */

import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Search, Filter, Download, Check, X, Eye, CheckSquare, Square, Users } from 'lucide-react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from '@/hooks/use-toast';
import { authAPI, downloadFile } from '@/lib/api-client';
import { PendingSignup, PendingSignupFilters } from '@/types/auth';
import { AppLayout } from '@/components/Layout/AppLayout';

interface BulkActionToolbarProps {
  selectedCount: number;
  onApproveAll: () => void;
  onRejectAll: () => void;
  onClearSelection: () => void;
}

const BulkActionToolbar: React.FC<BulkActionToolbarProps> = ({
  selectedCount,
  onApproveAll,
  onRejectAll,
  onClearSelection
}) => {
  if (selectedCount === 0) return null;

  return (
    <div className="fixed bottom-4 left-1/2 transform -translate-x-1/2 bg-primary text-primary-foreground px-6 py-3 rounded-lg shadow-lg flex items-center gap-4 z-50">
      <span className="font-medium">
        {selectedCount} request{selectedCount === 1 ? '' : 's'} selected
      </span>
      <div className="flex gap-2">
        <Button
          size="sm"
          variant="secondary"
          onClick={onApproveAll}
          className="bg-green-600 hover:bg-green-700 text-white"
        >
          <Check className="h-4 w-4 mr-1" />
          Approve All
        </Button>
        <Button
          size="sm"
          variant="secondary"
          onClick={onRejectAll}
          className="bg-red-600 hover:bg-red-700 text-white"
        >
          <X className="h-4 w-4 mr-1" />
          Reject All
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={onClearSelection}
          className="border-primary-foreground text-primary-foreground hover:bg-primary-foreground hover:text-primary"
        >
          Clear
        </Button>
      </div>
    </div>
  );
};

export const PendingRequests = () => {
  const [filters, setFilters] = useState<PendingSignupFilters>({
    status: 'pending',
    page: 1,
    limit: 20
  });
  
  const [selectedRequests, setSelectedRequests] = useState<Set<string>>(new Set());
  const [showApproveModal, setShowApproveModal] = useState(false);
  const [showRejectModal, setShowRejectModal] = useState(false);
  const [isSelectAllChecked, setIsSelectAllChecked] = useState(false);
  const [defaultRoleId, setDefaultRoleId] = useState<string>('');
  const [rejectReason, setRejectReason] = useState('');

  const queryClient = useQueryClient();

  // Fetch pending requests
  const { data: requestsData, isLoading } = useQuery({
    queryKey: ['pending-requests', filters],
    queryFn: () => authAPI.getPendingSignups(filters),
  });

  const requests = requestsData?.items || [];
  const totalCount = requestsData?.total || 0;

  // Approve requests mutation
  const approveMutation = useMutation({
    mutationFn: (data: { ids: string[]; assignRoleId?: string }) => {
      if (data.ids.length === 1) {
        return authAPI.approvePendingSignup(data.ids[0], { assignRoleId: data.assignRoleId });
      } else {
        return authAPI.bulkApprovePendingSignups({ 
          signupIds: data.ids, 
          assignRoleId: data.assignRoleId,
          notifyUsers: true 
        });
      }
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['pending-requests'] });
      setSelectedRequests(new Set());
      setShowApproveModal(false);
      setDefaultRoleId('');
      
      toast({
        title: "Requests approved",
        description: `${variables.ids.length} request${variables.ids.length === 1 ? '' : 's'} approved successfully.`
      });
    },
    onError: (error) => {
      toast({
        title: "Approval failed",
        description: error instanceof Error ? error.message : "Failed to approve requests",
        variant: "destructive"
      });
    }
  });

  // Reject requests mutation
  const rejectMutation = useMutation({
    mutationFn: (data: { ids: string[]; reason?: string }) => {
      if (data.ids.length === 1) {
        return authAPI.rejectPendingSignup(data.ids[0], data.reason);
      } else {
        return authAPI.bulkRejectPendingSignups(data.ids, data.reason);
      }
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['pending-requests'] });
      setSelectedRequests(new Set());
      setShowRejectModal(false);
      setRejectReason('');
      
      toast({
        title: "Requests rejected",
        description: `${variables.ids.length} request${variables.ids.length === 1 ? '' : 's'} rejected.`
      });
    },
    onError: (error) => {
      toast({
        title: "Rejection failed",
        description: error instanceof Error ? error.message : "Failed to reject requests",
        variant: "destructive"
      });
    }
  });

  // Export mutation
  const exportMutation = useMutation({
    mutationFn: () => authAPI.exportPendingSignups(filters),
    onSuccess: (blob) => {
      downloadFile(blob, `pending-requests-${new Date().toISOString().split('T')[0]}.csv`);
      toast({
        title: "Export successful",
        description: "Pending requests exported to CSV file."
      });
    },
    onError: () => {
      toast({
        title: "Export failed",
        description: "Failed to export pending requests",
        variant: "destructive"
      });
    }
  });

  // Handle individual request selection
  const handleRequestSelect = (requestId: string, checked: boolean) => {
    const newSelected = new Set(selectedRequests);
    if (checked) {
      newSelected.add(requestId);
    } else {
      newSelected.delete(requestId);
    }
    setSelectedRequests(newSelected);
  };

  // Handle select all toggle
  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      const allIds = new Set(requests.map(r => r.id));
      setSelectedRequests(allIds);
    } else {
      setSelectedRequests(new Set());
    }
    setIsSelectAllChecked(checked);
  };

  // Update select all checkbox state based on individual selections
  useEffect(() => {
    const allSelected = requests.length > 0 && requests.every(r => selectedRequests.has(r.id));
    const someSelected = requests.some(r => selectedRequests.has(r.id));
    
    setIsSelectAllChecked(allSelected);
  }, [selectedRequests, requests]);

  // Handle bulk approve
  const handleBulkApprove = () => {
    const selectedIds = Array.from(selectedRequests);
    approveMutation.mutate({ ids: selectedIds, assignRoleId: defaultRoleId || undefined });
  };

  // Handle bulk reject
  const handleBulkReject = () => {
    const selectedIds = Array.from(selectedRequests);
    rejectMutation.mutate({ ids: selectedIds, reason: rejectReason || undefined });
  };

  // Handle single approve
  const handleSingleApprove = (requestId: string) => {
    approveMutation.mutate({ ids: [requestId] });
  };

  // Handle single reject
  const handleSingleReject = (requestId: string) => {
    rejectMutation.mutate({ ids: [requestId] });
  };

  const getProviderBadge = (provider: string) => {
    const config = {
      'local_password': { label: 'Email', variant: 'default' as const },
      'email_otp': { label: 'OTP', variant: 'secondary' as const },
      'google': { label: 'Google', variant: 'outline' as const },
      'azure': { label: 'Azure', variant: 'outline' as const },
    };

    const { label, variant } = config[provider] || { label: provider, variant: 'default' as const };
    return <Badge variant={variant}>{label}</Badge>;
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <AppLayout>
      <div className="container mx-auto py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Pending Requests</h1>
          <p className="text-muted-foreground">
            Review and approve user account requests
          </p>
        </div>
        <Button
          variant="outline"
          onClick={() => exportMutation.mutate()}
          disabled={exportMutation.isPending}
        >
          <Download className="h-4 w-4 mr-2" />
          Export CSV
        </Button>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Filter className="h-5 w-5" />
            Filters
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="space-y-2">
              <Label>Search</Label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search by email..."
                  className="pl-10"
                  value={filters.search || ''}
                  onChange={(e) => setFilters(prev => ({ ...prev, search: e.target.value, page: 1 }))}
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label>Status</Label>
              <Select
                value={filters.status || ''}
                onValueChange={(value) => setFilters(prev => ({ ...prev, status: value as any, page: 1 }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="All statuses" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">All statuses</SelectItem>
                  <SelectItem value="pending">Pending</SelectItem>
                  <SelectItem value="approved">Approved</SelectItem>
                  <SelectItem value="rejected">Rejected</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Provider</Label>
              <Select
                value={filters.provider || ''}
                onValueChange={(value) => setFilters(prev => ({ ...prev, provider: value, page: 1 }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="All providers" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">All providers</SelectItem>
                  <SelectItem value="local_password">Email & Password</SelectItem>
                  <SelectItem value="email_otp">Email OTP</SelectItem>
                  <SelectItem value="google">Google</SelectItem>
                  <SelectItem value="azure">Azure</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-end">
              <Button
                variant="outline"
                onClick={() => setFilters({ status: 'pending', page: 1, limit: 20 })}
                className="w-full"
              >
                Reset Filters
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-orange-100 dark:bg-orange-900 rounded-lg">
                <Users className="h-6 w-6 text-orange-600 dark:text-orange-300" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Total Pending</p>
                <p className="text-2xl font-bold">{totalCount}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-blue-100 dark:bg-blue-900 rounded-lg">
                <CheckSquare className="h-6 w-6 text-blue-600 dark:text-blue-300" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Selected</p>
                <p className="text-2xl font-bold">{selectedRequests.size}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-green-100 dark:bg-green-900 rounded-lg">
                <Check className="h-6 w-6 text-green-600 dark:text-green-300" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Ready to Approve</p>
                <p className="text-2xl font-bold">{selectedRequests.size}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Requests Table */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-12">
                  <Checkbox
                    checked={isSelectAllChecked}
                    onCheckedChange={handleSelectAll}
                  />
                </TableHead>
                <TableHead>User</TableHead>
                <TableHead>Provider</TableHead>
                <TableHead>Organization</TableHead>
                <TableHead>Requested</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8">
                    Loading...
                  </TableCell>
                </TableRow>
              ) : requests.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                    No pending requests found
                  </TableCell>
                </TableRow>
              ) : (
                requests.map((request) => (
                  <TableRow key={request.id}>
                    <TableCell>
                      <Checkbox
                        checked={selectedRequests.has(request.id)}
                        onCheckedChange={(checked) => 
                          handleRequestSelect(request.id, checked as boolean)
                        }
                      />
                    </TableCell>
                    <TableCell>
                      <div>
                        <div className="font-medium">{request.displayName}</div>
                        <div className="text-sm text-muted-foreground">{request.email}</div>
                      </div>
                    </TableCell>
                    <TableCell>
                      {getProviderBadge(request.providerRequested)}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {request.tenantId || 'No organization'}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="text-sm">
                        {formatDate(request.createdAt)}
                      </div>
                      {request.requestedByIp && (
                        <div className="text-xs text-muted-foreground">
                          IP: {request.requestedByIp}
                        </div>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge 
                        variant={
                          request.status === 'pending' ? 'secondary' :
                          request.status === 'approved' ? 'default' : 'destructive'
                        }
                      >
                        {request.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        {request.status === 'pending' && (
                          <>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleSingleApprove(request.id)}
                              disabled={approveMutation.isPending}
                              className="text-green-600 hover:bg-green-50"
                            >
                              <Check className="h-4 w-4" />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleSingleReject(request.id)}
                              disabled={rejectMutation.isPending}
                              className="text-red-600 hover:bg-red-50"
                            >
                              <X className="h-4 w-4" />
                            </Button>
                          </>
                        )}
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {/* Open request details */}}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Bulk Action Toolbar */}
      <BulkActionToolbar
        selectedCount={selectedRequests.size}
        onApproveAll={() => setShowApproveModal(true)}
        onRejectAll={() => setShowRejectModal(true)}
        onClearSelection={() => setSelectedRequests(new Set())}
      />

      {/* Approve Modal */}
      <Dialog open={showApproveModal} onOpenChange={setShowApproveModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Approve Requests</DialogTitle>
            <DialogDescription>
              Approve {selectedRequests.size} selected request{selectedRequests.size === 1 ? '' : 's'}.
              Users will be notified via email.
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Default Role (Optional)</Label>
              <Select value={defaultRoleId} onValueChange={setDefaultRoleId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select default role" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">No role assignment</SelectItem>
                  <SelectItem value="user">User</SelectItem>
                  <SelectItem value="viewer">Viewer</SelectItem>
                  <SelectItem value="editor">Editor</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowApproveModal(false)}>
              Cancel
            </Button>
            <Button 
              onClick={handleBulkApprove}
              disabled={approveMutation.isPending}
            >
              {approveMutation.isPending ? "Approving..." : "Approve All"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Reject Modal */}
      <Dialog open={showRejectModal} onOpenChange={setShowRejectModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reject Requests</DialogTitle>
            <DialogDescription>
              Reject {selectedRequests.size} selected request{selectedRequests.size === 1 ? '' : 's'}.
              Users will be notified via email.
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Reason (Optional)</Label>
              <Textarea
                placeholder="Enter reason for rejection..."
                value={rejectReason}
                onChange={(e) => setRejectReason(e.target.value)}
              />
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRejectModal(false)}>
              Cancel
            </Button>
            <Button 
              variant="destructive"
              onClick={handleBulkReject}
              disabled={rejectMutation.isPending}
            >
              {rejectMutation.isPending ? "Rejecting..." : "Reject All"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      </div>
    </AppLayout>
  );
};

export default PendingRequests;