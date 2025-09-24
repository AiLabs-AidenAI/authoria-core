/**
 * Audit Log page for reviewing authentication and administrative events
 */

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Calendar, Search, Filter, Download, Eye, AlertCircle, CheckCircle, XCircle } from 'lucide-react';
import { authAPI } from '@/lib/api-client';
import { AuditLog, AuditLogFilters } from '@/types/auth';
import { toast } from '@/hooks/use-toast';
import { AppLayout } from '@/components/Layout/AppLayout';

export const AuditLogPage = () => {
  const [events, setEvents] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  const eventTypes = [
    'all',
    'user_login',
    'user_logout', 
    'signup_request',
    'signup_approved',
    'signup_rejected',
    'password_reset',
    'oauth_login',
    'token_refresh',
    'admin_action',
    'config_change',
    'provider_linked',
    'provider_unlinked'
  ];

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'success': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'warning': return <AlertCircle className="h-4 w-4 text-yellow-500" />;
      case 'error': return <XCircle className="h-4 w-4 text-red-500" />;
      default: return <Eye className="h-4 w-4 text-blue-500" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'success': return 'bg-green-100 text-green-800 border-green-200';
      case 'warning': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'error': return 'bg-red-100 text-red-800 border-red-200';
      default: return 'bg-blue-100 text-blue-800 border-blue-200';
    }
  };

  const fetchAuditEvents = async () => {
    try {
      setLoading(true);
      const filters: AuditLogFilters = {
        page: currentPage,
        limit: 50,
        search: searchTerm || undefined,
        event_type: eventTypeFilter === 'all' ? undefined : eventTypeFilter,
        severity: severityFilter === 'all' ? undefined : (severityFilter as any)
      };

      const response = await authAPI.getAuditLogs(filters);
      setEvents(response.items || []);
      setTotalPages(Math.ceil((response.total || 0) / 50));
    } catch (error) {
      toast({
        title: "Failed to load audit events",
        description: error instanceof Error ? error.message : "Please try again.",
        variant: "destructive"
      });
      // Mock data for development
      setEvents([
        {
          id: '1',
          timestamp: new Date().toISOString(),
          event_type: 'user_login',
          actionType: 'user_login',
          targetType: 'user',
          user_email: 'admin@example.com',
          ip_address: '192.168.1.1',
          ipAddress: '192.168.1.1',
          user_agent: 'Mozilla/5.0...',
          userAgent: 'Mozilla/5.0...',
          details: { provider: 'local_password' },
          payload: { provider: 'local_password' },
          severity: 'success'
        },
        {
          id: '2',
          timestamp: new Date(Date.now() - 3600000).toISOString(),
          event_type: 'config_change',
          actionType: 'config_change',
          targetType: 'system',
          user_email: 'admin@example.com',
          ip_address: '192.168.1.1',
          ipAddress: '192.168.1.1',
          user_agent: 'Mozilla/5.0...',
          userAgent: 'Mozilla/5.0...',
          details: { config_key: 'oauth_provider', action: 'updated' },
          payload: { config_key: 'oauth_provider', action: 'updated' },
          severity: 'info'
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const exportAuditLog = async () => {
    try {
      const filters: AuditLogFilters = {
        search: searchTerm || undefined,
        event_type: eventTypeFilter === 'all' ? undefined : eventTypeFilter,
        severity: severityFilter === 'all' ? undefined : (severityFilter as any)
      };

      const response = await authAPI.exportAuditLogs(filters);

      // Create and download CSV file
      const blob = new Blob([response], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit_log_${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      toast({
        title: "Audit log exported",
        description: "The audit log has been downloaded as a CSV file."
      });
    } catch (error) {
      toast({
        title: "Export failed",
        description: error instanceof Error ? error.message : "Please try again.",
        variant: "destructive"
      });
    }
  };

  useEffect(() => {
    fetchAuditEvents();
  }, [currentPage, searchTerm, eventTypeFilter, severityFilter]);

  const filteredEvents = events.filter(event => {
    const matchesSearch = !searchTerm || 
      event.user_email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      event.event_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      event.ip_address.includes(searchTerm);
    
    return matchesSearch;
  });

  return (
    <AppLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">Audit Log</h1>
          <p className="text-muted-foreground">
            Monitor authentication events and administrative actions
          </p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Eye className="h-5 w-5" />
              Event History
            </CardTitle>
            <CardDescription>
              View and filter authentication and system events
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-6">
            {/* Filters */}
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
              <div className="flex flex-col gap-2 md:flex-row md:items-center md:gap-4">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search events, users, or IPs..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10 w-64"
                  />
                </div>

                <Select value={eventTypeFilter} onValueChange={setEventTypeFilter}>
                  <SelectTrigger className="w-48">
                    <SelectValue placeholder="Event Type" />
                  </SelectTrigger>
                  <SelectContent>
                    {eventTypes.map(type => (
                      <SelectItem key={type} value={type}>
                        {type === 'all' ? 'All Events' : type.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>

                <Select value={severityFilter} onValueChange={setSeverityFilter}>
                  <SelectTrigger className="w-32">
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="success">Success</SelectItem>
                    <SelectItem value="info">Info</SelectItem>
                    <SelectItem value="warning">Warning</SelectItem>
                    <SelectItem value="error">Error</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <Button onClick={exportAuditLog} variant="outline" className="flex items-center gap-2">
                <Download className="h-4 w-4" />
                Export CSV
              </Button>
            </div>

            {/* Events Table */}
            <div className="border rounded-lg">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Severity</TableHead>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Event Type</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead>IP Address</TableHead>
                    <TableHead>Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-8">
                        Loading audit events...
                      </TableCell>
                    </TableRow>
                  ) : filteredEvents.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                        No events found matching your criteria
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredEvents.map((event) => (
                      <TableRow key={event.id}>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            {getSeverityIcon(event.severity)}
                            <Badge variant="outline" className={getSeverityColor(event.severity)}>
                              {event.severity}
                            </Badge>
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {new Date(event.timestamp).toLocaleString()}
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary">
                            {event.event_type.replace('_', ' ')}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {event.user_email || <span className="text-muted-foreground">System</span>}
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {event.ip_address}
                        </TableCell>
                        <TableCell>
                          <details className="cursor-pointer">
                            <summary className="text-sm text-muted-foreground hover:text-foreground">
                              View details
                            </summary>
                            <pre className="mt-2 text-xs bg-muted p-2 rounded overflow-auto max-w-md">
                              {JSON.stringify(event.details, null, 2)}
                            </pre>
                          </details>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between">
                <div className="text-sm text-muted-foreground">
                  Page {currentPage} of {totalPages}
                </div>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                    disabled={currentPage === 1}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                    disabled={currentPage === totalPages}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </AppLayout>
  );
};

export default AuditLogPage;