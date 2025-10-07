/**
 * Bulk User Upload Modal Component
 * Allows admins to create multiple users at once via CSV or form
 */

import React, { useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Badge } from '@/components/ui/badge';
import { Upload, UserPlus, FileText, Check, X } from 'lucide-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { authAPI } from '@/lib/api-client';
import { toast } from '@/hooks/use-toast';

interface BulkUserUploadModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess?: () => void;
}

interface BulkUserItem {
  email: string;
  displayName?: string;
  password?: string;
  isAdmin: boolean;
}

export const BulkUserUploadModal: React.FC<BulkUserUploadModalProps> = ({
  open,
  onOpenChange,
  onSuccess
}) => {
  const [users, setUsers] = useState<BulkUserItem[]>([]);
  const [csvText, setCsvText] = useState('');
  const [parseErrors, setParseErrors] = useState<string[]>([]);
  const queryClient = useQueryClient();

  const bulkCreateMutation = useMutation({
    mutationFn: (users: BulkUserItem[]) => authAPI.bulkCreateUsers(users),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      
      const { success_count, failure_count, failed_users } = data;
      
      if (failure_count > 0) {
        toast({
          title: "Partially Successful",
          description: `${success_count} users created, ${failure_count} failed`,
          variant: "default"
        });
      } else {
        toast({
          title: "Success",
          description: `All ${success_count} users created successfully`
        });
      }
      
      onSuccess?.();
      onOpenChange(false);
      resetForm();
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to create users",
        variant: "destructive"
      });
    }
  });

  const resetForm = () => {
    setUsers([]);
    setCsvText('');
    setParseErrors([]);
  };

  const parseCSV = () => {
    const errors: string[] = [];
    const parsed: BulkUserItem[] = [];
    
    const lines = csvText.trim().split('\n');
    
    // Skip header if present
    const startIndex = lines[0].toLowerCase().includes('email') ? 1 : 0;
    
    for (let i = startIndex; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      
      const parts = line.split(',').map(p => p.trim());
      
      if (parts.length < 1) {
        errors.push(`Line ${i + 1}: Invalid format`);
        continue;
      }
      
      const email = parts[0];
      const displayName = parts[1] || undefined;
      const password = parts[2] || undefined;
      const isAdmin = parts[3]?.toLowerCase() === 'true' || parts[3] === '1';
      
      // Basic email validation
      if (!email.includes('@')) {
        errors.push(`Line ${i + 1}: Invalid email format`);
        continue;
      }
      
      parsed.push({
        email,
        displayName,
        password,
        isAdmin
      });
    }
    
    setParseErrors(errors);
    setUsers(parsed);
    
    if (parsed.length > 0) {
      toast({
        title: "CSV Parsed",
        description: `Found ${parsed.length} valid user(s)${errors.length > 0 ? ` and ${errors.length} error(s)` : ''}`
      });
    }
  };

  const addManualUser = () => {
    setUsers([...users, { email: '', isAdmin: false }]);
  };

  const updateManualUser = (index: number, field: keyof BulkUserItem, value: any) => {
    const updated = [...users];
    updated[index] = { ...updated[index], [field]: value };
    setUsers(updated);
  };

  const removeManualUser = (index: number) => {
    setUsers(users.filter((_, i) => i !== index));
  };

  const handleSubmit = () => {
    // Validate
    const validUsers = users.filter(u => u.email && u.email.includes('@'));
    
    if (validUsers.length === 0) {
      toast({
        title: "Validation Error",
        description: "Please add at least one valid user",
        variant: "destructive"
      });
      return;
    }
    
    bulkCreateMutation.mutate(validUsers);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[80vh]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <UserPlus className="h-5 w-5" />
            Bulk Create Users
          </DialogTitle>
          <DialogDescription>
            Upload a CSV file or manually add multiple users at once
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="csv" className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="csv">
              <FileText className="h-4 w-4 mr-2" />
              CSV Upload
            </TabsTrigger>
            <TabsTrigger value="manual">
              <UserPlus className="h-4 w-4 mr-2" />
              Manual Entry
            </TabsTrigger>
          </TabsList>

          <TabsContent value="csv" className="space-y-4">
            <div className="space-y-2">
              <Label>CSV Format</Label>
              <div className="p-3 bg-muted rounded-md text-sm font-mono">
                email,display_name,password,is_admin
                <br />
                john@example.com,John Doe,Pass123!,false
                <br />
                admin@example.com,Admin User,SecurePass!,true
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="csv-input">Paste CSV Content</Label>
              <Textarea
                id="csv-input"
                placeholder="Paste your CSV content here..."
                value={csvText}
                onChange={(e) => setCsvText(e.target.value)}
                rows={10}
                className="font-mono text-sm"
              />
            </div>

            <Button onClick={parseCSV} variant="outline" className="w-full">
              <Upload className="h-4 w-4 mr-2" />
              Parse CSV
            </Button>

            {parseErrors.length > 0 && (
              <div className="p-3 bg-destructive/10 border border-destructive rounded-md">
                <p className="font-medium text-sm mb-2">Parsing Errors:</p>
                <ScrollArea className="h-20">
                  {parseErrors.map((error, i) => (
                    <p key={i} className="text-sm text-destructive">{error}</p>
                  ))}
                </ScrollArea>
              </div>
            )}
          </TabsContent>

          <TabsContent value="manual" className="space-y-4">
            <ScrollArea className="h-[300px] pr-4">
              <div className="space-y-3">
                {users.map((user, index) => (
                  <div key={index} className="p-3 border rounded-lg space-y-2">
                    <div className="flex justify-between items-start">
                      <span className="text-sm font-medium">User {index + 1}</span>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => removeManualUser(index)}
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <Label className="text-xs">Email *</Label>
                        <Input
                          type="email"
                          placeholder="user@example.com"
                          value={user.email}
                          onChange={(e) => updateManualUser(index, 'email', e.target.value)}
                        />
                      </div>
                      <div>
                        <Label className="text-xs">Display Name</Label>
                        <Input
                          placeholder="John Doe"
                          value={user.displayName || ''}
                          onChange={(e) => updateManualUser(index, 'displayName', e.target.value)}
                        />
                      </div>
                      <div>
                        <Label className="text-xs">Password</Label>
                        <Input
                          type="password"
                          placeholder="Optional"
                          value={user.password || ''}
                          onChange={(e) => updateManualUser(index, 'password', e.target.value)}
                        />
                      </div>
                      <div className="flex items-end">
                        <Label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={user.isAdmin}
                            onChange={(e) => updateManualUser(index, 'isAdmin', e.target.checked)}
                            className="rounded"
                          />
                          <span className="text-xs">Admin</span>
                        </Label>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>

            <Button onClick={addManualUser} variant="outline" className="w-full">
              <UserPlus className="h-4 w-4 mr-2" />
              Add User
            </Button>
          </TabsContent>
        </Tabs>

        {users.length > 0 && (
          <div className="p-3 bg-muted rounded-md">
            <p className="text-sm font-medium">
              Ready to create {users.length} user(s)
            </p>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={users.length === 0 || bulkCreateMutation.isPending}
          >
            {bulkCreateMutation.isPending ? (
              <>Creating...</>
            ) : (
              <>
                <Check className="h-4 w-4 mr-2" />
                Create {users.length} User(s)
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
