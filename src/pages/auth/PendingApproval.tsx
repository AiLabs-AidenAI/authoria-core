/**
 * Pending approval page for users waiting for admin approval
 */

import React from 'react';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Clock, Mail, Shield, RefreshCw } from 'lucide-react';

export const PendingApproval = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-yellow-100">
            <Clock className="h-8 w-8 text-yellow-600" />
          </div>
          <CardTitle className="text-2xl font-bold">Account Pending Approval</CardTitle>
          <CardDescription>
            Your account is awaiting administrator approval
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-6">
          <div className="space-y-4">
            <div className="flex items-start gap-3 p-3 bg-yellow-50 rounded-lg border border-yellow-200">
              <Shield className="h-5 w-5 text-yellow-600 mt-0.5 flex-shrink-0" />
              <div>
                <h4 className="text-sm font-medium text-yellow-900">Under Review</h4>
                <p className="text-sm text-yellow-700">
                  Your signup request has been received and is currently being reviewed by an administrator.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3 p-3 bg-blue-50 rounded-lg border border-blue-200">
              <Mail className="h-5 w-5 text-blue-600 mt-0.5 flex-shrink-0" />
              <div>
                <h4 className="text-sm font-medium text-blue-900">Email Notification</h4>
                <p className="text-sm text-blue-700">
                  Once approved, you'll receive an email with instructions on how to access your account.
                </p>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <h4 className="text-sm font-semibold">Approval Process</h4>
            <div className="space-y-2 text-sm text-muted-foreground">
              <p>
                • Account requests are typically reviewed within 1-2 business days
              </p>
              <p>
                • You may be contacted if additional information is needed
              </p>
              <p>
                • Approval depends on your organization's access policies
              </p>
            </div>
          </div>

          <div className="space-y-3">
            <Button 
              variant="outline" 
              className="w-full"
              onClick={() => window.location.reload()}
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Check Status
            </Button>
            
            <Button asChild variant="secondary" className="w-full">
              <Link to="/auth/login">
                Back to Login
              </Link>
            </Button>
          </div>

          <div className="text-center pt-4 border-t">
            <p className="text-sm text-muted-foreground">
              Questions about your request?{' '}
              <a 
                href="mailto:admin@example.com" 
                className="text-primary hover:underline"
              >
                Contact administrator
              </a>
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default PendingApproval;