/**
 * Signup success page
 */

import React from 'react';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { CheckCircle, Clock, Mail } from 'lucide-react';

export const SignupSuccess = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-green-100">
            <CheckCircle className="h-8 w-8 text-green-600" />
          </div>
          <CardTitle className="text-2xl font-bold">Account Request Submitted!</CardTitle>
          <CardDescription>
            Your signup request has been successfully submitted for admin review
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-6">
          <div className="space-y-4">
            <div className="flex items-start gap-3 p-3 bg-blue-50 rounded-lg border border-blue-200">
              <Clock className="h-5 w-5 text-blue-600 mt-0.5 flex-shrink-0" />
              <div>
                <h4 className="text-sm font-medium text-blue-900">Pending Approval</h4>
                <p className="text-sm text-blue-700">
                  An administrator will review your request and approve or reject it based on your organization's policies.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3 p-3 bg-green-50 rounded-lg border border-green-200">
              <Mail className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
              <div>
                <h4 className="text-sm font-medium text-green-900">Email Notification</h4>
                <p className="text-sm text-green-700">
                  You'll receive an email notification once your account has been approved and is ready to use.
                </p>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <h4 className="text-sm font-semibold">What happens next?</h4>
            <ol className="text-sm text-muted-foreground space-y-2">
              <li className="flex items-center gap-2">
                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-primary text-xs text-primary-foreground">1</span>
                Admin reviews your signup request
              </li>
              <li className="flex items-center gap-2">
                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-primary text-xs text-primary-foreground">2</span>
                You receive approval email
              </li>
              <li className="flex items-center gap-2">
                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-primary text-xs text-primary-foreground">3</span>
                Sign in with your credentials
              </li>
            </ol>
          </div>

          <div className="pt-4 border-t">
            <Button asChild className="w-full">
              <Link to="/auth/login">
                Return to Login
              </Link>
            </Button>
          </div>

          <div className="text-center">
            <p className="text-sm text-muted-foreground">
              Need help?{' '}
              <Link to="/documentation" className="text-primary hover:underline">
                View documentation
              </Link>
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default SignupSuccess;