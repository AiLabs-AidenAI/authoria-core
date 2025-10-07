/**
 * OAuth Callback Handler
 * Handles the redirect from OAuth providers (Google, Microsoft, etc.)
 */

import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Loader2, CheckCircle, XCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';


export const OAuthCallback = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing');
  const [message, setMessage] = useState('Processing authentication...');

  useEffect(() => {
    const handleCallback = async () => {
      try {
        // Extract parameters from URL
        const token = searchParams.get('token');
        const error = searchParams.get('error');
        const errorDescription = searchParams.get('error_description');
        const userId = searchParams.get('user_id');
        const email = searchParams.get('email');

        console.log('OAuth callback params:', { 
          token: !!token, 
          error, 
          errorDescription,
          userId,
          email 
        });

        // Handle OAuth errors
        if (error) {
          console.error('OAuth error:', error, errorDescription);
          
          if (error === 'pending_approval') {
            setMessage('Your account is pending admin approval.');
            setStatus('error');
            setTimeout(() => navigate('/auth/pending-approval'), 2000);
            return;
          }

          setMessage(errorDescription || 'Authentication failed. Please try again.');
          setStatus('error');
          return;
        }

        // Handle successful OAuth with token
        if (token && userId && email) {
          console.log('✅ OAuth successful, storing authentication');
          
          // Store the access token and trigger context initialization
          localStorage.setItem('access_token', token);
          localStorage.setItem('user_id', userId);
          localStorage.setItem('user_email', email);
          
          // Create user object and store it
          const userData = {
            id: userId,
            email: email,
            displayName: email.split('@')[0],
            role: 'user',
            isActive: true,
            isApproved: true,
            isAdmin: false,
            createdAt: new Date().toISOString()
          };
          localStorage.setItem('auth_user', JSON.stringify(userData));
          
          setMessage('Authentication successful! Redirecting...');
          setStatus('success');
          
          // Force reload to trigger auth initialization
          setTimeout(() => {
            window.location.href = '/';
          }, 1500);
          return;
        }

        // If we get here, something is wrong with the callback
        console.error('❌ Invalid OAuth callback - missing required parameters');
        setMessage('Invalid authentication response. Please try again.');
        setStatus('error');

      } catch (err) {
        console.error('OAuth callback error:', err);
        setMessage('An error occurred during authentication.');
        setStatus('error');
      }
    };

    handleCallback();
  }, [searchParams, navigate]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1">
          <CardTitle className="text-2xl font-bold text-center">
            {status === 'processing' && 'Authenticating...'}
            {status === 'success' && 'Success!'}
            {status === 'error' && 'Authentication Failed'}
          </CardTitle>
          <CardDescription className="text-center">
            {message}
          </CardDescription>
        </CardHeader>

        <CardContent className="flex flex-col items-center space-y-4">
          {status === 'processing' && (
            <Loader2 className="h-16 w-16 animate-spin text-primary" />
          )}
          
          {status === 'success' && (
            <CheckCircle className="h-16 w-16 text-green-500" />
          )}
          
          {status === 'error' && (
            <>
              <XCircle className="h-16 w-16 text-destructive" />
              <Button 
                onClick={() => navigate('/auth/login')}
                className="w-full"
              >
                Back to Login
              </Button>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default OAuthCallback;
