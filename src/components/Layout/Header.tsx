import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, Users, Settings, Activity } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface HeaderProps {
  title?: string;
}

export function Header({ title = "Authentication Service" }: HeaderProps) {
  return (
    <header className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-16 items-center justify-between">
        <div className="flex items-center gap-4">
          <Link to="/" className="flex items-center gap-2 font-semibold">
            <Shield className="h-6 w-6 text-primary" />
            <span className="text-lg">{title}</span>
          </Link>
        </div>
        
        <nav className="flex items-center gap-1">
          <Button variant="ghost" size="sm" asChild>
            <Link to="/admin/pending-requests" className="flex items-center gap-2">
              <Users className="h-4 w-4" />
              Pending Requests
            </Link>
          </Button>
          
          <Button variant="ghost" size="sm" asChild>
            <Link to="/admin/users" className="flex items-center gap-2">
              <Activity className="h-4 w-4" />
              Users
            </Link>
          </Button>
          
          <Button variant="ghost" size="sm" asChild>
            <Link to="/admin/auth-config" className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              Configuration
            </Link>
          </Button>
        </nav>
      </div>
    </header>
  );
}