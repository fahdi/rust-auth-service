'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/components/AuthProvider';
import LoginForm from '@/components/LoginForm';
import LoadingSpinner from '@/components/LoadingSpinner';

export default function LoginPage() {
  const { isAuthenticated, loading } = useAuth();
  const router = useRouter();
  
  // Get redirect parameter from URL (client-side)
  const getRedirectTo = () => {
    if (typeof window !== 'undefined') {
      const urlParams = new URLSearchParams(window.location.search);
      return urlParams.get('redirectTo') || '/dashboard';
    }
    return '/dashboard';
  };

  useEffect(() => {
    if (!loading && isAuthenticated) {
      const redirectTo = getRedirectTo();
      router.push(redirectTo);
    }
  }, [isAuthenticated, loading, router]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <LoadingSpinner size="large" />
      </div>
    );
  }

  if (isAuthenticated) {
    return null; // Will redirect to dashboard
  }

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <Link href="/" className="flex items-center">
              <h1 className="text-xl font-bold text-gray-900">
                🦀 Rust Auth Service
              </h1>
              <span className="ml-2 px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded-full">
                Next.js Example
              </span>
            </Link>
            
            <nav>
              <Link href="/" className="btn-secondary">
                ← Back to Home
              </Link>
            </nav>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 flex items-center justify-center px-4 sm:px-6 lg:px-8 py-12">
        <div className="w-full max-w-md">
          <LoginForm onSuccess={() => {
            const redirectTo = getRedirectTo();
            router.push(redirectTo);
          }} />
          
          {/* Additional Info */}
          <div className="mt-8 text-center">
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <h3 className="text-sm font-medium text-blue-800 mb-2">
                Demo Credentials
              </h3>
              <div className="text-xs text-blue-600 space-y-1">
                <p><strong>Email:</strong> test@demo.com</p>
                <p><strong>Password:</strong> Test123!</p>
                <p className="mt-2 text-xs">Or create a new account above.</p>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="text-center text-gray-600 text-sm">
            <p>
              Secure authentication powered by Rust • Next.js 14 Integration Example
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}