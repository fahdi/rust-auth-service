'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useAuth } from '@/components/AuthProvider';
import { LoginRequest } from '@/lib/types';
import LoadingSpinner from './LoadingSpinner';
import Link from 'next/link';

const loginSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
  password: z.string().min(1, 'Password is required'),
});

type LoginFormData = z.infer<typeof loginSchema>;

interface LoginFormProps {
  onSuccess?: () => void;
}

export default function LoginForm({ onSuccess }: LoginFormProps) {
  const { login, loading, error, clearError } = useAuth();
  const router = useRouter();
  const [submitError, setSubmitError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
  });

  const onSubmit = async (data: LoginFormData) => {
    try {
      setSubmitError(null);
      clearError();
      
      const loginData: LoginRequest = {
        email: data.email,
        password: data.password,
      };

      await login(loginData);
      
      if (onSuccess) {
        onSuccess();
      } else {
        router.push('/dashboard');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Login failed';
      setSubmitError(errorMessage);
    }
  };

  const displayError = error || submitError;

  return (
    <div className="w-full max-w-md mx-auto">
      <div className="card">
        <div className="text-center mb-6">
          <h1 className="text-2xl font-bold text-gray-900">Sign In</h1>
          <p className="text-gray-600 mt-2">Welcome back! Please sign in to your account.</p>
        </div>

        {displayError && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg">
            <p className="error-message">{displayError}</p>
          </div>
        )}

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
              Email Address
            </label>
            <input
              {...register('email')}
              type="email"
              id="email"
              className="input-field"
              placeholder="Enter your email"
              disabled={loading || isSubmitting}
            />
            {errors.email && (
              <p className="error-message">{errors.email.message}</p>
            )}
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
              Password
            </label>
            <input
              {...register('password')}
              type="password"
              id="password"
              className="input-field"
              placeholder="Enter your password"
              disabled={loading || isSubmitting}
            />
            {errors.password && (
              <p className="error-message">{errors.password.message}</p>
            )}
          </div>

          <button
            type="submit"
            disabled={loading || isSubmitting}
            className="btn-primary w-full flex items-center justify-center"
          >
            {(loading || isSubmitting) ? (
              <>
                <LoadingSpinner size="small" className="mr-2" />
                Signing In...
              </>
            ) : (
              'Sign In'
            )}
          </button>
        </form>

        <div className="mt-6 text-center space-y-2">
          <p className="text-sm text-gray-600">
            Don't have an account?{' '}
            <Link href="/register" className="text-blue-600 hover:text-blue-500 font-medium">
              Create one here
            </Link>
          </p>
          <p className="text-sm">
            <Link href="/forgot-password" className="text-blue-600 hover:text-blue-500">
              Forgot your password?
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}