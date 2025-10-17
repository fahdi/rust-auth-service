'use client';

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { apiClient } from '@/lib/api';
import {
  User,
  LoginRequest,
  RegisterRequest,
  UpdateProfileRequest,
  AuthContextType,
} from '@/lib/types';

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Initialize auth state on mount
  useEffect(() => {
    initializeAuth();
  }, []);

  const initializeAuth = async () => {
    try {
      setLoading(true);
      setError(null);

      // Check if we have a token
      const hasToken = apiClient.hasValidToken();
      console.log('Has token:', hasToken);
      console.log('Access token:', apiClient.getAccessToken());
      
      if (hasToken) {
        // Try to get user profile to verify token validity
        console.log('Attempting to get user profile...');
        const userProfile = await apiClient.getProfile();
        console.log('User profile retrieved:', userProfile);
        setUser(userProfile);
      } else {
        console.log('No valid token found');
        setUser(null);
      }
    } catch (err) {
      // Token is invalid or expired, clear it
      console.log('Authentication initialization failed:', err);
      setUser(null);
    } finally {
      setLoading(false);
      console.log('Auth initialization complete. User:', user);
    }
  };

  const login = async (credentials: LoginRequest) => {
    try {
      setLoading(true);
      setError(null);

      console.log('Attempting login with:', credentials.email);
      const response = await apiClient.login(credentials);
      console.log('Login response:', response);
      console.log('Setting user:', response.user);
      setUser(response.user);
      console.log('Login successful, tokens saved');
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Login failed';
      console.log('Login failed:', errorMessage);
      setError(errorMessage);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const register = async (userData: RegisterRequest) => {
    try {
      setLoading(true);
      setError(null);

      const response = await apiClient.register(userData);
      setUser(response.user);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Registration failed';
      setError(errorMessage);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      setLoading(true);
      setError(null);

      await apiClient.logout();
    } catch (err) {
      // Even if logout fails on server, clear local state
      console.error('Logout error:', err);
    } finally {
      setUser(null);
      setLoading(false);
    }
  };

  const updateProfile = async (data: UpdateProfileRequest) => {
    try {
      setLoading(true);
      setError(null);

      const updatedUser = await apiClient.updateProfile(data);
      setUser(updatedUser);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Profile update failed';
      setError(errorMessage);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const clearError = () => {
    setError(null);
  };

  const value: AuthContextType = {
    user,
    loading,
    error,
    login,
    register,
    logout,
    updateProfile,
    clearError,
    isAuthenticated: !!user,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}