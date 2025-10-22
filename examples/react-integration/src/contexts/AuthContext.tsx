import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { User, authClient, AuthResponse } from '../lib/auth-client';
import toast from 'react-hot-toast';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, firstName: string, lastName: string) => Promise<void>;
  logout: () => Promise<void>;
  updateProfile: (updates: Partial<User>) => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const isAuthenticated = !!user && authClient.isAuthenticated();

  // Load user on mount if token exists
  useEffect(() => {
    const loadUser = async () => {
      if (authClient.isAuthenticated()) {
        try {
          const userData = await authClient.getCurrentUser();
          setUser(userData);
        } catch (error) {
          console.error('Failed to load user:', error);
          // Token might be invalid, clear it
          await authClient.logout();
        }
      }
      setLoading(false);
    };

    loadUser();
  }, []);

  const login = async (email: string, password: string): Promise<void> => {
    try {
      setLoading(true);
      const authResponse: AuthResponse = await authClient.login({ email, password });
      setUser(authResponse.user);
      toast.success('Successfully logged in!');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Login failed';
      toast.error(message);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const register = async (
    email: string,
    password: string,
    firstName: string,
    lastName: string
  ): Promise<void> => {
    try {
      setLoading(true);
      const authResponse: AuthResponse = await authClient.register({
        email,
        password,
        first_name: firstName,
        last_name: lastName,
      });
      setUser(authResponse.user);
      toast.success('Account created successfully!');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Registration failed';
      toast.error(message);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const logout = async (): Promise<void> => {
    try {
      setLoading(true);
      await authClient.logout();
      setUser(null);
      toast.success('Successfully logged out');
    } catch (error) {
      console.error('Logout error:', error);
      // Still clear user state even if API call fails
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const updateProfile = async (updates: Partial<User>): Promise<void> => {
    try {
      const updatedUser = await authClient.updateProfile(updates);
      setUser(updatedUser);
      toast.success('Profile updated successfully!');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Profile update failed';
      toast.error(message);
      throw error;
    }
  };

  const refreshUser = async (): Promise<void> => {
    try {
      if (authClient.isAuthenticated()) {
        const userData = await authClient.getCurrentUser();
        setUser(userData);
      }
    } catch (error) {
      console.error('Failed to refresh user:', error);
      setUser(null);
    }
  };

  const value: AuthContextType = {
    user,
    loading,
    isAuthenticated,
    login,
    register,
    logout,
    updateProfile,
    refreshUser,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;