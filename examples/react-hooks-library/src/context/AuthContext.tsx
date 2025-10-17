import React, { createContext, useContext, useReducer, useEffect, ReactNode } from 'react';
import { AuthApiClient } from '../utils/api-client';
import {
  AuthContextType,
  AuthConfig,
  AuthState,
  AuthEvent,
  LoginRequest,
  RegisterRequest,
  UpdateProfileRequest,
  ForgotPasswordRequest,
  ResetPasswordRequest,
  VerifyEmailRequest,
} from '../types';

// Auth reducer for state management
function authReducer(state: AuthState, action: AuthEvent): AuthState {
  switch (action.type) {
    case 'INITIALIZE_START':
      return {
        ...state,
        loading: true,
        error: null,
      };
    case 'INITIALIZE_SUCCESS':
      return {
        ...state,
        loading: false,
        error: null,
        user: action.payload.user,
        isAuthenticated: !!action.payload.user,
        isInitialized: true,
      };
    case 'INITIALIZE_ERROR':
      return {
        ...state,
        loading: false,
        error: action.payload.error,
        user: null,
        isAuthenticated: false,
        isInitialized: true,
      };
    case 'LOGIN_START':
    case 'REGISTER_START':
    case 'UPDATE_PROFILE_START':
      return {
        ...state,
        loading: true,
        error: null,
      };
    case 'LOGIN_SUCCESS':
    case 'REGISTER_SUCCESS':
    case 'UPDATE_PROFILE_SUCCESS':
      return {
        ...state,
        loading: false,
        error: null,
        user: action.payload.user,
        isAuthenticated: true,
      };
    case 'LOGIN_ERROR':
    case 'REGISTER_ERROR':
    case 'UPDATE_PROFILE_ERROR':
    case 'TOKEN_REFRESH_ERROR':
      return {
        ...state,
        loading: false,
        error: action.payload.error,
      };
    case 'TOKEN_REFRESH_SUCCESS':
      return {
        ...state,
        error: null,
      };
    case 'LOGOUT':
      return {
        ...state,
        loading: false,
        error: null,
        user: null,
        isAuthenticated: false,
      };
    case 'CLEAR_ERROR':
      return {
        ...state,
        error: null,
      };
    default:
      return state;
  }
}

const initialState: AuthState = {
  user: null,
  loading: true,
  error: null,
  isAuthenticated: false,
  isInitialized: false,
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
  config?: AuthConfig;
}

export function AuthProvider({ children, config = {} }: AuthProviderProps) {
  const [state, dispatch] = useReducer(authReducer, initialState);
  const apiClient = React.useMemo(() => new AuthApiClient(config), [config]);

  // Initialize authentication state on mount
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        dispatch({ type: 'INITIALIZE_START' });

        // Check if we have a token
        const hasToken = apiClient.hasValidToken();
        
        if (hasToken) {
          // Try to get user profile to verify token validity
          const userProfile = await apiClient.getProfile();
          dispatch({ 
            type: 'INITIALIZE_SUCCESS', 
            payload: { user: userProfile }
          });
        } else {
          dispatch({ 
            type: 'INITIALIZE_SUCCESS', 
            payload: { user: null }
          });
        }
      } catch (err) {
        // Token is invalid or expired, clear it
        dispatch({ 
          type: 'INITIALIZE_ERROR', 
          payload: { 
            error: err instanceof Error ? err.message : 'Initialization failed'
          }
        });
      }
    };

    initializeAuth();
  }, [apiClient]);

  // Auto-refresh token if configured
  useEffect(() => {
    if (!config.autoRefresh || !state.isAuthenticated) return;

    const refreshThreshold = config.refreshThreshold || 10; // 10 minutes default
    const refreshInterval = (refreshThreshold - 1) * 60 * 1000; // Convert to milliseconds

    const interval = setInterval(async () => {
      try {
        await apiClient.refreshAccessToken();
        dispatch({ type: 'TOKEN_REFRESH_SUCCESS' });
      } catch (err) {
        dispatch({ 
          type: 'TOKEN_REFRESH_ERROR', 
          payload: { 
            error: err instanceof Error ? err.message : 'Token refresh failed'
          }
        });
      }
    }, refreshInterval);

    return () => clearInterval(interval);
  }, [apiClient, config.autoRefresh, config.refreshThreshold, state.isAuthenticated]);

  const login = async (credentials: LoginRequest) => {
    try {
      dispatch({ type: 'LOGIN_START' });
      const response = await apiClient.login(credentials);
      dispatch({ 
        type: 'LOGIN_SUCCESS', 
        payload: { user: response.user }
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Login failed';
      dispatch({ 
        type: 'LOGIN_ERROR', 
        payload: { error: errorMessage }
      });
      throw err;
    }
  };

  const register = async (userData: RegisterRequest) => {
    try {
      dispatch({ type: 'REGISTER_START' });
      const response = await apiClient.register(userData);
      dispatch({ 
        type: 'REGISTER_SUCCESS', 
        payload: { user: response.user }
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Registration failed';
      dispatch({ 
        type: 'REGISTER_ERROR', 
        payload: { error: errorMessage }
      });
      throw err;
    }
  };

  const logout = async () => {
    try {
      await apiClient.logout();
    } catch (err) {
      // Even if logout fails on server, clear local state
      console.error('Logout error:', err);
    } finally {
      dispatch({ type: 'LOGOUT' });
    }
  };

  const updateProfile = async (data: UpdateProfileRequest) => {
    try {
      dispatch({ type: 'UPDATE_PROFILE_START' });
      const updatedUser = await apiClient.updateProfile(data);
      dispatch({ 
        type: 'UPDATE_PROFILE_SUCCESS', 
        payload: { user: updatedUser }
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Profile update failed';
      dispatch({ 
        type: 'UPDATE_PROFILE_ERROR', 
        payload: { error: errorMessage }
      });
      throw err;
    }
  };

  const refreshToken = async () => {
    try {
      await apiClient.refreshAccessToken();
      dispatch({ type: 'TOKEN_REFRESH_SUCCESS' });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Token refresh failed';
      dispatch({ 
        type: 'TOKEN_REFRESH_ERROR', 
        payload: { error: errorMessage }
      });
      throw err;
    }
  };

  const clearError = () => {
    dispatch({ type: 'CLEAR_ERROR' });
  };

  const forgotPassword = async (data: ForgotPasswordRequest) => {
    await apiClient.forgotPassword(data);
  };

  const resetPassword = async (data: ResetPasswordRequest) => {
    await apiClient.resetPassword(data);
  };

  const verifyEmail = async (data: VerifyEmailRequest) => {
    await apiClient.verifyEmail(data);
  };

  const value: AuthContextType = {
    ...state,
    config,
    login,
    register,
    logout,
    updateProfile,
    refreshToken,
    clearError,
    forgotPassword,
    resetPassword,
    verifyEmail,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuthContext(): AuthContextType {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuthContext must be used within an AuthProvider');
  }
  return context;
}

export { AuthContext };