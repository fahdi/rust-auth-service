// Main exports for the React Auth Hooks library

// Context and Provider
export { AuthProvider, useAuthContext } from './context/AuthContext';

// Hooks
export { useAuth } from './hooks/useAuth';
export { useUser } from './hooks/useUser';
export { useApi } from './hooks/useApi';

// Types
export type {
  User,
  LoginRequest,
  RegisterRequest,
  UpdateProfileRequest,
  RefreshTokenRequest,
  ResetPasswordRequest,
  ForgotPasswordRequest,
  VerifyEmailRequest,
  AuthResponse,
  TokenRefreshResponse,
  ApiError,
  HealthResponse,
  AuthConfig,
  AuthState,
  AuthActions,
  UseAuthReturn,
  UseUserReturn,
  UseApiReturn,
  AuthContextType,
  AuthEvent,
} from './types';

// Utilities
export { AuthApiClient } from './utils/api-client';

// Default export - the main provider
export { AuthProvider as default } from './context/AuthContext';