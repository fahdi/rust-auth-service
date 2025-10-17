// User types
export interface User {
  user_id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: string;
  is_active: boolean;
  email_verified: boolean;
  created_at: string;
  updated_at?: string;
  last_login?: string;
}

// Authentication request types
export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  first_name: string;
  last_name: string;
  role?: string;
}

export interface UpdateProfileRequest {
  first_name?: string;
  last_name?: string;
  email?: string;
}

export interface RefreshTokenRequest {
  refresh_token: string;
}

export interface ResetPasswordRequest {
  token: string;
  new_password: string;
}

export interface ForgotPasswordRequest {
  email: string;
}

export interface VerifyEmailRequest {
  token: string;
}

// Authentication response types
export interface AuthResponse {
  user: User;
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

export interface TokenRefreshResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

// API error types
export interface ApiError {
  error: string;
  message: string;
  details?: string;
}

// Health check types
export interface HealthResponse {
  status: string;
  timestamp: string;
  version: string;
  service: string;
  database: {
    status: string;
    type: string;
    connected: boolean;
    response_time_ms: number;
  };
  cache: {
    healthy: boolean;
    type: string;
    stats: {
      hits: number;
      misses: number;
      hit_ratio: number;
      total_operations: number;
    };
  };
}

// Hook-specific types
export interface AuthConfig {
  baseUrl?: string;
  storageType?: 'localStorage' | 'sessionStorage' | 'memory';
  autoRefresh?: boolean;
  refreshThreshold?: number; // Minutes before expiry to refresh
}

export interface AuthState {
  user: User | null;
  loading: boolean;
  error: string | null;
  isAuthenticated: boolean;
  isInitialized: boolean;
}

export interface AuthActions {
  login: (credentials: LoginRequest) => Promise<void>;
  register: (userData: RegisterRequest) => Promise<void>;
  logout: () => Promise<void>;
  updateProfile: (data: UpdateProfileRequest) => Promise<void>;
  refreshToken: () => Promise<void>;
  clearError: () => void;
  forgotPassword: (data: ForgotPasswordRequest) => Promise<void>;
  resetPassword: (data: ResetPasswordRequest) => Promise<void>;
  verifyEmail: (data: VerifyEmailRequest) => Promise<void>;
}

export interface UseAuthReturn extends AuthState, AuthActions {}

export interface UseUserReturn {
  user: User | null;
  loading: boolean;
  error: string | null;
  updateProfile: (data: UpdateProfileRequest) => Promise<void>;
  refreshUser: () => Promise<void>;
  clearError: () => void;
}

export interface UseApiReturn {
  loading: boolean;
  error: string | null;
  makeRequest: <T>(
    endpoint: string,
    options?: RequestInit
  ) => Promise<T>;
  get: <T>(endpoint: string) => Promise<T>;
  post: <T>(endpoint: string, data?: any) => Promise<T>;
  put: <T>(endpoint: string, data?: any) => Promise<T>;
  delete: <T>(endpoint: string) => Promise<T>;
  clearError: () => void;
}

// Context types
export interface AuthContextType extends UseAuthReturn {
  config: AuthConfig;
}

// Event types
export type AuthEvent = 
  | { type: 'LOGIN_START' }
  | { type: 'LOGIN_SUCCESS'; payload: { user: User } }
  | { type: 'LOGIN_ERROR'; payload: { error: string } }
  | { type: 'LOGOUT' }
  | { type: 'REGISTER_START' }
  | { type: 'REGISTER_SUCCESS'; payload: { user: User } }
  | { type: 'REGISTER_ERROR'; payload: { error: string } }
  | { type: 'UPDATE_PROFILE_START' }
  | { type: 'UPDATE_PROFILE_SUCCESS'; payload: { user: User } }
  | { type: 'UPDATE_PROFILE_ERROR'; payload: { error: string } }
  | { type: 'TOKEN_REFRESH_SUCCESS' }
  | { type: 'TOKEN_REFRESH_ERROR'; payload: { error: string } }
  | { type: 'CLEAR_ERROR' }
  | { type: 'INITIALIZE_START' }
  | { type: 'INITIALIZE_SUCCESS'; payload: { user: User | null } }
  | { type: 'INITIALIZE_ERROR'; payload: { error: string } };