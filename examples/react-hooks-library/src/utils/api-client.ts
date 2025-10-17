import {
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
  HealthResponse,
  ApiError,
  AuthConfig,
} from '../types';

export class AuthApiClient {
  private baseUrl: string;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private storageType: 'localStorage' | 'sessionStorage' | 'memory';
  private memoryStorage: { [key: string]: string } = {};

  constructor(config: AuthConfig = {}) {
    this.baseUrl = config.baseUrl || 'http://localhost:8080';
    this.storageType = config.storageType || 'localStorage';
    this.loadTokensFromStorage();
  }

  private getStorage() {
    if (typeof window === 'undefined') return null;
    
    switch (this.storageType) {
      case 'localStorage':
        return localStorage;
      case 'sessionStorage':
        return sessionStorage;
      case 'memory':
        return {
          getItem: (key: string) => this.memoryStorage[key] || null,
          setItem: (key: string, value: string) => { this.memoryStorage[key] = value; },
          removeItem: (key: string) => { delete this.memoryStorage[key]; },
        };
      default:
        return localStorage;
    }
  }

  private loadTokensFromStorage() {
    const storage = this.getStorage();
    if (!storage) return;

    this.accessToken = storage.getItem('access_token');
    this.refreshToken = storage.getItem('refresh_token');
    
    // Fallback to cookies if localStorage is empty (for SSR compatibility)
    if (!this.accessToken && typeof document !== 'undefined') {
      const cookies = document.cookie.split(';');
      for (const cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'access_token') this.accessToken = value;
        if (name === 'refresh_token') this.refreshToken = value;
      }
    }
  }

  private saveTokensToStorage(accessToken: string, refreshToken: string) {
    const storage = this.getStorage();
    if (!storage) return;

    storage.setItem('access_token', accessToken);
    storage.setItem('refresh_token', refreshToken);
    
    // Also store in cookies for SSR/middleware access (if in browser)
    if (typeof document !== 'undefined') {
      const isSecure = window.location.protocol === 'https:' ? '; secure' : '';
      document.cookie = `access_token=${accessToken}; path=/${isSecure}; samesite=strict`;
      document.cookie = `refresh_token=${refreshToken}; path=/${isSecure}; samesite=strict`;
    }
    
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
  }

  private clearTokensFromStorage() {
    const storage = this.getStorage();
    if (storage) {
      storage.removeItem('access_token');
      storage.removeItem('refresh_token');
    }
    
    // Also clear cookies
    if (typeof document !== 'undefined') {
      document.cookie = 'access_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
      document.cookie = 'refresh_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
    }
    
    this.accessToken = null;
    this.refreshToken = null;
  }

  private async makeRequest<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    
    const defaultHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.accessToken) {
      defaultHeaders.Authorization = `Bearer ${this.accessToken}`;
    }

    const config: RequestInit = {
      ...options,
      headers: {
        ...defaultHeaders,
        ...options.headers,
      },
    };

    try {
      const response = await fetch(url, config);
      
      if (!response.ok) {
        // Try to parse error response
        let errorData: ApiError;
        try {
          errorData = await response.json();
        } catch {
          // Provide user-friendly messages for common HTTP status codes
          let message = `Request failed with status ${response.status}`;
          if (response.status === 423) {
            message = 'Account is temporarily locked due to too many failed login attempts. Please try again later.';
          } else if (response.status === 401) {
            message = 'Invalid email or password. Please check your credentials and try again.';
          } else if (response.status === 429) {
            message = 'Too many requests. Please wait a moment before trying again.';
          } else if (response.status >= 500) {
            message = 'Server error. Please try again later.';
          } else if (response.status >= 400) {
            message = 'Invalid request. Please check your input and try again.';
          }
          
          errorData = {
            error: 'network_error',
            message,
          };
        }

        // If unauthorized and we have a refresh token, try to refresh
        if (response.status === 401 && this.refreshToken && endpoint !== '/auth/refresh') {
          try {
            await this.refreshAccessToken();
            // Retry the original request with new token
            return this.makeRequest<T>(endpoint, options);
          } catch (refreshError) {
            // Refresh failed, clear tokens and re-throw original error
            this.clearTokensFromStorage();
            throw new Error(errorData.message);
          }
        }

        throw new Error(errorData.message);
      }

      // Handle empty responses (like logout)
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return response.json();
      } else {
        return {} as T;
      }
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error('Network error occurred');
    }
  }

  // Authentication methods
  async login(credentials: LoginRequest): Promise<AuthResponse> {
    const response = await this.makeRequest<AuthResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });

    this.saveTokensToStorage(response.access_token, response.refresh_token);
    return response;
  }

  async register(userData: RegisterRequest): Promise<AuthResponse> {
    const response = await this.makeRequest<AuthResponse>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    });

    this.saveTokensToStorage(response.access_token, response.refresh_token);
    return response;
  }

  async logout(): Promise<void> {
    try {
      await this.makeRequest('/auth/logout', {
        method: 'POST',
      });
    } finally {
      this.clearTokensFromStorage();
    }
  }

  async refreshAccessToken(): Promise<TokenRefreshResponse> {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await this.makeRequest<TokenRefreshResponse>('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: this.refreshToken }),
    });

    this.saveTokensToStorage(response.access_token, response.refresh_token);
    return response;
  }

  // User profile methods
  async getProfile(): Promise<User> {
    return this.makeRequest<User>('/auth/me');
  }

  async updateProfile(data: UpdateProfileRequest): Promise<User> {
    return this.makeRequest<User>('/auth/profile', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  // Password reset methods
  async forgotPassword(data: ForgotPasswordRequest): Promise<void> {
    await this.makeRequest('/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async resetPassword(data: ResetPasswordRequest): Promise<void> {
    await this.makeRequest('/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // Email verification
  async verifyEmail(data: VerifyEmailRequest): Promise<void> {
    await this.makeRequest('/auth/verify', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // Health check
  async getHealth(): Promise<HealthResponse> {
    return this.makeRequest<HealthResponse>('/health');
  }

  // Generic API methods for custom requests
  async get<T>(endpoint: string): Promise<T> {
    return this.makeRequest<T>(endpoint, { method: 'GET' });
  }

  async post<T>(endpoint: string, data?: any): Promise<T> {
    return this.makeRequest<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async put<T>(endpoint: string, data?: any): Promise<T> {
    return this.makeRequest<T>(endpoint, {
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async delete<T>(endpoint: string): Promise<T> {
    return this.makeRequest<T>(endpoint, { method: 'DELETE' });
  }

  // Token management
  getAccessToken(): string | null {
    return this.accessToken;
  }

  getRefreshToken(): string | null {
    return this.refreshToken;
  }

  hasValidToken(): boolean {
    return !!this.accessToken;
  }

  // Update configuration
  updateConfig(config: Partial<AuthConfig>) {
    if (config.baseUrl) {
      this.baseUrl = config.baseUrl;
    }
    if (config.storageType && config.storageType !== this.storageType) {
      // Clear old storage and reload from new storage
      this.clearTokensFromStorage();
      this.storageType = config.storageType;
      this.loadTokensFromStorage();
    }
  }
}