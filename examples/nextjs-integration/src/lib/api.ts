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
} from './types';

class AuthApiClient {
  private baseUrl: string;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;

  constructor(baseUrl: string = process.env.API_BASE_URL || 'http://localhost:8080') {
    this.baseUrl = baseUrl;
    this.loadTokensFromStorage();
  }

  private loadTokensFromStorage() {
    if (typeof window !== 'undefined') {
      this.accessToken = localStorage.getItem('access_token');
      this.refreshToken = localStorage.getItem('refresh_token');
    }
  }

  private saveTokensToStorage(accessToken: string, refreshToken: string) {
    if (typeof window !== 'undefined') {
      localStorage.setItem('access_token', accessToken);
      localStorage.setItem('refresh_token', refreshToken);
    }
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
  }

  private clearTokensFromStorage() {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
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
          errorData = {
            error: 'network_error',
            message: `Request failed with status ${response.status}`,
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

  // Token management
  getAccessToken(): string | null {
    return this.accessToken;
  }

  hasValidToken(): boolean {
    return !!this.accessToken;
  }
}

// Export singleton instance
export const apiClient = new AuthApiClient();
export default AuthApiClient;