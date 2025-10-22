import axios, { AxiosInstance, AxiosResponse } from 'axios';
import Cookies from 'js-cookie';

export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  is_active: boolean;
  is_verified: boolean;
  role: string;
  created_at: string;
  updated_at: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  first_name: string;
  last_name: string;
}

export interface ForgotPasswordRequest {
  email: string;
}

export interface ResetPasswordRequest {
  token: string;
  new_password: string;
}

export interface UpdateProfileRequest {
  first_name?: string;
  last_name?: string;
  email?: string;
}

export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}

export interface ApiError {
  error: string;
  message: string;
  details?: Record<string, any>;
}

export class AuthClient {
  private api: AxiosInstance;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private baseUrl: string;

  constructor(baseUrl: string = 'https://localhost/api') {
    this.baseUrl = baseUrl;
    this.api = axios.create({
      baseURL: baseUrl,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Load tokens from cookies
    this.accessToken = Cookies.get('access_token') || null;
    this.refreshToken = Cookies.get('refresh_token') || null;

    // Set up request interceptor to add auth headers
    this.api.interceptors.request.use((config) => {
      if (this.accessToken) {
        config.headers.Authorization = `Bearer ${this.accessToken}`;
      }
      return config;
    });

    // Set up response interceptor for token refresh
    this.api.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 401 && this.refreshToken) {
          try {
            await this.refreshAccessToken();
            // Retry the original request
            const originalRequest = error.config;
            originalRequest.headers.Authorization = `Bearer ${this.accessToken}`;
            return this.api.request(originalRequest);
          } catch (refreshError) {
            // Refresh failed, redirect to login
            this.clearTokens();
            window.location.href = '/login';
            return Promise.reject(refreshError);
          }
        }
        return Promise.reject(error);
      }
    );
  }

  private setTokens(accessToken: string, refreshToken?: string): void {
    this.accessToken = accessToken;
    
    // Store in HTTP-only cookies for security
    Cookies.set('access_token', accessToken, {
      secure: true,
      sameSite: 'strict',
      expires: 1, // 1 day
    });

    if (refreshToken) {
      this.refreshToken = refreshToken;
      Cookies.set('refresh_token', refreshToken, {
        secure: true,
        sameSite: 'strict',
        expires: 7, // 7 days
      });
    }
  }

  private clearTokens(): void {
    this.accessToken = null;
    this.refreshToken = null;
    Cookies.remove('access_token');
    Cookies.remove('refresh_token');
  }

  private handleApiError(error: any): never {
    if (error.response?.data) {
      throw new Error(error.response.data.message || error.response.data.error || 'An error occurred');
    }
    throw new Error(error.message || 'Network error');
  }

  /**
   * Register a new user
   */
  async register(userData: RegisterRequest): Promise<AuthResponse> {
    try {
      const response: AxiosResponse<AuthResponse> = await this.api.post('/auth/register', userData);
      const authData = response.data;
      
      this.setTokens(authData.access_token);
      return authData;
    } catch (error) {
      this.handleApiError(error);
    }
  }

  /**
   * Login with email and password
   */
  async login(credentials: LoginRequest): Promise<AuthResponse> {
    try {
      const response: AxiosResponse<AuthResponse> = await this.api.post('/auth/login', credentials);
      const authData = response.data;
      
      this.setTokens(authData.access_token);
      return authData;
    } catch (error) {
      this.handleApiError(error);
    }
  }

  /**
   * Logout current user
   */
  async logout(): Promise<void> {
    try {
      await this.api.post('/auth/logout');
    } catch (error) {
      // Continue with logout even if API call fails
      console.warn('Logout API call failed:', error);
    } finally {
      this.clearTokens();
    }
  }

  /**
   * Get current user profile
   */
  async getCurrentUser(): Promise<User> {
    try {
      const response: AxiosResponse<User> = await this.api.get('/auth/me');
      return response.data;
    } catch (error) {
      this.handleApiError(error);
    }
  }

  /**
   * Update user profile
   */
  async updateProfile(updates: UpdateProfileRequest): Promise<User> {
    try {
      const response: AxiosResponse<User> = await this.api.put('/auth/profile', updates);
      return response.data;
    } catch (error) {
      this.handleApiError(error);
    }
  }

  /**
   * Change user password
   */
  async changePassword(passwordData: ChangePasswordRequest): Promise<void> {
    try {
      await this.api.post('/auth/change-password', passwordData);
    } catch (error) {
      this.handleApiError(error);
    }
  }

  /**
   * Request password reset
   */
  async forgotPassword(email: string): Promise<void> {
    try {
      await this.api.post('/auth/forgot-password', { email });
    } catch (error) {
      this.handleApiError(error);
    }
  }

  /**
   * Reset password with token
   */
  async resetPassword(resetData: ResetPasswordRequest): Promise<void> {
    try {
      await this.api.post('/auth/reset-password', resetData);
    } catch (error) {
      this.handleApiError(error);
    }
  }

  /**
   * Verify email with token
   */
  async verifyEmail(token: string): Promise<void> {
    try {
      await this.api.post('/auth/verify', { token });
    } catch (error) {
      this.handleApiError(error);
    }
  }

  /**
   * Refresh access token
   */
  async refreshAccessToken(): Promise<string> {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const response: AxiosResponse<{ access_token: string }> = await this.api.post('/auth/refresh', {
        refresh_token: this.refreshToken,
      });
      
      const newAccessToken = response.data.access_token;
      this.setTokens(newAccessToken);
      return newAccessToken;
    } catch (error) {
      this.clearTokens();
      this.handleApiError(error);
    }
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    return !!this.accessToken;
  }

  /**
   * Get current access token
   */
  getAccessToken(): string | null {
    return this.accessToken;
  }

  /**
   * Check service health
   */
  async healthCheck(): Promise<any> {
    try {
      const response = await this.api.get('/health');
      return response.data;
    } catch (error) {
      this.handleApiError(error);
    }
  }
}

// Create a singleton instance
export const authClient = new AuthClient();

// Export default instance
export default authClient;