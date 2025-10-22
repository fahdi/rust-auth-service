# API Integration Guide

This guide provides comprehensive examples for integrating with the Rust Auth Service API.

## Table of Contents

- [Quick Start](#quick-start)
- [Authentication Flow](#authentication-flow)
- [Code Examples](#code-examples)
  - [JavaScript/TypeScript](#javascripttypescript)
  - [Python](#python)
  - [cURL](#curl)
  - [Rust](#rust)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Best Practices](#best-practices)
- [Testing](#testing)

## Quick Start

1. **Start the service** using Docker:
   ```bash
   cd rust-auth-service/docker
   ./scripts/setup-dev.sh
   ```

2. **Access the API** at `https://localhost/api`

3. **View interactive documentation** at `https://localhost/docs`

## Authentication Flow

### 1. User Registration

```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "user_id": "usr_123456789",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user",
    "email_verified": false
  }
}
```

### 2. Email Verification

```http
POST /auth/verify
Content-Type: application/json

{
  "token": "verification_token_from_email"
}
```

### 3. User Login

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

### 4. Using Protected Endpoints

```http
GET /auth/me
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

## Code Examples

### JavaScript/TypeScript

#### Basic Client Setup

```typescript
class AuthClient {
  private baseUrl: string;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;

  constructor(baseUrl: string = 'https://localhost/api') {
    this.baseUrl = baseUrl;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const config: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    };

    // Add auth header if token exists
    if (this.accessToken) {
      config.headers = {
        ...config.headers,
        Authorization: `Bearer ${this.accessToken}`,
      };
    }

    const response = await fetch(url, config);

    if (!response.ok) {
      if (response.status === 401 && this.refreshToken) {
        // Try to refresh token
        const refreshed = await this.refreshAccessToken();
        if (refreshed) {
          // Retry original request with new token
          config.headers = {
            ...config.headers,
            Authorization: `Bearer ${this.accessToken}`,
          };
          const retryResponse = await fetch(url, config);
          if (retryResponse.ok) {
            return retryResponse.json();
          }
        }
      }
      
      const error = await response.json();
      throw new Error(error.message || 'Request failed');
    }

    return response.json();
  }

  async register(userData: {
    email: string;
    password: string;
    first_name: string;
    last_name: string;
  }) {
    const response = await this.request<AuthResponse>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    });
    
    this.setTokens(response);
    return response;
  }

  async login(email: string, password: string) {
    const response = await this.request<AuthResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    
    this.setTokens(response);
    return response;
  }

  async logout() {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } finally {
      this.clearTokens();
    }
  }

  async getCurrentUser() {
    return this.request<UserResponse>('/auth/me');
  }

  async updateProfile(updates: Partial<UpdateUserRequest>) {
    return this.request<UserResponse>('/auth/profile', {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  }

  async verifyEmail(token: string) {
    return this.request('/auth/verify', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  async forgotPassword(email: string) {
    return this.request('/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  async resetPassword(token: string, newPassword: string) {
    return this.request('/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, new_password: newPassword }),
    });
  }

  private async refreshAccessToken(): Promise<boolean> {
    if (!this.refreshToken) return false;

    try {
      const response = await this.request<AuthResponse>('/auth/refresh', {
        method: 'POST',
        body: JSON.stringify({ refresh_token: this.refreshToken }),
      });
      
      this.setTokens(response);
      return true;
    } catch {
      this.clearTokens();
      return false;
    }
  }

  private setTokens(authResponse: AuthResponse) {
    this.accessToken = authResponse.access_token;
    this.refreshToken = authResponse.refresh_token;
    
    // Store in localStorage for persistence
    localStorage.setItem('access_token', this.accessToken);
    localStorage.setItem('refresh_token', this.refreshToken);
  }

  private clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  }

  // Load tokens from localStorage on initialization
  loadTokensFromStorage() {
    this.accessToken = localStorage.getItem('access_token');
    this.refreshToken = localStorage.getItem('refresh_token');
  }

  isAuthenticated(): boolean {
    return !!this.accessToken;
  }
}

// Type definitions
interface AuthResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: UserResponse;
}

interface UserResponse {
  user_id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: string;
  is_active: boolean;
  email_verified: boolean;
  last_login?: string;
  created_at: string;
}

interface UpdateUserRequest {
  email?: string;
  first_name?: string;
  last_name?: string;
  metadata?: Record<string, any>;
}

// Usage example
async function example() {
  const auth = new AuthClient();
  auth.loadTokensFromStorage();

  try {
    // Register new user
    const authResponse = await auth.register({
      email: 'user@example.com',
      password: 'SecurePass123!',
      first_name: 'John',
      last_name: 'Doe',
    });
    
    console.log('Registered successfully:', authResponse.user);

    // Get current user
    const user = await auth.getCurrentUser();
    console.log('Current user:', user);

    // Update profile
    const updatedUser = await auth.updateProfile({
      first_name: 'Jane',
    });
    console.log('Updated user:', updatedUser);

  } catch (error) {
    console.error('Auth error:', error);
  }
}
```

#### React Hook

```typescript
import { useState, useEffect, useContext, createContext } from 'react';

interface AuthContextType {
  user: UserResponse | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (userData: RegisterData) => Promise<void>;
  logout: () => Promise<void>;
  updateProfile: (updates: Partial<UpdateUserRequest>) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const authClient = new AuthClient();

  useEffect(() => {
    // Load tokens and current user on mount
    authClient.loadTokensFromStorage();
    if (authClient.isAuthenticated()) {
      getCurrentUser();
    } else {
      setIsLoading(false);
    }
  }, []);

  const getCurrentUser = async () => {
    try {
      const userData = await authClient.getCurrentUser();
      setUser(userData);
    } catch (error) {
      console.error('Failed to get current user:', error);
      authClient.clearTokens();
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (email: string, password: string) => {
    const response = await authClient.login(email, password);
    setUser(response.user);
  };

  const register = async (userData: RegisterData) => {
    const response = await authClient.register(userData);
    setUser(response.user);
  };

  const logout = async () => {
    await authClient.logout();
    setUser(null);
  };

  const updateProfile = async (updates: Partial<UpdateUserRequest>) => {
    const updatedUser = await authClient.updateProfile(updates);
    setUser(updatedUser);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
        updateProfile,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
```

### Python

```python
import requests
import json
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

class AuthClient:
    def __init__(self, base_url: str = "https://localhost/api"):
        self.base_url = base_url
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.session = requests.Session()
        
        # Configure session for SSL (disable verification for local dev)
        self.session.verify = False
        
    def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> requests.Response:
        """Make HTTP request with automatic token refresh"""
        url = f"{self.base_url}{endpoint}"
        
        request_headers = {"Content-Type": "application/json"}
        if headers:
            request_headers.update(headers)
            
        if self.access_token:
            request_headers["Authorization"] = f"Bearer {self.access_token}"
        
        json_data = json.dumps(data) if data else None
        
        response = self.session.request(
            method=method,
            url=url,
            data=json_data,
            headers=request_headers
        )
        
        # Handle token refresh on 401
        if response.status_code == 401 and self.refresh_token:
            if self._refresh_access_token():
                # Retry with new token
                request_headers["Authorization"] = f"Bearer {self.access_token}"
                response = self.session.request(
                    method=method,
                    url=url,
                    data=json_data,
                    headers=request_headers
                )
        
        return response
    
    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """Handle response and raise exceptions for errors"""
        if response.status_code >= 400:
            try:
                error_data = response.json()
                raise Exception(f"API Error: {error_data.get('message', 'Unknown error')}")
            except json.JSONDecodeError:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
        
        return response.json()
    
    def register(
        self, 
        email: str, 
        password: str, 
        first_name: str, 
        last_name: str,
        role: Optional[str] = None
    ) -> Dict[str, Any]:
        """Register a new user"""
        data = {
            "email": email,
            "password": password,
            "first_name": first_name,
            "last_name": last_name
        }
        if role:
            data["role"] = role
            
        response = self._make_request("POST", "/auth/register", data)
        result = self._handle_response(response)
        
        # Store tokens
        self.access_token = result["access_token"]
        self.refresh_token = result["refresh_token"]
        
        return result
    
    def login(self, email: str, password: str) -> Dict[str, Any]:
        """Login user"""
        data = {"email": email, "password": password}
        response = self._make_request("POST", "/auth/login", data)
        result = self._handle_response(response)
        
        # Store tokens
        self.access_token = result["access_token"]
        self.refresh_token = result["refresh_token"]
        
        return result
    
    def logout(self) -> None:
        """Logout user"""
        try:
            response = self._make_request("POST", "/auth/logout")
            self._handle_response(response)
        finally:
            self.access_token = None
            self.refresh_token = None
    
    def get_current_user(self) -> Dict[str, Any]:
        """Get current user profile"""
        response = self._make_request("GET", "/auth/me")
        return self._handle_response(response)
    
    def update_profile(self, **updates) -> Dict[str, Any]:
        """Update user profile"""
        response = self._make_request("PUT", "/auth/profile", updates)
        return self._handle_response(response)
    
    def verify_email(self, token: str) -> Dict[str, Any]:
        """Verify email with token"""
        data = {"token": token}
        response = self._make_request("POST", "/auth/verify", data)
        return self._handle_response(response)
    
    def forgot_password(self, email: str) -> Dict[str, Any]:
        """Request password reset"""
        data = {"email": email}
        response = self._make_request("POST", "/auth/forgot-password", data)
        return self._handle_response(response)
    
    def reset_password(self, token: str, new_password: str) -> Dict[str, Any]:
        """Reset password with token"""
        data = {"token": token, "new_password": new_password}
        response = self._make_request("POST", "/auth/reset-password", data)
        return self._handle_response(response)
    
    def _refresh_access_token(self) -> bool:
        """Refresh access token using refresh token"""
        if not self.refresh_token:
            return False
            
        try:
            data = {"refresh_token": self.refresh_token}
            response = self._make_request("POST", "/auth/refresh", data)
            result = self._handle_response(response)
            
            self.access_token = result["access_token"]
            self.refresh_token = result["refresh_token"]
            return True
        except:
            self.access_token = None
            self.refresh_token = None
            return False
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated"""
        return bool(self.access_token)

# Usage example
def main():
    client = AuthClient()
    
    try:
        # Register new user
        auth_response = client.register(
            email="user@example.com",
            password="SecurePass123!",
            first_name="John",
            last_name="Doe"
        )
        
        print(f"Registered user: {auth_response['user']['email']}")
        
        # Get current user
        user = client.get_current_user()
        print(f"Current user: {user['first_name']} {user['last_name']}")
        
        # Update profile
        updated_user = client.update_profile(first_name="Jane")
        print(f"Updated name: {updated_user['first_name']}")
        
        # Logout
        client.logout()
        print("Logged out successfully")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

### cURL

```bash
#!/bin/bash

# Configuration
API_BASE="https://localhost/api"
EMAIL="user@example.com"
PASSWORD="SecurePass123!"

echo "=== Rust Auth Service API Examples ==="

# 1. Register user
echo "1. Registering user..."
REGISTER_RESPONSE=$(curl -s -X POST "$API_BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "'$EMAIL'",
    "password": "'$PASSWORD'",
    "first_name": "John",
    "last_name": "Doe"
  }' | jq .)

echo "Register response: $REGISTER_RESPONSE"

# Extract access token
ACCESS_TOKEN=$(echo $REGISTER_RESPONSE | jq -r '.access_token')
echo "Access token: ${ACCESS_TOKEN:0:50}..."

# 2. Get current user
echo -e "\n2. Getting current user..."
curl -s -X GET "$API_BASE/auth/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

# 3. Update profile
echo -e "\n3. Updating profile..."
curl -s -X PUT "$API_BASE/auth/profile" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{
    "first_name": "Jane"
  }' | jq .

# 4. Health check
echo -e "\n4. Health check..."
curl -s -X GET "$API_BASE/health" | jq .

# 5. Service stats
echo -e "\n5. Service stats..."
curl -s -X GET "$API_BASE/stats" | jq .

# 6. Logout
echo -e "\n6. Logging out..."
curl -s -X POST "$API_BASE/auth/logout" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

echo -e "\nDone!"
```

### Rust

```rust
use reqwest::{Client, header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE}};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::{Result, anyhow};

#[derive(Debug, Serialize)]
struct RegisterRequest {
    email: String,
    password: String,
    first_name: String,
    last_name: String,
}

#[derive(Debug, Serialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    expires_in: u64,
    user: UserResponse,
}

#[derive(Debug, Deserialize)]
struct UserResponse {
    user_id: String,
    email: String,
    first_name: String,
    last_name: String,
    role: String,
    is_active: bool,
    email_verified: bool,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
    message: String,
    details: Option<serde_json::Value>,
}

pub struct AuthClient {
    client: Client,
    base_url: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

impl AuthClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.into(),
            access_token: None,
            refresh_token: None,
        }
    }

    fn create_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        
        if let Some(token) = &self.access_token {
            let auth_value = format!("Bearer {}", token);
            headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_value).unwrap());
        }
        
        headers
    }

    async fn make_request<T, R>(&self, method: reqwest::Method, endpoint: &str, body: Option<&T>) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let url = format!("{}{}", self.base_url, endpoint);
        let mut request = self.client.request(method, &url).headers(self.create_headers());
        
        if let Some(body) = body {
            request = request.json(body);
        }
        
        let response = request.send().await?;
        
        if !response.status().is_success() {
            let error: ErrorResponse = response.json().await?;
            return Err(anyhow!("API Error: {}", error.message));
        }
        
        let result: R = response.json().await?;
        Ok(result)
    }

    pub async fn register(
        &mut self,
        email: String,
        password: String,
        first_name: String,
        last_name: String,
    ) -> Result<AuthResponse> {
        let request = RegisterRequest {
            email,
            password,
            first_name,
            last_name,
        };
        
        let response: AuthResponse = self
            .make_request(reqwest::Method::POST, "/auth/register", Some(&request))
            .await?;
        
        // Store tokens
        self.access_token = Some(response.access_token.clone());
        self.refresh_token = Some(response.refresh_token.clone());
        
        Ok(response)
    }

    pub async fn login(&mut self, email: String, password: String) -> Result<AuthResponse> {
        let request = LoginRequest { email, password };
        
        let response: AuthResponse = self
            .make_request(reqwest::Method::POST, "/auth/login", Some(&request))
            .await?;
        
        // Store tokens
        self.access_token = Some(response.access_token.clone());
        self.refresh_token = Some(response.refresh_token.clone());
        
        Ok(response)
    }

    pub async fn get_current_user(&self) -> Result<UserResponse> {
        self.make_request(reqwest::Method::GET, "/auth/me", None::<&()>)
            .await
    }

    pub async fn update_profile(&self, updates: HashMap<String, serde_json::Value>) -> Result<UserResponse> {
        self.make_request(reqwest::Method::PUT, "/auth/profile", Some(&updates))
            .await
    }

    pub async fn logout(&mut self) -> Result<()> {
        let _: serde_json::Value = self
            .make_request(reqwest::Method::POST, "/auth/logout", None::<&()>)
            .await?;
        
        // Clear tokens
        self.access_token = None;
        self.refresh_token = None;
        
        Ok(())
    }

    pub fn is_authenticated(&self) -> bool {
        self.access_token.is_some()
    }
}

// Usage example
#[tokio::main]
async fn main() -> Result<()> {
    let mut client = AuthClient::new("https://localhost/api");
    
    // Register new user
    let auth_response = client
        .register(
            "user@example.com".to_string(),
            "SecurePass123!".to_string(),
            "John".to_string(),
            "Doe".to_string(),
        )
        .await?;
    
    println!("Registered user: {}", auth_response.user.email);
    
    // Get current user
    let user = client.get_current_user().await?;
    println!("Current user: {} {}", user.first_name, user.last_name);
    
    // Update profile
    let mut updates = HashMap::new();
    updates.insert("first_name".to_string(), serde_json::Value::String("Jane".to_string()));
    
    let updated_user = client.update_profile(updates).await?;
    println!("Updated name: {}", updated_user.first_name);
    
    // Logout
    client.logout().await?;
    println!("Logged out successfully");
    
    Ok(())
}
```

## Error Handling

### Common Error Responses

```json
{
  "error": "ValidationError",
  "message": "Invalid email format",
  "details": {
    "field": "email",
    "code": "invalid_format"
  }
}
```

### Error Types

| Status Code | Error Type | Description |
|-------------|------------|-------------|
| 400 | ValidationError | Invalid input data |
| 401 | AuthenticationError | Invalid credentials or token |
| 403 | AuthorizationError | Insufficient permissions |
| 404 | NotFoundError | Resource not found |
| 409 | ConflictError | Resource already exists |
| 423 | AccountLockedError | Account locked due to failed attempts |
| 429 | RateLimitError | Too many requests |
| 500 | InternalServerError | Server error |

### Handling Errors in Code

```typescript
try {
  const user = await authClient.login(email, password);
} catch (error) {
  if (error.message.includes('Invalid credentials')) {
    // Handle login failure
    showError('Email or password is incorrect');
  } else if (error.message.includes('Account locked')) {
    // Handle locked account
    showError('Account is locked. Try again later.');
  } else if (error.message.includes('Rate limit')) {
    // Handle rate limiting
    showError('Too many attempts. Please wait and try again.');
  } else {
    // Handle other errors
    showError('Login failed. Please try again.');
  }
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Authentication endpoints**: 5 requests per minute per IP
- **General endpoints**: 100 requests per minute per IP  
- **Admin endpoints**: 50 requests per minute per authenticated user

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642694400
```

### Handling Rate Limits

```typescript
async function makeRequestWithRetry(requestFn: () => Promise<any>, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await requestFn();
    } catch (error) {
      if (error.message.includes('Rate limit') && attempt < maxRetries) {
        // Wait before retrying (exponential backoff)
        const delay = Math.pow(2, attempt) * 1000;
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      throw error;
    }
  }
}
```

## Best Practices

### 1. Token Management

- Store tokens securely (use httpOnly cookies in production)
- Implement automatic token refresh
- Clear tokens on logout
- Handle token expiration gracefully

### 2. Security

- Always use HTTPS in production
- Validate SSL certificates
- Implement proper error handling
- Don't log sensitive information

### 3. Performance

- Implement request caching where appropriate
- Use connection pooling
- Implement exponential backoff for retries
- Monitor API response times

### 4. User Experience

- Provide clear error messages
- Implement loading states
- Handle offline scenarios
- Provide user feedback for long operations

## Testing

### Unit Tests Example (Jest)

```typescript
describe('AuthClient', () => {
  let authClient: AuthClient;
  
  beforeEach(() => {
    authClient = new AuthClient('https://localhost/api');
  });

  it('should register a new user', async () => {
    const userData = {
      email: 'test@example.com',
      password: 'SecurePass123!',
      first_name: 'Test',
      last_name: 'User',
    };

    const response = await authClient.register(userData);
    
    expect(response.user.email).toBe(userData.email);
    expect(response.access_token).toBeDefined();
    expect(authClient.isAuthenticated()).toBe(true);
  });

  it('should handle login errors', async () => {
    await expect(
      authClient.login('invalid@example.com', 'wrongpassword')
    ).rejects.toThrow('Invalid credentials');
  });
});
```

### Integration Tests

```typescript
describe('Auth Flow Integration', () => {
  it('should complete full auth flow', async () => {
    const authClient = new AuthClient();
    
    // 1. Register
    const registerResponse = await authClient.register({
      email: 'integration@example.com',
      password: 'SecurePass123!',
      first_name: 'Integration',
      last_name: 'Test',
    });
    
    expect(registerResponse.user.email_verified).toBe(false);
    
    // 2. Verify email (would need actual token from email)
    // await authClient.verifyEmail(verificationToken);
    
    // 3. Login
    await authClient.logout();
    const loginResponse = await authClient.login(
      'integration@example.com',
      'SecurePass123!'
    );
    
    expect(loginResponse.user.email).toBe('integration@example.com');
    
    // 4. Get profile
    const user = await authClient.getCurrentUser();
    expect(user.email).toBe('integration@example.com');
    
    // 5. Update profile
    const updatedUser = await authClient.updateProfile({
      first_name: 'Updated',
    });
    expect(updatedUser.first_name).toBe('Updated');
    
    // 6. Logout
    await authClient.logout();
    expect(authClient.isAuthenticated()).toBe(false);
  });
});
```

This integration guide provides everything developers need to successfully integrate with the Rust Auth Service API across multiple programming languages and use cases.