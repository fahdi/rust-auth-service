# 🦀 Rust Auth Service - React Hooks Library

A comprehensive React hooks library for integrating with the Rust Auth Service. Provides easy-to-use hooks for authentication, user management, and API interactions with TypeScript support.

## ✨ Features

- 🪝 **React Hooks**: `useAuth`, `useUser`, `useApi` for complete authentication flows
- 🔒 **Authentication Management**: Login, logout, registration, and profile updates  
- 🔄 **Automatic Token Refresh**: Built-in token management with configurable refresh
- 📱 **Storage Options**: Support for localStorage, sessionStorage, or memory storage
- 🌐 **API Integration**: Pre-configured API client with error handling
- 📊 **Loading States**: Built-in loading and error state management
- 🎯 **TypeScript Support**: Full TypeScript definitions included
- ⚡ **Lightweight**: Minimal dependencies, optimized for performance
- 🧪 **SSR Compatible**: Works with Next.js and other SSR frameworks

## 📦 Installation

```bash
npm install @rust-auth-service/react-hooks
# or
yarn add @rust-auth-service/react-hooks
```

## 🚀 Quick Start

### 1. Wrap your app with AuthProvider

```tsx
import React from 'react';
import { AuthProvider } from '@rust-auth-service/react-hooks';
import App from './App';

function Root() {
  return (
    <AuthProvider
      config={{
        baseUrl: 'http://localhost:8080',
        storageType: 'localStorage',
        autoRefresh: true,
        refreshThreshold: 10, // Refresh 10 minutes before expiry
      }}
    >
      <App />
    </AuthProvider>
  );
}

export default Root;
```

### 2. Use authentication in your components

```tsx
import React from 'react';
import { useAuth } from '@rust-auth-service/react-hooks';

function LoginForm() {
  const { login, loading, error, isAuthenticated } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    
    try {
      await login({
        email: formData.get('email'),
        password: formData.get('password'),
      });
    } catch (error) {
      // Error handling is managed by the hook
    }
  };

  if (isAuthenticated) {
    return <div>Welcome! You are logged in.</div>;
  }

  return (
    <form onSubmit={handleSubmit}>
      {error && <div className="error">{error}</div>}
      
      <input name="email" type="email" placeholder="Email" required />
      <input name="password" type="password" placeholder="Password" required />
      
      <button type="submit" disabled={loading}>
        {loading ? 'Logging in...' : 'Login'}
      </button>
    </form>
  );
}
```

### 3. Manage user profiles

```tsx
import React from 'react';
import { useUser } from '@rust-auth-service/react-hooks';

function UserProfile() {
  const { user, updateProfile, loading, error } = useUser();

  const handleUpdateProfile = async (data) => {
    try {
      await updateProfile(data);
      // Profile updated successfully
    } catch (error) {
      // Error handling is managed by the hook
    }
  };

  if (!user) {
    return <div>Please log in to view your profile</div>;
  }

  return (
    <div>
      <h1>Welcome, {user.first_name} {user.last_name}!</h1>
      <p>Email: {user.email}</p>
      <p>Role: {user.role}</p>
      
      {error && <div className="error">{error}</div>}
      {loading && <div>Updating profile...</div>}
      
      {/* Profile edit form */}
    </div>
  );
}
```

### 4. Make authenticated API calls

```tsx
import React, { useState } from 'react';
import { useApi } from '@rust-auth-service/react-hooks';

function DataComponent() {
  const { get, post, loading, error } = useApi();
  const [data, setData] = useState(null);

  const fetchData = async () => {
    try {
      const result = await get('/api/protected-data');
      setData(result);
    } catch (error) {
      // Error handling is managed by the hook
    }
  };

  const createData = async (newData) => {
    try {
      const result = await post('/api/data', newData);
      setData(result);
    } catch (error) {
      // Error handling is managed by the hook
    }
  };

  return (
    <div>
      {loading && <div>Loading...</div>}
      {error && <div className="error">{error}</div>}
      {data && <pre>{JSON.stringify(data, null, 2)}</pre>}
      
      <button onClick={fetchData}>Fetch Data</button>
    </div>
  );
}
```

## 📖 API Reference

### AuthProvider

The main provider component that wraps your application.

```tsx
<AuthProvider config={authConfig}>
  {children}
</AuthProvider>
```

#### AuthConfig Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `baseUrl` | `string` | `'http://localhost:8080'` | API base URL |
| `storageType` | `'localStorage' \| 'sessionStorage' \| 'memory'` | `'localStorage'` | Token storage method |
| `autoRefresh` | `boolean` | `false` | Enable automatic token refresh |
| `refreshThreshold` | `number` | `10` | Minutes before expiry to refresh token |

### useAuth

Primary authentication hook with complete auth state management.

```tsx
const {
  user,                    // Current user object or null
  loading,                 // Loading state for auth operations
  error,                   // Error message string or null
  isAuthenticated,         // Boolean authentication status
  isInitialized,          // Boolean initialization status
  login,                   // Login function: (credentials) => Promise<void>
  register,                // Register function: (userData) => Promise<void>
  logout,                  // Logout function: () => Promise<void>
  updateProfile,           // Update profile: (data) => Promise<void>
  refreshToken,            // Manual token refresh: () => Promise<void>
  clearError,              // Clear error state: () => void
  forgotPassword,          // Forgot password: (data) => Promise<void>
  resetPassword,           // Reset password: (data) => Promise<void>
  verifyEmail,            // Verify email: (data) => Promise<void>
} = useAuth();
```

### useUser

Focused hook for user profile management.

```tsx
const {
  user,                    // Current user object or null
  loading,                 // Loading state for user operations
  error,                   // Error message string or null
  updateProfile,           // Update profile: (data) => Promise<void>
  refreshUser,             // Refresh user data: () => Promise<void>
  clearError,              // Clear error state: () => void
} = useUser();
```

### useApi

Hook for making authenticated API calls.

```tsx
const {
  loading,                 // Loading state for API operations
  error,                   // Error message string or null
  makeRequest,             // Generic request: (endpoint, options) => Promise<T>
  get,                     // GET request: (endpoint) => Promise<T>
  post,                    // POST request: (endpoint, data?) => Promise<T>
  put,                     // PUT request: (endpoint, data?) => Promise<T>
  delete,                  // DELETE request: (endpoint) => Promise<T>
  clearError,              // Clear error state: () => void
} = useApi();
```

## 🏗️ Type Definitions

The library includes comprehensive TypeScript definitions:

```tsx
interface User {
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

interface LoginRequest {
  email: string;
  password: string;
}

interface RegisterRequest {
  email: string;
  password: string;
  first_name: string;
  last_name: string;
  role?: string;
}

interface UpdateProfileRequest {
  first_name?: string;
  last_name?: string;
  email?: string;
}

// ... and many more
```

## 🛡️ Security Features

- **Automatic Token Management**: Handles JWT access and refresh tokens
- **Secure Storage**: Configurable storage options with fallbacks
- **Token Refresh**: Automatic refresh before expiration
- **Error Handling**: Comprehensive error handling with user-friendly messages
- **CORS Support**: Works with cross-origin requests
- **Input Validation**: Client-side validation for better UX

## 🧪 Testing

The library includes comprehensive example applications and test utilities:

```bash
# Run the example application
cd example
npm install
npm start
```

Visit `http://localhost:3000` to see the hooks in action with a complete authentication flow.

## 🔧 Advanced Usage

### Custom API Client Configuration

```tsx
import { AuthApiClient } from '@rust-auth-service/react-hooks';

const customClient = new AuthApiClient({
  baseUrl: 'https://your-api.com',
  storageType: 'sessionStorage',
});

// Use with your own React context if needed
```

### Error Handling Patterns

```tsx
function MyComponent() {
  const { login, error, clearError } = useAuth();

  const handleLogin = async (credentials) => {
    clearError(); // Clear previous errors
    
    try {
      await login(credentials);
      // Success handling
    } catch (error) {
      // Error is automatically set in hook state
      // Additional error handling if needed
    }
  };

  return (
    <div>
      {error && (
        <div className="error">
          {error}
          <button onClick={clearError}>Dismiss</button>
        </div>
      )}
      {/* Rest of component */}
    </div>
  );
}
```

### Protected Routes Pattern

```tsx
import { useAuth } from '@rust-auth-service/react-hooks';

function ProtectedRoute({ children }) {
  const { isAuthenticated, isInitialized, loading } = useAuth();

  if (!isInitialized || loading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return <div>Please log in to access this page</div>;
  }

  return children;
}

// Usage
function App() {
  return (
    <ProtectedRoute>
      <Dashboard />
    </ProtectedRoute>
  );
}
```

## 🤝 Contributing

Contributions are welcome! Please see the main [Rust Auth Service repository](https://github.com/fahdi/rust-auth-service) for contribution guidelines.

## 📄 License

MIT - See the main repository for license details.

## 🔗 Related

- [Rust Auth Service](https://github.com/fahdi/rust-auth-service) - The main authentication service
- [Next.js Integration Example](../nextjs-integration) - Complete Next.js example
- [API Documentation](../../API_DOCUMENTATION.md) - Complete API reference

---

Built with ❤️ for the Rust Auth Service ecosystem.