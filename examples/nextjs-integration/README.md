# Next.js 14 + TypeScript Integration Example

A complete Next.js 14 TypeScript example demonstrating integration with the Rust Auth Service. This example showcases modern React patterns, type-safe API integration, and production-ready authentication flows.

## 🚀 Features

- **Next.js 14** with App Router and TypeScript
- **Complete Authentication Flow** - Login, register, logout, profile management
- **Type-Safe API Integration** - Full TypeScript interfaces for all endpoints
- **React Context & Hooks** - Modern state management with custom hooks
- **Form Validation** - React Hook Form with Zod schema validation
- **Protected Routes** - Route protection with automatic redirects
- **Responsive UI** - TailwindCSS with custom components
- **Error Handling** - Comprehensive error states and user feedback
- **Token Management** - Automatic JWT refresh and secure storage
- **Docker Support** - Full containerized development environment

## 📋 Prerequisites

Before running this example, make sure you have:

1. **Rust Auth Service** running on `http://localhost:8080`
2. **Node.js 18+** and npm installed
3. **Docker & Docker Compose** (for containerized setup)

## 🛠️ Quick Start

### Option 1: Local Development

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Set up environment variables:**
   ```bash
   cp .env.example .env.local
   ```

3. **Start the development server:**
   ```bash
   npm run dev
   ```

4. **Open your browser:**
   Visit [http://localhost:3000](http://localhost:3000)

### Option 2: Docker Compose (Recommended)

1. **Start all services:**
   ```bash
   docker-compose up --build
   ```

2. **Access the applications:**
   - Next.js App: [http://localhost:3000](http://localhost:3000)
   - Rust Auth API: [http://localhost:8080](http://localhost:8080)
   - API Documentation: [http://localhost:8080/docs](http://localhost:8080/docs)

3. **Optional admin interfaces:**
   ```bash
   # Start with admin tools
   docker-compose --profile admin up -d
   
   # Access admin interfaces
   # MongoDB Express: http://localhost:8081
   # Redis Insight: http://localhost:8082
   ```

## 📁 Project Structure

```
src/
├── app/                    # Next.js 14 App Router
│   ├── globals.css        # Global styles with TailwindCSS
│   ├── layout.tsx         # Root layout with AuthProvider
│   ├── page.tsx           # Homepage with API status
│   ├── login/page.tsx     # Login page
│   ├── register/page.tsx  # Registration page
│   └── dashboard/page.tsx # Protected dashboard
├── components/            # Reusable React components
│   ├── AuthProvider.tsx   # Authentication context provider
│   ├── ProtectedRoute.tsx # Route protection wrapper
│   ├── LoginForm.tsx      # Login form with validation
│   ├── RegisterForm.tsx   # Registration form
│   └── LoadingSpinner.tsx # Loading indicator
├── hooks/                 # Custom React hooks
│   ├── useAuth.ts         # Authentication hook
│   └── useApi.ts          # API interaction hooks
└── lib/                   # Utilities and configuration
    ├── api.ts             # API client with auto-refresh
    └── types.ts           # TypeScript type definitions
```

## 🎯 Key Components

### Authentication Provider

```typescript
import { AuthProvider } from '@/components/AuthProvider';
import { useAuth } from '@/components/AuthProvider';

// Provides authentication state throughout the app
const { user, login, logout, loading, error } = useAuth();
```

### API Client

```typescript
import { apiClient } from '@/lib/api';

// Type-safe API calls with automatic token refresh
const response = await apiClient.login({ email, password });
const profile = await apiClient.getProfile();
```

### Protected Routes

```typescript
import ProtectedRoute from '@/components/ProtectedRoute';

<ProtectedRoute>
  <DashboardContent />
</ProtectedRoute>
```

### Custom Hooks

```typescript
import { useApi, useHealthCheck } from '@/hooks/useApi';

// Reusable API state management
const { data, loading, error, execute } = useHealthCheck();
```

## 🔐 Authentication Flow

1. **Registration/Login** - Forms with validation and error handling
2. **Token Storage** - Secure local storage with automatic cleanup
3. **Route Protection** - Middleware and component-level guards
4. **Auto Refresh** - Transparent token refresh on API calls
5. **Logout** - Complete session cleanup and redirect

## 🎨 UI Components

Built with TailwindCSS and custom component classes:

```css
.btn-primary     /* Primary action buttons */
.btn-secondary   /* Secondary action buttons */
.input-field     /* Form input styling */
.card           /* Card container component */
.error-message  /* Error text styling */
```

## 🧪 API Integration

### Type Definitions

All API endpoints have complete TypeScript definitions:

```typescript
interface LoginRequest {
  email: string;
  password: string;
}

interface AuthResponse {
  user: User;
  access_token: string;
  refresh_token: string;
  expires_in: number;
}
```

### Error Handling

Comprehensive error handling with user-friendly messages:

```typescript
try {
  await login(credentials);
} catch (error) {
  // Automatic error state management
  // User sees friendly error messages
}
```

## 🐳 Docker Configuration

### Services

- **nextjs-app** - Next.js development server with hot reload
- **rust-auth-service** - Rust authentication API
- **mongodb** - Database with auto-initialization
- **redis** - Caching layer
- **mongo-express** - Database admin (optional)
- **redis-insight** - Redis admin (optional)

### Environment Variables

```bash
API_BASE_URL=http://rust-auth-service:8080
NODE_ENV=development
DATABASE_URL=mongodb://admin:password123@mongodb:27017/auth_service
JWT_SECRET=your-ultra-secure-jwt-secret
```

## 📝 Available Scripts

```bash
# Development
npm run dev          # Start development server
npm run build        # Build for production
npm run start        # Start production server
npm run lint         # Run ESLint
npm run type-check   # TypeScript compilation check

# Docker
docker-compose up --build              # Start all services
docker-compose --profile admin up -d   # Start with admin tools
docker-compose down                     # Stop all services
```

## 🔍 Testing the Integration

### Manual Testing Steps

1. **Homepage** - Visit [http://localhost:3000](http://localhost:3000)
   - Check API status display
   - Verify navigation links work

2. **Registration** - Create a new account
   - Test form validation
   - Verify successful registration redirects to dashboard

3. **Login** - Sign in with credentials
   - Test error handling for invalid credentials
   - Verify successful login redirects to dashboard

4. **Dashboard** - Access protected area
   - View user profile information
   - Test profile update functionality
   - Verify logout works correctly

5. **Route Protection** - Test authentication guards
   - Try accessing `/dashboard` without login
   - Verify automatic redirects work

### API Health Check

The homepage displays real-time API status including:
- Service health and version
- Database connection status
- Cache (Redis) status
- Response times

## 🚀 Production Deployment

### Build Optimization

```bash
# Create production build
npm run build

# Optimize for Docker
docker build -t nextjs-rust-auth .
```

### Environment Configuration

```bash
# Production environment variables
API_BASE_URL=https://your-api-domain.com
NODE_ENV=production
NEXT_TELEMETRY_DISABLED=1
```

### Security Considerations

- Use HTTPS in production
- Set secure JWT secrets
- Configure proper CORS settings
- Implement rate limiting
- Use environment-specific API URLs

## 🛠️ Development Tips

### Hot Reload

Both Next.js and Rust services support hot reload in Docker:
- Next.js: Automatic reload on file changes
- Rust: Use `cargo watch` for automatic rebuilds

### Debugging

- Enable debug logging: `RUST_LOG=debug`
- Use browser dev tools for frontend debugging
- Check Docker logs: `docker-compose logs nextjs-app`

### API Documentation

- Interactive Swagger UI: [http://localhost:8080/docs](http://localhost:8080/docs)
- Health endpoint: [http://localhost:8080/health](http://localhost:8080/health)
- Metrics: [http://localhost:8080/metrics](http://localhost:8080/metrics)

## 📚 Next Steps

1. **Extend the UI** - Add more pages and components
2. **Add Testing** - Implement Jest and Cypress tests
3. **Enhance Security** - Add 2FA, password reset flows
4. **Performance** - Implement caching strategies
5. **Monitoring** - Add error tracking and analytics

## 🤝 Contributing

This example is part of the Rust Auth Service project. Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This example is part of the Rust Auth Service project and follows the same licensing terms.

---

**Built with ❤️ using Rust, Next.js 14, TypeScript, and TailwindCSS**