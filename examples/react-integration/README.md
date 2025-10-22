# React Integration Example

This example demonstrates how to integrate the Rust Auth Service with a React application using TypeScript, React Router, and modern React patterns.

## 🎯 Features

- **Complete Authentication Flow**: Login, registration, logout, and profile management
- **TypeScript Support**: Fully typed authentication client and components
- **React Context**: Centralized auth state management
- **Protected Routes**: Route guards for authenticated users
- **Automatic Token Refresh**: Seamless token renewal with interceptors
- **Form Validation**: Comprehensive form validation with react-hook-form and Yup
- **Error Handling**: User-friendly error messages and toast notifications
- **Responsive UI**: Mobile-first design with Tailwind CSS

## 🚀 Quick Start

### Prerequisites

- Node.js 16+ and npm/yarn
- Rust Auth Service running (see [local development guide](../../docs/deployment/local-development.md))

### Installation

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

The application will be available at `http://localhost:5173`

### Environment Configuration

Create a `.env.local` file:

```env
VITE_API_BASE_URL=https://localhost/api
```

## 📁 Project Structure

```
src/
├── lib/
│   └── auth-client.ts          # Authentication client with full API integration
├── contexts/
│   └── AuthContext.tsx         # React context for auth state management
├── components/
│   ├── LoginForm.tsx          # Login component with validation
│   ├── RegisterForm.tsx       # Registration component
│   ├── Dashboard.tsx          # Protected dashboard page
│   └── ProfileModal.tsx       # Profile editing modal
├── App.tsx                    # Main app with routing
└── index.css                  # Tailwind CSS styles
```

## 🔧 Core Components

### Authentication Client (`lib/auth-client.ts`)

The `AuthClient` class provides a complete interface to the Rust Auth Service:

```typescript
import { authClient } from './lib/auth-client';

// Login
const authResponse = await authClient.login({
  email: 'user@example.com',
  password: 'password123'
});

// Register
const authResponse = await authClient.register({
  email: 'user@example.com',
  password: 'password123',
  first_name: 'John',
  last_name: 'Doe'
});

// Get current user
const user = await authClient.getCurrentUser();

// Update profile
const updatedUser = await authClient.updateProfile({
  first_name: 'Jane'
});

// Logout
await authClient.logout();
```

#### Key Features:
- **Automatic Token Management**: Stores JWT tokens in secure HTTP-only cookies
- **Request Interceptors**: Automatically adds Authorization headers
- **Token Refresh**: Handles token expiration with automatic refresh
- **Error Handling**: Consistent error handling with meaningful messages
- **TypeScript Support**: Full type safety for all API operations

### Auth Context (`contexts/AuthContext.tsx`)

React context provider for managing authentication state:

```typescript
import { useAuth } from './contexts/AuthContext';

function MyComponent() {
  const { user, login, logout, isAuthenticated, loading } = useAuth();

  if (loading) return <div>Loading...</div>;
  
  if (!isAuthenticated) {
    return <LoginForm />;
  }

  return (
    <div>
      <h1>Welcome, {user.first_name}!</h1>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

#### Features:
- **Global State**: Accessible from any component
- **Automatic Loading**: Manages loading states for auth operations
- **Error Handling**: Displays toast notifications for errors
- **User Persistence**: Maintains user state across page refreshes

### Protected Routes

Route guards that redirect unauthenticated users:

```typescript
<Routes>
  <Route path="/login" element={<PublicRoute><LoginForm /></PublicRoute>} />
  <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
</Routes>
```

## 🎨 UI Components

### Login Form (`components/LoginForm.tsx`)

- **Validation**: Email format and password requirements
- **Error Display**: Field-specific error messages
- **Loading States**: Visual feedback during authentication
- **Responsive Design**: Works on mobile and desktop

```typescript
const schema = yup.object({
  email: yup.string().email().required(),
  password: yup.string().min(8).required(),
});
```

### Registration Form (`components/RegisterForm.tsx`)

- **Complex Validation**: Password strength and confirmation
- **Real-time Feedback**: Instant validation as user types
- **Accessibility**: Proper labels and ARIA attributes

```typescript
const schema = yup.object({
  firstName: yup.string().min(2).required(),
  lastName: yup.string().min(2).required(),
  email: yup.string().email().required(),
  password: yup.string()
    .min(8)
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
    .required(),
  confirmPassword: yup.string()
    .oneOf([yup.ref('password')])
    .required(),
});
```

### Dashboard (`components/Dashboard.tsx`)

- **User Profile Display**: Shows user information and status
- **Quick Actions**: Common user operations
- **Responsive Layout**: Grid-based layout that adapts to screen size
- **Activity Tracking**: Recent user activities

### Profile Modal (`components/ProfileModal.tsx`)

- **Inline Editing**: Update profile without page refresh
- **Validation**: Ensures data integrity
- **Optimistic Updates**: Immediate UI feedback

## 🔒 Security Features

### Token Management

```typescript
// Secure cookie storage
Cookies.set('access_token', accessToken, {
  secure: true,           // HTTPS only
  sameSite: 'strict',     // CSRF protection
  expires: 1,             // 1 day expiration
});
```

### Request Interceptors

```typescript
// Automatic token attachment
api.interceptors.request.use((config) => {
  if (this.accessToken) {
    config.headers.Authorization = `Bearer ${this.accessToken}`;
  }
  return config;
});

// Automatic token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401 && this.refreshToken) {
      await this.refreshAccessToken();
      return this.api.request(error.config);
    }
    return Promise.reject(error);
  }
);
```

### Input Validation

All forms use comprehensive validation:

```typescript
// Email validation
email: yup.string()
  .email('Please enter a valid email address')
  .required('Email is required'),

// Password validation
password: yup.string()
  .min(8, 'Password must be at least 8 characters')
  .matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/,
    'Password must contain uppercase, lowercase, number, and special character'
  )
  .required('Password is required'),
```

## 📱 Responsive Design

The application uses Tailwind CSS for responsive design:

```typescript
// Mobile-first responsive classes
<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
  <div className="bg-white overflow-hidden shadow rounded-lg">
    {/* Card content */}
  </div>
</div>
```

### Breakpoints

- **Mobile**: Default styles
- **Tablet**: `md:` classes (768px+)
- **Desktop**: `lg:` classes (1024px+)
- **Large Desktop**: `xl:` classes (1280px+)

## 🧪 Testing

### Unit Tests

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage
```

### Integration Tests

```bash
# Run integration tests
npm run test:integration
```

### Example Test

```typescript
import { render, screen, fireEvent } from '@testing-library/react';
import { AuthProvider } from '../contexts/AuthContext';
import LoginForm from '../components/LoginForm';

test('login form validates email', async () => {
  render(
    <AuthProvider>
      <LoginForm />
    </AuthProvider>
  );

  const emailInput = screen.getByPlaceholderText('Email address');
  const submitButton = screen.getByRole('button', { name: /sign in/i });

  fireEvent.change(emailInput, { target: { value: 'invalid-email' } });
  fireEvent.click(submitButton);

  expect(await screen.findByText('Please enter a valid email address')).toBeInTheDocument();
});
```

## 🚀 Production Deployment

### Build for Production

```bash
# Create production build
npm run build

# Preview production build
npm run preview
```

### Environment Variables

```env
# Production environment
VITE_API_BASE_URL=https://api.yourdomain.com
```

### Docker Deployment

```dockerfile
FROM node:18-alpine as builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

## 🔧 Customization

### Styling

The application uses Tailwind CSS. Customize the theme in `tailwind.config.js`:

```javascript
module.exports = {
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#eff6ff',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
        }
      }
    }
  }
}
```

### API Configuration

Modify the `AuthClient` configuration:

```typescript
const authClient = new AuthClient('https://your-api.com/api', {
  timeout: 10000,
  retries: 3,
  headers: {
    'X-App-Version': '1.0.0'
  }
});
```

### Adding New Features

1. **Add API methods** to `AuthClient`
2. **Update TypeScript types** in the client
3. **Create React components** with validation
4. **Add routes** to the router
5. **Update context** if needed

## 🐛 Troubleshooting

### Common Issues

#### CORS Errors

Ensure your Rust Auth Service allows your frontend origin:

```yaml
# config.yml
cors:
  allowed_origins: ["http://localhost:5173", "https://yourdomain.com"]
```

#### Token Refresh Issues

Check browser developer tools for network errors:

```typescript
// Debug token refresh
localStorage.setItem('debug', 'auth:*');
```

#### Build Errors

Clear node modules and reinstall:

```bash
rm -rf node_modules package-lock.json
npm install
```

### Debug Mode

Enable debug logging:

```typescript
// Enable debug mode
window.localStorage.setItem('debug', 'auth:*');

// Disable debug mode
window.localStorage.removeItem('debug');
```

## 📚 Next Steps

1. **Add More Features**:
   - Password reset flow
   - Email verification
   - Two-factor authentication
   - Social login integration

2. **Improve UX**:
   - Dark mode support
   - Internationalization (i18n)
   - Offline support
   - Push notifications

3. **Testing**:
   - Add more unit tests
   - E2E testing with Cypress
   - Visual regression testing

4. **Performance**:
   - Code splitting
   - Image optimization
   - Bundle analysis

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This example is part of the Rust Auth Service project and follows the same license terms.

---

**Ready to build amazing authentication experiences with React! 🚀⚛️**