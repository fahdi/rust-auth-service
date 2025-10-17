import React, { useState } from 'react';
import { useAuth, useUser, useApi } from '@rust-auth-service/react-hooks';
import LoginForm from './LoginForm';
import RegisterForm from './RegisterForm';
import UserProfile from './UserProfile';
import ApiDemo from './ApiDemo';

const AuthDemo: React.FC = () => {
  const { isAuthenticated, isInitialized, loading: authLoading } = useAuth();
  const [activeTab, setActiveTab] = useState<'login' | 'register'>('login');

  if (!isInitialized) {
    return (
      <div className="loading">
        <div className="spinner"></div>
        <p>Initializing authentication...</p>
      </div>
    );
  }

  if (isAuthenticated) {
    return (
      <div className="authenticated-view">
        <UserProfile />
        <ApiDemo />
      </div>
    );
  }

  return (
    <div className="auth-view">
      <div className="auth-tabs">
        <button
          className={`tab ${activeTab === 'login' ? 'active' : ''}`}
          onClick={() => setActiveTab('login')}
        >
          Login
        </button>
        <button
          className={`tab ${activeTab === 'register' ? 'active' : ''}`}
          onClick={() => setActiveTab('register')}
        >
          Register
        </button>
      </div>

      <div className="auth-content">
        {activeTab === 'login' ? <LoginForm /> : <RegisterForm />}
      </div>

      <div className="demo-credentials">
        <h3>Demo Credentials</h3>
        <p><strong>Email:</strong> test@demo.com</p>
        <p><strong>Password:</strong> Test123!</p>
      </div>
    </div>
  );
};

export default AuthDemo;