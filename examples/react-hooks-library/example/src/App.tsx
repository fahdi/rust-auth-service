import React from 'react';
import { AuthProvider } from '@rust-auth-service/react-hooks';
import AuthDemo from './components/AuthDemo';
import './App.css';

function App() {
  return (
    <AuthProvider
      config={{
        baseUrl: 'http://localhost:8080',
        storageType: 'localStorage',
        autoRefresh: true,
        refreshThreshold: 10, // Refresh 10 minutes before expiry
      }}
    >
      <div className="App">
        <header className="App-header">
          <h1>🦀 Rust Auth Service</h1>
          <h2>React Hooks Library Demo</h2>
        </header>
        <main>
          <AuthDemo />
        </main>
      </div>
    </AuthProvider>
  );
}

export default App;