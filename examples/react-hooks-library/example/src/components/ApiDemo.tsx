import React, { useState } from 'react';
import { useApi } from '@rust-auth-service/react-hooks';

const ApiDemo: React.FC = () => {
  const { get, loading, error, clearError } = useApi();
  const [healthData, setHealthData] = useState<any>(null);
  const [showHealthData, setShowHealthData] = useState(false);

  const checkHealth = async () => {
    try {
      clearError();
      const health = await get('/health');
      setHealthData(health);
      setShowHealthData(true);
    } catch (error) {
      // Error is handled by the hook
    }
  };

  return (
    <div className="api-demo">
      <h3>API Demo</h3>
      <p>Test the useApi hook with the health endpoint:</p>

      {error && (
        <div className="error-message">
          <span className="error-icon">⚠️</span>
          {error}
        </div>
      )}

      <div className="api-actions">
        <button 
          onClick={checkHealth} 
          disabled={loading}
          className="api-button"
        >
          {loading ? (
            <>
              <span className="spinner small"></span>
              Checking Health...
            </>
          ) : (
            'Check Service Health'
          )}
        </button>

        {showHealthData && (
          <button 
            onClick={() => setShowHealthData(false)}
            className="hide-button"
          >
            Hide Data
          </button>
        )}
      </div>

      {showHealthData && healthData && (
        <div className="health-data">
          <h4>Health Check Response:</h4>
          <pre className="json-display">
            {JSON.stringify(healthData, null, 2)}
          </pre>
        </div>
      )}

      <div className="api-info">
        <h4>useApi Hook Features:</h4>
        <ul>
          <li>Automatic authentication with JWT tokens</li>
          <li>Built-in loading and error state management</li>
          <li>Support for GET, POST, PUT, DELETE requests</li>
          <li>Automatic token refresh on expiry</li>
          <li>TypeScript support for response types</li>
        </ul>
      </div>
    </div>
  );
};

export default ApiDemo;