import { useState, useCallback, useMemo } from 'react';
import { AuthApiClient } from '../utils/api-client';
import { useAuthContext } from '../context/AuthContext';
import { UseApiReturn } from '../types';

/**
 * Hook for making API calls with automatic authentication
 * Must be used within an AuthProvider
 * 
 * @returns API client methods with loading and error state
 * 
 * @example
 * ```tsx
 * function DataComponent() {
 *   const { get, post, loading, error, clearError } = useApi();
 *   const [data, setData] = useState(null);
 *   
 *   const fetchData = async () => {
 *     try {
 *       const result = await get('/api/data');
 *       setData(result);
 *     } catch (error) {
 *       // Handle error
 *     }
 *   };
 *   
 *   const createData = async (newData) => {
 *     try {
 *       const result = await post('/api/data', newData);
 *       setData(result);
 *     } catch (error) {
 *       // Handle error
 *     }
 *   };
 *   
 *   return (
 *     <div>
 *       {loading && <div>Loading...</div>}
 *       {error && <div className="error">{error}</div>}
 *       {data && <div>{JSON.stringify(data)}</div>}
 *     </div>
 *   );
 * }
 * ```
 */
export function useApi(): UseApiReturn {
  const context = useAuthContext();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Create API client instance with the same config as the auth context
  const apiClient = useMemo(() => new AuthApiClient(context.config), [context.config]);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const makeRequest = useCallback(async <T>(
    endpoint: string,
    options?: RequestInit
  ): Promise<T> => {
    try {
      setLoading(true);
      setError(null);
      
      // Use the internal makeRequest method through a proxy
      // Since makeRequest is private, we'll use the specific methods
      if (!options || options.method === 'GET') {
        return await apiClient.get<T>(endpoint);
      } else if (options.method === 'POST') {
        const body = options.body ? JSON.parse(options.body as string) : undefined;
        return await apiClient.post<T>(endpoint, body);
      } else if (options.method === 'PUT') {
        const body = options.body ? JSON.parse(options.body as string) : undefined;
        return await apiClient.put<T>(endpoint, body);
      } else if (options.method === 'DELETE') {
        return await apiClient.delete<T>(endpoint);
      } else {
        throw new Error(`Unsupported HTTP method: ${options.method}`);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'API request failed';
      setError(errorMessage);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [apiClient]);

  const get = useCallback(async <T>(endpoint: string): Promise<T> => {
    return makeRequest<T>(endpoint, { method: 'GET' });
  }, [makeRequest]);

  const post = useCallback(async <T>(endpoint: string, data?: any): Promise<T> => {
    return makeRequest<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    });
  }, [makeRequest]);

  const put = useCallback(async <T>(endpoint: string, data?: any): Promise<T> => {
    return makeRequest<T>(endpoint, {
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
    });
  }, [makeRequest]);

  const deleteRequest = useCallback(async <T>(endpoint: string): Promise<T> => {
    return makeRequest<T>(endpoint, { method: 'DELETE' });
  }, [makeRequest]);

  return {
    loading,
    error,
    makeRequest,
    get,
    post,
    put,
    delete: deleteRequest,
    clearError,
  };
}