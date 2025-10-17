import { useAuthContext } from '../context/AuthContext';
import { UseAuthReturn } from '../types';

/**
 * Hook for accessing authentication state and actions
 * Must be used within an AuthProvider
 * 
 * @returns Authentication state and actions
 * 
 * @example
 * ```tsx
 * function LoginForm() {
 *   const { login, loading, error, isAuthenticated } = useAuth();
 *   
 *   const handleSubmit = async (credentials) => {
 *     try {
 *       await login(credentials);
 *       // User is now logged in
 *     } catch (error) {
 *       // Handle login error
 *     }
 *   };
 *   
 *   if (isAuthenticated) {
 *     return <div>Already logged in!</div>;
 *   }
 *   
 *   return (
 *     <form onSubmit={handleSubmit}>
 *       {error && <div className="error">{error}</div>}
 *       {loading && <div>Logging in...</div>}
 *       // Form fields...
 *     </form>
 *   );
 * }
 * ```
 */
export function useAuth(): UseAuthReturn {
  const context = useAuthContext();
  
  return {
    user: context.user,
    loading: context.loading,
    error: context.error,
    isAuthenticated: context.isAuthenticated,
    isInitialized: context.isInitialized,
    login: context.login,
    register: context.register,
    logout: context.logout,
    updateProfile: context.updateProfile,
    refreshToken: context.refreshToken,
    clearError: context.clearError,
    forgotPassword: context.forgotPassword,
    resetPassword: context.resetPassword,
    verifyEmail: context.verifyEmail,
  };
}