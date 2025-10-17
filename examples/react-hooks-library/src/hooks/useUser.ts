import { useCallback } from 'react';
import { useAuthContext } from '../context/AuthContext';
import { UseUserReturn, UpdateProfileRequest } from '../types';

/**
 * Hook for managing user profile data and operations
 * Must be used within an AuthProvider
 * 
 * @returns User state and profile management functions
 * 
 * @example
 * ```tsx
 * function UserProfile() {
 *   const { user, loading, error, updateProfile, clearError } = useUser();
 *   
 *   const handleUpdateProfile = async (data) => {
 *     try {
 *       await updateProfile(data);
 *       // Profile updated successfully
 *     } catch (error) {
 *       // Handle update error
 *     }
 *   };
 *   
 *   if (!user) {
 *     return <div>Please log in to view your profile</div>;
 *   }
 *   
 *   return (
 *     <div>
 *       <h1>Welcome, {user.first_name} {user.last_name}!</h1>
 *       <p>Email: {user.email}</p>
 *       <p>Role: {user.role}</p>
 *       {error && <div className="error">{error}</div>}
 *       {loading && <div>Updating profile...</div>}
 *       // Profile edit form...
 *     </div>
 *   );
 * }
 * ```
 */
export function useUser(): UseUserReturn {
  const context = useAuthContext();
  
  const refreshUser = useCallback(async () => {
    // Force refresh user data by calling the API
    if (context.isAuthenticated) {
      try {
        await context.refreshToken();
      } catch (error) {
        // If token refresh fails, the user will be logged out automatically
        throw error;
      }
    }
  }, [context.isAuthenticated, context.refreshToken]);

  const updateProfile = useCallback(async (data: UpdateProfileRequest) => {
    return context.updateProfile(data);
  }, [context.updateProfile]);

  const clearError = useCallback(() => {
    context.clearError();
  }, [context.clearError]);

  return {
    user: context.user,
    loading: context.loading,
    error: context.error,
    updateProfile,
    refreshUser,
    clearError,
  };
}