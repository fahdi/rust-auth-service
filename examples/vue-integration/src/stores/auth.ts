import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { authClient, type User, type AuthResponse } from '../lib/auth-client';
import { useToast } from 'vue-toastification';

export const useAuthStore = defineStore('auth', () => {
  // State
  const user = ref<User | null>(null);
  const loading = ref(false);
  const initialized = ref(false);

  // Getters
  const isAuthenticated = computed(() => !!user.value && authClient.isAuthenticated());
  const fullName = computed(() => {
    if (!user.value) return '';
    return `${user.value.first_name} ${user.value.last_name}`;
  });

  // Toast instance
  const toast = useToast();

  // Actions
  const initialize = async () => {
    if (initialized.value) return;
    
    loading.value = true;
    try {
      if (authClient.isAuthenticated()) {
        const userData = await authClient.getCurrentUser();
        user.value = userData;
      }
    } catch (error) {
      console.error('Failed to initialize user:', error);
      await authClient.logout();
    } finally {
      loading.value = false;
      initialized.value = true;
    }
  };

  const login = async (email: string, password: string): Promise<void> => {
    loading.value = true;
    try {
      const authResponse: AuthResponse = await authClient.login({ email, password });
      user.value = authResponse.user;
      toast.success('Successfully logged in!');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Login failed';
      toast.error(message);
      throw error;
    } finally {
      loading.value = false;
    }
  };

  const register = async (
    email: string,
    password: string,
    firstName: string,
    lastName: string
  ): Promise<void> => {
    loading.value = true;
    try {
      const authResponse: AuthResponse = await authClient.register({
        email,
        password,
        first_name: firstName,
        last_name: lastName,
      });
      user.value = authResponse.user;
      toast.success('Account created successfully!');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Registration failed';
      toast.error(message);
      throw error;
    } finally {
      loading.value = false;
    }
  };

  const logout = async (): Promise<void> => {
    loading.value = true;
    try {
      await authClient.logout();
      user.value = null;
      toast.success('Successfully logged out');
    } catch (error) {
      console.error('Logout error:', error);
      user.value = null;
    } finally {
      loading.value = false;
    }
  };

  const updateProfile = async (updates: Partial<User>): Promise<void> => {
    try {
      const updatedUser = await authClient.updateProfile(updates);
      user.value = updatedUser;
      toast.success('Profile updated successfully!');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Profile update failed';
      toast.error(message);
      throw error;
    }
  };

  const changePassword = async (currentPassword: string, newPassword: string): Promise<void> => {
    try {
      await authClient.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      toast.success('Password changed successfully!');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Password change failed';
      toast.error(message);
      throw error;
    }
  };

  const forgotPassword = async (email: string): Promise<void> => {
    try {
      await authClient.forgotPassword(email);
      toast.success('Password reset email sent!');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to send reset email';
      toast.error(message);
      throw error;
    }
  };

  const resetPassword = async (token: string, newPassword: string): Promise<void> => {
    try {
      await authClient.resetPassword(token, newPassword);
      toast.success('Password reset successfully!');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Password reset failed';
      toast.error(message);
      throw error;
    }
  };

  const verifyEmail = async (token: string): Promise<void> => {
    try {
      await authClient.verifyEmail(token);
      // Refresh user data to get updated verification status
      if (user.value) {
        const userData = await authClient.getCurrentUser();
        user.value = userData;
      }
      toast.success('Email verified successfully!');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Email verification failed';
      toast.error(message);
      throw error;
    }
  };

  const refreshUser = async (): Promise<void> => {
    try {
      if (authClient.isAuthenticated()) {
        const userData = await authClient.getCurrentUser();
        user.value = userData;
      }
    } catch (error) {
      console.error('Failed to refresh user:', error);
      user.value = null;
    }
  };

  // Listen for logout events from auth client
  if (typeof window !== 'undefined') {
    window.addEventListener('auth:logout', () => {
      user.value = null;
      toast.info('Session expired. Please log in again.');
    });
  }

  return {
    // State
    user,
    loading,
    initialized,
    
    // Getters
    isAuthenticated,
    fullName,
    
    // Actions
    initialize,
    login,
    register,
    logout,
    updateProfile,
    changePassword,
    forgotPassword,
    resetPassword,
    verifyEmail,
    refreshUser,
  };
});