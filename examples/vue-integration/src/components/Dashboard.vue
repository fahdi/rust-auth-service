<template>
  <div class="min-h-screen bg-gray-50">
    <!-- Navigation -->
    <nav class="bg-white shadow">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex justify-between h-16">
          <div class="flex items-center">
            <h1 class="text-xl font-semibold text-gray-900">
              🦀 Rust Auth Service
            </h1>
          </div>
          <div class="flex items-center space-x-4">
            <span class="text-sm text-gray-700">
              Welcome, {{ authStore.user?.first_name }}!
            </span>
            <button
              @click="showProfileModal = true"
              class="bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-2 rounded-md text-sm font-medium"
            >
              Profile
            </button>
            <button
              @click="handleLogout"
              class="bg-gray-600 hover:bg-gray-700 text-white px-3 py-2 rounded-md text-sm font-medium"
            >
              Logout
            </button>
          </div>
        </div>
      </div>
    </nav>

    <!-- Main Content -->
    <main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
      <div class="px-4 py-6 sm:px-0">
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <!-- User Info Card -->
          <div class="bg-white overflow-hidden shadow rounded-lg">
            <div class="p-5">
              <div class="flex items-center">
                <div class="flex-shrink-0">
                  <div class="w-12 h-12 bg-indigo-100 rounded-full flex items-center justify-center">
                    <span class="text-indigo-600 font-semibold text-lg">
                      {{ userInitials }}
                    </span>
                  </div>
                </div>
                <div class="ml-5 w-0 flex-1">
                  <dl>
                    <dt class="text-sm font-medium text-gray-500 truncate">
                      User Profile
                    </dt>
                    <dd class="text-lg font-medium text-gray-900">
                      {{ authStore.fullName }}
                    </dd>
                  </dl>
                </div>
              </div>
            </div>
            <div class="bg-gray-50 px-5 py-3">
              <div class="text-sm">
                <p class="text-gray-600">Email: {{ authStore.user?.email }}</p>
                <p class="text-gray-600">Role: {{ authStore.user?.role }}</p>
                <div class="flex items-center mt-2">
                  <span
                    :class="[
                      'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                      authStore.user?.is_verified
                        ? 'bg-green-100 text-green-800'
                        : 'bg-yellow-100 text-yellow-800'
                    ]"
                  >
                    {{ authStore.user?.is_verified ? '✓ Verified' : '⚠ Unverified' }}
                  </span>
                  <span
                    :class="[
                      'ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                      authStore.user?.is_active
                        ? 'bg-green-100 text-green-800'
                        : 'bg-red-100 text-red-800'
                    ]"
                  >
                    {{ authStore.user?.is_active ? '✓ Active' : '✗ Inactive' }}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <!-- Account Stats Card -->
          <div class="bg-white overflow-hidden shadow rounded-lg">
            <div class="p-5">
              <div class="flex items-center">
                <div class="flex-shrink-0">
                  <svg
                    class="w-8 h-8 text-indigo-600"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
                    />
                  </svg>
                </div>
                <div class="ml-5 w-0 flex-1">
                  <dl>
                    <dt class="text-sm font-medium text-gray-500 truncate">
                      Account Statistics
                    </dt>
                    <dd class="text-lg font-medium text-gray-900">
                      Member since {{ memberSince }}
                    </dd>
                  </dl>
                </div>
              </div>
            </div>
            <div class="bg-gray-50 px-5 py-3">
              <div class="text-sm text-gray-600">
                <p>Last updated: {{ lastUpdated }}</p>
                <p>User ID: {{ authStore.user?.id }}</p>
              </div>
            </div>
          </div>

          <!-- Quick Actions Card -->
          <div class="bg-white overflow-hidden shadow rounded-lg">
            <div class="p-5">
              <h3 class="text-lg font-medium text-gray-900 mb-4">
                Quick Actions
              </h3>
              <div class="space-y-3">
                <button
                  @click="showProfileModal = true"
                  class="w-full bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md text-sm font-medium"
                >
                  Edit Profile
                </button>
                <button
                  @click="showChangePasswordModal = true"
                  class="w-full bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-md text-sm font-medium"
                >
                  Change Password
                </button>
                <button
                  v-if="!authStore.user?.is_verified"
                  @click="resendVerificationEmail"
                  class="w-full bg-yellow-600 hover:bg-yellow-700 text-white px-4 py-2 rounded-md text-sm font-medium"
                >
                  Resend Verification Email
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- Recent Activity Section -->
        <div class="mt-8">
          <div class="bg-white shadow rounded-lg">
            <div class="px-4 py-5 sm:p-6">
              <h3 class="text-lg leading-6 font-medium text-gray-900">
                Recent Activity
              </h3>
              <div class="mt-5">
                <div class="text-sm text-gray-600">
                  <p>• Logged in successfully</p>
                  <p>• Profile loaded</p>
                  <p>• Dashboard accessed</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>

    <!-- Profile Modal -->
    <ProfileModal
      v-if="showProfileModal"
      :user="authStore.user!"
      @close="showProfileModal = false"
    />

    <!-- Change Password Modal -->
    <ChangePasswordModal
      v-if="showChangePasswordModal"
      @close="showChangePasswordModal = false"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { useAuthStore } from '../stores/auth';
import ProfileModal from './ProfileModal.vue';
import ChangePasswordModal from './ChangePasswordModal.vue';
import { useToast } from 'vue-toastification';

const authStore = useAuthStore();
const toast = useToast();

const showProfileModal = ref(false);
const showChangePasswordModal = ref(false);

const userInitials = computed(() => {
  if (!authStore.user) return '';
  return (
    authStore.user.first_name.charAt(0).toUpperCase() +
    authStore.user.last_name.charAt(0).toUpperCase()
  );
});

const memberSince = computed(() => {
  if (!authStore.user) return '';
  return new Date(authStore.user.created_at).toLocaleDateString();
});

const lastUpdated = computed(() => {
  if (!authStore.user) return '';
  return new Date(authStore.user.updated_at).toLocaleDateString();
});

const handleLogout = async () => {
  try {
    await authStore.logout();
  } catch (error) {
    console.error('Logout failed:', error);
  }
};

const resendVerificationEmail = () => {
  // This would typically call an API endpoint
  toast.info('Verification email resent! Check your inbox.');
};
</script>