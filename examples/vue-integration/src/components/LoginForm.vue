<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
    <div class="max-w-md w-full space-y-8">
      <div>
        <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
          Sign in to your account
        </h2>
        <p class="mt-2 text-center text-sm text-gray-600">
          Or
          <router-link
            to="/register"
            class="font-medium text-indigo-600 hover:text-indigo-500"
          >
            create a new account
          </router-link>
        </p>
      </div>
      
      <form class="mt-8 space-y-6" @submit="onSubmit">
        <div class="rounded-md shadow-sm -space-y-px">
          <div>
            <label for="email" class="sr-only">Email address</label>
            <input
              v-model="email"
              v-bind="emailAttrs"
              type="email"
              autocomplete="email"
              class="appearance-none rounded-none relative block w-full px-3 py-2 border"
              :class="{
                'border-red-300': errors.email,
                'border-gray-300': !errors.email
              }"
              placeholder="Email address"
            />
            <p v-if="errors.email" class="mt-1 text-sm text-red-600">
              {{ errors.email }}
            </p>
          </div>
          
          <div>
            <label for="password" class="sr-only">Password</label>
            <input
              v-model="password"
              v-bind="passwordAttrs"
              type="password"
              autocomplete="current-password"
              class="appearance-none rounded-none relative block w-full px-3 py-2 border"
              :class="{
                'border-red-300': errors.password,
                'border-gray-300': !errors.password
              }"
              placeholder="Password"
            />
            <p v-if="errors.password" class="mt-1 text-sm text-red-600">
              {{ errors.password }}
            </p>
          </div>
        </div>

        <div class="flex items-center justify-between">
          <div class="text-sm">
            <router-link
              to="/forgot-password"
              class="font-medium text-indigo-600 hover:text-indigo-500"
            >
              Forgot your password?
            </router-link>
          </div>
        </div>

        <div>
          <button
            type="submit"
            :disabled="isSubmitting || authStore.loading"
            class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <LoadingSpinner v-if="isSubmitting || authStore.loading" />
            {{ isSubmitting || authStore.loading ? 'Signing in...' : 'Sign in' }}
          </button>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useForm } from 'vee-validate';
import * as yup from 'yup';
import { useAuthStore } from '../stores/auth';
import { useRouter, useRoute } from 'vue-router';
import LoadingSpinner from './LoadingSpinner.vue';

const authStore = useAuthStore();
const router = useRouter();
const route = useRoute();

// Validation schema
const schema = yup.object({
  email: yup
    .string()
    .email('Please enter a valid email address')
    .required('Email is required'),
  password: yup
    .string()
    .min(8, 'Password must be at least 8 characters')
    .required('Password is required'),
});

// Form setup
const { handleSubmit, errors, isSubmitting } = useForm({
  validationSchema: schema,
});

const [email, emailAttrs] = defineModel('email');
const [password, passwordAttrs] = defineModel('password');

// Form submission
const onSubmit = handleSubmit(async (values) => {
  try {
    await authStore.login(values.email, values.password);
    
    // Redirect to the page user was trying to access, or dashboard
    const from = (route.query.from as string) || '/dashboard';
    router.push(from);
  } catch (error) {
    // Error is handled by the store
  }
});
</script>

<style scoped>
.rounded-t-md {
  border-top-left-radius: 0.375rem;
  border-top-right-radius: 0.375rem;
}

.rounded-b-md {
  border-bottom-left-radius: 0.375rem;
  border-bottom-right-radius: 0.375rem;
}
</style>