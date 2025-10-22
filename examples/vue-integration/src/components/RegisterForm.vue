<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
    <div class="max-w-md w-full space-y-8">
      <div>
        <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
          Create your account
        </h2>
        <p class="mt-2 text-center text-sm text-gray-600">
          Or
          <router-link
            to="/login"
            class="font-medium text-indigo-600 hover:text-indigo-500"
          >
            sign in to your existing account
          </router-link>
        </p>
      </div>
      
      <form class="mt-8 space-y-6" @submit="onSubmit">
        <div class="space-y-4">
          <div class="grid grid-cols-2 gap-4">
            <div>
              <label for="firstName" class="block text-sm font-medium text-gray-700">
                First Name
              </label>
              <input
                v-model="firstName"
                v-bind="firstNameAttrs"
                type="text"
                autocomplete="given-name"
                class="mt-1 appearance-none relative block w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                :class="{
                  'border-red-300': errors.firstName,
                  'border-gray-300': !errors.firstName
                }"
                placeholder="First Name"
              />
              <p v-if="errors.firstName" class="mt-1 text-sm text-red-600">
                {{ errors.firstName }}
              </p>
            </div>
            
            <div>
              <label for="lastName" class="block text-sm font-medium text-gray-700">
                Last Name
              </label>
              <input
                v-model="lastName"
                v-bind="lastNameAttrs"
                type="text"
                autocomplete="family-name"
                class="mt-1 appearance-none relative block w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                :class="{
                  'border-red-300': errors.lastName,
                  'border-gray-300': !errors.lastName
                }"
                placeholder="Last Name"
              />
              <p v-if="errors.lastName" class="mt-1 text-sm text-red-600">
                {{ errors.lastName }}
              </p>
            </div>
          </div>

          <div>
            <label for="email" class="block text-sm font-medium text-gray-700">
              Email Address
            </label>
            <input
              v-model="email"
              v-bind="emailAttrs"
              type="email"
              autocomplete="email"
              class="mt-1 appearance-none relative block w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
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
            <label for="password" class="block text-sm font-medium text-gray-700">
              Password
            </label>
            <input
              v-model="password"
              v-bind="passwordAttrs"
              type="password"
              autocomplete="new-password"
              class="mt-1 appearance-none relative block w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
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

          <div>
            <label for="confirmPassword" class="block text-sm font-medium text-gray-700">
              Confirm Password
            </label>
            <input
              v-model="confirmPassword"
              v-bind="confirmPasswordAttrs"
              type="password"
              autocomplete="new-password"
              class="mt-1 appearance-none relative block w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
              :class="{
                'border-red-300': errors.confirmPassword,
                'border-gray-300': !errors.confirmPassword
              }"
              placeholder="Confirm Password"
            />
            <p v-if="errors.confirmPassword" class="mt-1 text-sm text-red-600">
              {{ errors.confirmPassword }}
            </p>
          </div>
        </div>

        <div>
          <button
            type="submit"
            :disabled="isSubmitting || authStore.loading"
            class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <LoadingSpinner v-if="isSubmitting || authStore.loading" />
            {{ isSubmitting || authStore.loading ? 'Creating account...' : 'Create account' }}
          </button>
        </div>

        <div class="text-center">
          <p class="text-xs text-gray-500">
            By creating an account, you agree to our
            <a href="/terms" class="text-indigo-600 hover:text-indigo-500">
              Terms of Service
            </a>
            and
            <a href="/privacy" class="text-indigo-600 hover:text-indigo-500">
              Privacy Policy
            </a>.
          </p>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useForm } from 'vee-validate';
import * as yup from 'yup';
import { useAuthStore } from '../stores/auth';
import { useRouter } from 'vue-router';
import LoadingSpinner from './LoadingSpinner.vue';

const authStore = useAuthStore();
const router = useRouter();

// Validation schema
const schema = yup.object({
  firstName: yup
    .string()
    .min(2, 'First name must be at least 2 characters')
    .required('First name is required'),
  lastName: yup
    .string()
    .min(2, 'Last name must be at least 2 characters')
    .required('Last name is required'),
  email: yup
    .string()
    .email('Please enter a valid email address')
    .required('Email is required'),
  password: yup
    .string()
    .min(8, 'Password must be at least 8 characters')
    .matches(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    )
    .required('Password is required'),
  confirmPassword: yup
    .string()
    .oneOf([yup.ref('password')], 'Passwords must match')
    .required('Please confirm your password'),
});

// Form setup
const { handleSubmit, errors, isSubmitting } = useForm({
  validationSchema: schema,
});

const [firstName, firstNameAttrs] = defineModel('firstName');
const [lastName, lastNameAttrs] = defineModel('lastName');
const [email, emailAttrs] = defineModel('email');
const [password, passwordAttrs] = defineModel('password');
const [confirmPassword, confirmPasswordAttrs] = defineModel('confirmPassword');

// Form submission
const onSubmit = handleSubmit(async (values) => {
  try {
    await authStore.register(
      values.email,
      values.password,
      values.firstName,
      values.lastName
    );
    router.push('/dashboard');
  } catch (error) {
    // Error is handled by the store
  }
});
</script>