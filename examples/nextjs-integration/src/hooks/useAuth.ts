'use client';

import { useContext } from 'react';
import { AuthProvider, useAuth as useAuthContext } from '@/components/AuthProvider';

// Re-export the useAuth hook from AuthProvider for convenience
export { useAuth as default } from '@/components/AuthProvider';