/**
 * Auth store — manages JWT authentication state, login, MFA, and logout.
 */

import { create } from 'zustand';
import { api, setAccessToken } from '../api/client';

interface User {
  id: string;
  username: string;
  email: string;
  fullName: string | null;
  mfaEnabled: boolean;
  role: { id: string; name: string; description: string | null };
}

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  mfaChallengeToken: string | null;

  login: (username: string, password: string) => Promise<{ mfaRequired: boolean }>;
  verifyMfa: (totpCode: string) => Promise<void>;
  logout: () => Promise<void>;
  fetchMe: () => Promise<void>;
  silentRefresh: () => Promise<boolean>;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  isAuthenticated: false,
  isLoading: true,
  mfaChallengeToken: null,

  login: async (username, password) => {
    const data = await api.post<{
      access_token: string;
      mfa_required: boolean;
      mfa_challenge_token: string | null;
    }>('/auth/login', { username, password });

    if (data.mfa_required) {
      set({ mfaChallengeToken: data.mfa_challenge_token });
      return { mfaRequired: true };
    }

    setAccessToken(data.access_token);
    await get().fetchMe();
    return { mfaRequired: false };
  },

  verifyMfa: async (totpCode) => {
    const { mfaChallengeToken } = get();
    if (!mfaChallengeToken) throw new Error('No MFA challenge active');

    const data = await api.post<{ access_token: string }>('/auth/mfa/verify', {
      mfa_challenge_token: mfaChallengeToken,
      totp_code: totpCode,
    });

    setAccessToken(data.access_token);
    set({ mfaChallengeToken: null });
    await get().fetchMe();
  },

  logout: async () => {
    try {
      await api.post('/auth/logout');
    } catch {
      // Ignore errors on logout
    }
    setAccessToken(null);
    set({ user: null, isAuthenticated: false, mfaChallengeToken: null });
  },

  fetchMe: async () => {
    try {
      const user = await api.get<User>('/auth/me');
      set({ user, isAuthenticated: true, isLoading: false });
    } catch {
      set({ user: null, isAuthenticated: false, isLoading: false });
    }
  },

  silentRefresh: async () => {
    try {
      const data = await api.post<{ access_token: string }>('/auth/refresh');
      if (data.access_token) {
        setAccessToken(data.access_token);
        await get().fetchMe();
        return true;
      }
    } catch {
      // Refresh failed
    }
    set({ isLoading: false });
    return false;
  },
}));
