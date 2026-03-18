/**
 * Theme store — Dark/Light/System mode with localStorage persistence.
 */

import { create } from 'zustand';

type ThemeMode = 'dark' | 'light' | 'system';

interface ThemeState {
  mode: ThemeMode;
  resolved: 'dark' | 'light';
  setMode: (mode: ThemeMode) => void;
}

function resolveTheme(mode: ThemeMode): 'dark' | 'light' {
  if (mode === 'system') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches
      ? 'dark'
      : 'light';
  }
  return mode;
}

function applyTheme(resolved: 'dark' | 'light') {
  document.documentElement.classList.toggle('dark', resolved === 'dark');
  document.documentElement.classList.toggle('light', resolved === 'light');
}

const stored = (localStorage.getItem('sentinel-theme') as ThemeMode) || 'dark';
const initialResolved = resolveTheme(stored);
applyTheme(initialResolved);

export const useThemeStore = create<ThemeState>((set) => ({
  mode: stored,
  resolved: initialResolved,

  setMode: (mode) => {
    localStorage.setItem('sentinel-theme', mode);
    const resolved = resolveTheme(mode);
    applyTheme(resolved);
    set({ mode, resolved });
  },
}));

// Listen for system theme changes
window
  .matchMedia('(prefers-color-scheme: dark)')
  .addEventListener('change', () => {
    const state = useThemeStore.getState();
    if (state.mode === 'system') {
      const resolved = resolveTheme('system');
      applyTheme(resolved);
      useThemeStore.setState({ resolved });
    }
  });
