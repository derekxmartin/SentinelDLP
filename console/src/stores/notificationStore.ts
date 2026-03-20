/**
 * Notification store — manages notification state, polling, and actions.
 *
 * Polls /api/notifications/count every 30 seconds for the badge count.
 * Full notification list is fetched on demand when the panel opens.
 */

import { create } from 'zustand';
import api from '../api/client';

export interface Notification {
  id: string;
  user_id: string;
  type: string;
  severity: string;
  title: string;
  message: string;
  resource_type: string | null;
  resource_id: string | null;
  is_read: boolean;
  created_at: string;
}

interface NotificationListResponse {
  items: Notification[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

interface NotificationState {
  notifications: Notification[];
  unreadCount: number;
  total: number;
  isOpen: boolean;
  loading: boolean;

  // Actions
  togglePanel: () => void;
  closePanel: () => void;
  fetchNotifications: () => Promise<void>;
  fetchUnreadCount: () => Promise<void>;
  markAsRead: (id: string) => Promise<void>;
  markAllAsRead: () => Promise<void>;
  deleteNotification: (id: string) => Promise<void>;
  startPolling: () => void;
  stopPolling: () => void;
}

let pollInterval: ReturnType<typeof setInterval> | null = null;

export const useNotificationStore = create<NotificationState>((set, get) => ({
  notifications: [],
  unreadCount: 0,
  total: 0,
  isOpen: false,
  loading: false,

  togglePanel: () => {
    const wasOpen = get().isOpen;
    set({ isOpen: !wasOpen });
    if (!wasOpen) {
      get().fetchNotifications();
    }
  },

  closePanel: () => set({ isOpen: false }),

  fetchNotifications: async () => {
    set({ loading: true });
    try {
      const data = await api.get<NotificationListResponse>('/notifications?page_size=50');
      set({
        notifications: data.items,
        total: data.total,
        unreadCount: data.items.filter((n) => !n.is_read).length,
      });
    } catch {
      // Silently fail — badge just won't update
    } finally {
      set({ loading: false });
    }
  },

  fetchUnreadCount: async () => {
    try {
      const data = await api.get<{ count: number }>('/notifications/count');
      set({ unreadCount: data.count });
    } catch {
      // Silently fail
    }
  },

  markAsRead: async (id: string) => {
    try {
      await api.patch(`/notifications/${id}/read`, {});
      set((state) => ({
        notifications: state.notifications.map((n) =>
          n.id === id ? { ...n, is_read: true } : n,
        ),
        unreadCount: Math.max(0, state.unreadCount - 1),
      }));
    } catch {
      // Silently fail
    }
  },

  markAllAsRead: async () => {
    try {
      await api.post('/notifications/read-all', {});
      set((state) => ({
        notifications: state.notifications.map((n) => ({ ...n, is_read: true })),
        unreadCount: 0,
      }));
    } catch {
      // Silently fail
    }
  },

  deleteNotification: async (id: string) => {
    try {
      await api.delete(`/notifications/${id}`);
      set((state) => {
        const removed = state.notifications.find((n) => n.id === id);
        return {
          notifications: state.notifications.filter((n) => n.id !== id),
          unreadCount: removed && !removed.is_read
            ? Math.max(0, state.unreadCount - 1)
            : state.unreadCount,
          total: state.total - 1,
        };
      });
    } catch {
      // Silently fail
    }
  },

  startPolling: () => {
    if (pollInterval) return;
    // Initial fetch
    get().fetchUnreadCount();
    // Poll every 30 seconds
    pollInterval = setInterval(() => {
      get().fetchUnreadCount();
    }, 30_000);
  },

  stopPolling: () => {
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
  },
}));
