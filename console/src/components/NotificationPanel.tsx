/**
 * Notification panel — dropdown anchored to the bell icon.
 * Shows recent notifications with severity badges, timestamps,
 * read/unread state, and navigation to linked resources.
 */

import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  FileText,
  Wifi,
  Info,
  Check,
  CheckCheck,
  Trash2,
  X,
} from 'lucide-react';
import { useNotificationStore, type Notification } from '../stores/notificationStore';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#64748b',
};

const SEVERITY_BG: Record<string, string> = {
  critical: 'rgba(239,68,68,0.12)',
  high: 'rgba(249,115,22,0.12)',
  medium: 'rgba(234,179,8,0.12)',
  low: 'rgba(59,130,246,0.12)',
  info: 'rgba(100,116,139,0.12)',
};

const TYPE_ICONS: Record<string, typeof ShieldAlert> = {
  incident_created: ShieldAlert,
  policy_changed: FileText,
  agent_status: Wifi,
  system: Info,
};

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function NotificationItem({ notif }: { notif: Notification }) {
  const navigate = useNavigate();
  const { markAsRead, deleteNotification, closePanel } = useNotificationStore();

  const Icon = TYPE_ICONS[notif.type] || Info;

  function handleClick() {
    if (!notif.is_read) markAsRead(notif.id);
    if (notif.resource_type && notif.resource_id) {
      const path =
        notif.resource_type === 'incident' ? `/incidents/${notif.resource_id}` :
        notif.resource_type === 'policy' ? `/policies/${notif.resource_id}` :
        null;
      if (path) {
        closePanel();
        navigate(path);
      }
    }
  }

  return (
    <div
      onClick={handleClick}
      style={{
        display: 'flex', gap: '0.625rem', padding: '0.625rem 0.75rem',
        borderBottom: '1px solid rgba(255,255,255,0.04)',
        backgroundColor: notif.is_read ? 'transparent' : 'rgba(99,102,241,0.04)',
        cursor: notif.resource_id ? 'pointer' : 'default',
        transition: 'background-color 0.15s',
      }}
      onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.03)'; }}
      onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = notif.is_read ? 'transparent' : 'rgba(99,102,241,0.04)'; }}
    >
      {/* Icon */}
      <div style={{
        width: '1.75rem', height: '1.75rem', borderRadius: '50%', flexShrink: 0,
        backgroundColor: SEVERITY_BG[notif.severity] || SEVERITY_BG.info,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        marginTop: '0.125rem',
      }}>
        <Icon style={{ width: '0.8rem', height: '0.8rem', color: SEVERITY_COLORS[notif.severity] || SEVERITY_COLORS.info }} />
      </div>

      {/* Content */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
          <p style={{
            fontSize: '0.8125rem', color: '#e2e8f0',
            fontWeight: notif.is_read ? 400 : 600,
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {notif.title}
          </p>
          {!notif.is_read && (
            <div style={{
              width: '0.375rem', height: '0.375rem', borderRadius: '50%',
              backgroundColor: '#6366f1', flexShrink: 0,
            }} />
          )}
        </div>
        <p style={{
          fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.125rem',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          {notif.message}
        </p>
        <p style={{ fontSize: '0.6875rem', color: '#475569', marginTop: '0.25rem' }}>
          {timeAgo(notif.created_at)}
        </p>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', flexShrink: 0 }}>
        {!notif.is_read && (
          <button
            onClick={(e) => { e.stopPropagation(); markAsRead(notif.id); }}
            title="Mark as read"
            style={{
              padding: '0.25rem', borderRadius: '0.25rem', background: 'none',
              border: 'none', color: '#64748b', cursor: 'pointer',
            }}
          >
            <Check style={{ width: '0.7rem', height: '0.7rem' }} />
          </button>
        )}
        <button
          onClick={(e) => { e.stopPropagation(); deleteNotification(notif.id); }}
          title="Dismiss"
          style={{
            padding: '0.25rem', borderRadius: '0.25rem', background: 'none',
            border: 'none', color: '#475569', cursor: 'pointer',
          }}
        >
          <Trash2 style={{ width: '0.7rem', height: '0.7rem' }} />
        </button>
      </div>
    </div>
  );
}

export default function NotificationPanel() {
  const { notifications, unreadCount, total, isOpen, loading, closePanel, markAllAsRead } =
    useNotificationStore();

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={closePanel}
        style={{
          position: 'fixed', inset: 0, zIndex: 40,
        }}
      />

      {/* Panel */}
      <div style={{
        position: 'fixed', top: '3.25rem', right: '1rem', zIndex: 50,
        width: '24rem', maxHeight: '32rem',
        backgroundColor: 'var(--color-surface-card)',
        border: '1px solid rgba(255,255,255,0.1)',
        borderRadius: '0.75rem',
        boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
        display: 'flex', flexDirection: 'column',
        overflow: 'hidden',
      }}>
        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '0.75rem 1rem',
          borderBottom: '1px solid rgba(255,255,255,0.08)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <h3 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0' }}>Notifications</h3>
            {unreadCount > 0 && (
              <span style={{
                fontSize: '0.6875rem', fontWeight: 600,
                padding: '0.0625rem 0.375rem', borderRadius: '9999px',
                backgroundColor: 'rgba(99,102,241,0.15)', color: '#a5b4fc',
              }}>
                {unreadCount} new
              </span>
            )}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            {unreadCount > 0 && (
              <button
                onClick={markAllAsRead}
                title="Mark all as read"
                style={{
                  padding: '0.25rem 0.5rem', borderRadius: '0.25rem', fontSize: '0.6875rem',
                  background: 'none', border: 'none', color: '#6366f1', cursor: 'pointer',
                  display: 'flex', alignItems: 'center', gap: '0.25rem',
                }}
              >
                <CheckCheck style={{ width: '0.75rem', height: '0.75rem' }} /> Read all
              </button>
            )}
            <button
              onClick={closePanel}
              style={{
                padding: '0.25rem', borderRadius: '0.25rem', background: 'none',
                border: 'none', color: '#64748b', cursor: 'pointer',
              }}
            >
              <X style={{ width: '0.875rem', height: '0.875rem' }} />
            </button>
          </div>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {loading && notifications.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: '#64748b', fontSize: '0.8125rem' }}>
              Loading...
            </div>
          ) : notifications.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: '#475569', fontSize: '0.8125rem' }}>
              No notifications
            </div>
          ) : (
            notifications.map((n) => <NotificationItem key={n.id} notif={n} />)
          )}
        </div>

        {/* Footer */}
        {total > 0 && (
          <div style={{
            padding: '0.5rem 1rem', borderTop: '1px solid rgba(255,255,255,0.08)',
            textAlign: 'center',
          }}>
            <span style={{ fontSize: '0.6875rem', color: '#475569' }}>
              Showing {notifications.length} of {total}
            </span>
          </div>
        )}
      </div>
    </>
  );
}
