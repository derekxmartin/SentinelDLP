/**
 * User & Role management settings page.
 *
 * Lists console users with role badges and active/MFA status.
 * Supports creating new users and editing existing ones via modals.
 */

import { useEffect, useState } from 'react';
import { Users as UsersIcon, Plus, Pencil, Shield, ShieldCheck, ShieldOff, X } from 'lucide-react';
import useTitle from '../../hooks/useTitle';
import api from '../../api/client';

interface Role {
  id: string;
  name: string;
  description: string;
}

interface User {
  id: string;
  username: string;
  email: string;
  full_name: string;
  is_active: boolean;
  mfa_enabled: boolean;
  role_name: string;
  created_at: string;
  updated_at: string;
}

interface CreateUserPayload {
  username: string;
  email: string;
  password: string;
  full_name: string;
  role_name: string;
  is_active: boolean;
}

interface EditUserPayload {
  email: string;
  full_name: string;
  is_active: boolean;
  role_name: string;
}

const ROLE_COLORS: Record<string, { bg: string; text: string }> = {
  Admin:       { bg: 'rgba(168,85,247,0.15)',  text: '#a855f7' },
  Analyst:     { bg: 'rgba(59,130,246,0.15)',   text: '#3b82f6' },
  Remediator:  { bg: 'rgba(34,197,94,0.15)',    text: '#22c55e' },
};

function RoleBadge({ role }: { role: string }) {
  const cfg = ROLE_COLORS[role] || { bg: 'rgba(100,116,139,0.15)', text: '#64748b' };
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
      padding: '0.25rem 0.625rem', borderRadius: '9999px',
      backgroundColor: cfg.bg, color: cfg.text,
      fontSize: '0.75rem', fontWeight: 500,
    }}>
      <Shield style={{ width: '0.75rem', height: '0.75rem' }} />
      {role}
    </span>
  );
}

function ActiveBadge({ active }: { active: boolean }) {
  const bg = active ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)';
  const text = active ? '#22c55e' : '#ef4444';
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
      padding: '0.25rem 0.625rem', borderRadius: '9999px',
      backgroundColor: bg, color: text,
      fontSize: '0.75rem', fontWeight: 500,
    }}>
      {active ? 'Active' : 'Inactive'}
    </span>
  );
}

function MfaBadge({ enabled }: { enabled: boolean }) {
  const Icon = enabled ? ShieldCheck : ShieldOff;
  const color = enabled ? '#22c55e' : '#64748b';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.375rem', color, fontSize: '0.75rem', fontWeight: 500 }}>
      <Icon style={{ width: '0.875rem', height: '0.875rem' }} />
      {enabled ? 'Enabled' : 'Disabled'}
    </span>
  );
}

/* ── Modal wrapper ──────────────────────────────────────────── */

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div
      style={{
        position: 'fixed', inset: 0,
        backgroundColor: 'rgba(0,0,0,0.6)',
        zIndex: 50,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}
      onClick={onClose}
    >
      <div
        style={{
          backgroundColor: '#1e293b',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: '0.75rem',
          padding: '1.5rem',
          width: '28rem',
          maxHeight: '90vh',
          overflowY: 'auto',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
          <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'white' }}>{title}</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', padding: '0.25rem' }}>
            <X style={{ width: '1.125rem', height: '1.125rem' }} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

/* ── Shared form styles ─────────────────────────────────────── */

const labelStyle: React.CSSProperties = {
  display: 'block', fontSize: '0.75rem', fontWeight: 500,
  color: '#94a3b8', marginBottom: '0.375rem',
};

const inputStyle: React.CSSProperties = {
  width: '100%', padding: '0.5rem 0.75rem',
  backgroundColor: '#1e293b', border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: '0.5rem', color: 'white', fontSize: '0.875rem',
  outline: 'none', boxSizing: 'border-box',
};

const selectStyle: React.CSSProperties = {
  ...inputStyle,
  appearance: 'auto' as React.CSSProperties['appearance'],
};

/* ── Main component ─────────────────────────────────────────── */

export default function Users() {
  useTitle('Users & Roles');

  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Modal state
  const [showCreate, setShowCreate] = useState(false);
  const [editUser, setEditUser] = useState<User | null>(null);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  // Create form
  const [createForm, setCreateForm] = useState<CreateUserPayload>({
    username: '', email: '', password: '', full_name: '', role_name: '', is_active: true,
  });

  // Edit form
  const [editForm, setEditForm] = useState<EditUserPayload>({
    email: '', full_name: '', is_active: true, role_name: '',
  });

  async function fetchUsers() {
    setLoading(true);
    setError('');
    try {
      const data: User[] = await api.get('/users');
      setUsers(data);
    } catch {
      setError('Failed to load users.');
    } finally {
      setLoading(false);
    }
  }

  async function fetchRoles() {
    try {
      const data: Role[] = await api.get('/auth/roles');
      setRoles(data);
    } catch {
      // Non-critical — dropdown will be empty
    }
  }

  useEffect(() => { fetchUsers(); fetchRoles(); }, []);

  /* ── Create user ──────────────────────────────── */

  function openCreate() {
    setCreateForm({ username: '', email: '', password: '', full_name: '', role_name: roles[0]?.name || '', is_active: true });
    setFormError('');
    setShowCreate(true);
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setFormError('');
    try {
      await api.post('/users', createForm);
      setShowCreate(false);
      fetchUsers();
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : 'Failed to create user');
    } finally {
      setSaving(false);
    }
  }

  /* ── Edit user ────────────────────────────────── */

  function openEdit(user: User) {
    setEditForm({ email: user.email, full_name: user.full_name, is_active: user.is_active, role_name: user.role_name });
    setFormError('');
    setEditUser(user);
  }

  async function handleEdit(e: React.FormEvent) {
    e.preventDefault();
    if (!editUser) return;
    setSaving(true);
    setFormError('');
    try {
      await api.put(`/users/${editUser.id}`, editForm);
      setEditUser(null);
      fetchUsers();
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : 'Failed to update user');
    } finally {
      setSaving(false);
    }
  }

  /* ── Toggle active ────────────────────────────── */

  async function toggleActive(user: User) {
    try {
      await api.put(`/users/${user.id}`, {
        email: user.email,
        full_name: user.full_name,
        is_active: !user.is_active,
        role_name: user.role_name,
      });
      fetchUsers();
    } catch {
      setError('Failed to update user status.');
    }
  }

  function formatDate(iso: string): string {
    return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }

  return (
    <div style={{ maxWidth: '1200px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <UsersIcon style={{ width: '1.5rem', height: '1.5rem', color: 'var(--color-accent)' }} />
          <h1 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'white' }}>Users &amp; Roles</h1>
          <span style={{ fontSize: '0.875rem', color: '#64748b' }}>({users.length})</span>
        </div>
        <button
          onClick={openCreate}
          style={{
            display: 'inline-flex', alignItems: 'center', gap: '0.5rem',
            backgroundColor: 'var(--color-accent)', color: 'white',
            border: 'none', borderRadius: '0.5rem',
            padding: '0.5rem 1rem', fontSize: '0.875rem', fontWeight: 500,
            cursor: 'pointer',
          }}
        >
          <Plus style={{ width: '1rem', height: '1rem' }} />
          Add User
        </button>
      </div>

      {/* Error */}
      {error && (
        <div style={{
          padding: '0.75rem 1rem', borderRadius: '0.5rem',
          backgroundColor: 'rgba(239,68,68,0.1)', color: '#f87171',
          marginBottom: '1rem', fontSize: '0.875rem',
        }}>{error}</div>
      )}

      {/* Table */}
      <div style={{
        backgroundColor: 'var(--color-surface-card)',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '0.75rem',
        overflow: 'hidden',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
              {['Username', 'Email', 'Role', 'Status', 'MFA', 'Created', 'Actions'].map(h => (
                <th key={h} style={{
                  textAlign: 'left', padding: '0.75rem 1rem',
                  color: '#64748b', fontWeight: 500, fontSize: '0.75rem',
                  textTransform: 'uppercase', letterSpacing: '0.05em',
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>Loading...</td></tr>
            ) : users.length === 0 ? (
              <tr><td colSpan={7} style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>No users found</td></tr>
            ) : users.map((user) => (
              <tr
                key={user.id}
                style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}
              >
                <td style={{ padding: '0.75rem 1rem', color: 'white', fontWeight: 500, fontSize: '0.875rem' }}>
                  {user.username}
                  {user.full_name && (
                    <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.125rem' }}>{user.full_name}</div>
                  )}
                </td>
                <td style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontSize: '0.875rem' }}>
                  {user.email}
                </td>
                <td style={{ padding: '0.75rem 1rem' }}>
                  <RoleBadge role={user.role_name} />
                </td>
                <td style={{ padding: '0.75rem 1rem' }}>
                  <button
                    onClick={() => toggleActive(user)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
                    title={user.is_active ? 'Click to deactivate' : 'Click to activate'}
                  >
                    <ActiveBadge active={user.is_active} />
                  </button>
                </td>
                <td style={{ padding: '0.75rem 1rem' }}>
                  <MfaBadge enabled={user.mfa_enabled} />
                </td>
                <td style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontSize: '0.875rem' }}>
                  {formatDate(user.created_at)}
                </td>
                <td style={{ padding: '0.75rem 1rem' }}>
                  <button
                    onClick={() => openEdit(user)}
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
                      backgroundColor: 'rgba(255,255,255,0.06)', border: 'none',
                      borderRadius: '0.375rem', padding: '0.375rem 0.625rem',
                      color: '#94a3b8', fontSize: '0.75rem', cursor: 'pointer',
                    }}
                  >
                    <Pencil style={{ width: '0.75rem', height: '0.75rem' }} />
                    Edit
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── Create User Modal ────────────────────── */}
      {showCreate && (
        <Modal title="Create User" onClose={() => setShowCreate(false)}>
          <form onSubmit={handleCreate}>
            {formError && (
              <div style={{
                padding: '0.5rem 0.75rem', borderRadius: '0.375rem',
                backgroundColor: 'rgba(239,68,68,0.1)', color: '#f87171',
                marginBottom: '1rem', fontSize: '0.8125rem',
              }}>{formError}</div>
            )}

            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>Username</label>
              <input
                required
                value={createForm.username}
                onChange={(e) => setCreateForm(f => ({ ...f, username: e.target.value }))}
                style={inputStyle}
                placeholder="jdoe"
              />
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>Full Name</label>
              <input
                required
                value={createForm.full_name}
                onChange={(e) => setCreateForm(f => ({ ...f, full_name: e.target.value }))}
                style={inputStyle}
                placeholder="Jane Doe"
              />
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>Email</label>
              <input
                required
                type="email"
                value={createForm.email}
                onChange={(e) => setCreateForm(f => ({ ...f, email: e.target.value }))}
                style={inputStyle}
                placeholder="jane@example.com"
              />
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>Password</label>
              <input
                required
                type="password"
                value={createForm.password}
                onChange={(e) => setCreateForm(f => ({ ...f, password: e.target.value }))}
                style={inputStyle}
                placeholder="Minimum 8 characters"
                minLength={8}
              />
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>Role</label>
              <select
                required
                value={createForm.role_name}
                onChange={(e) => setCreateForm(f => ({ ...f, role_name: e.target.value }))}
                style={selectStyle}
              >
                <option value="" disabled>Select a role</option>
                {roles.map(r => (
                  <option key={r.id} value={r.name}>{r.name} &mdash; {r.description}</option>
                ))}
              </select>
            </div>

            <div style={{ marginBottom: '1.25rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', color: '#94a3b8', fontSize: '0.875rem' }}>
                <input
                  type="checkbox"
                  checked={createForm.is_active}
                  onChange={(e) => setCreateForm(f => ({ ...f, is_active: e.target.checked }))}
                  style={{ accentColor: 'var(--color-accent)' }}
                />
                Active
              </label>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setShowCreate(false)}
                style={{
                  padding: '0.5rem 1rem', borderRadius: '0.5rem',
                  backgroundColor: 'rgba(255,255,255,0.06)', border: 'none',
                  color: '#94a3b8', fontSize: '0.875rem', cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                style={{
                  padding: '0.5rem 1rem', borderRadius: '0.5rem',
                  backgroundColor: 'var(--color-accent)', border: 'none',
                  color: 'white', fontSize: '0.875rem', fontWeight: 500,
                  cursor: saving ? 'default' : 'pointer',
                  opacity: saving ? 0.6 : 1,
                }}
              >
                {saving ? 'Creating...' : 'Create User'}
              </button>
            </div>
          </form>
        </Modal>
      )}

      {/* ── Edit User Modal ──────────────────────── */}
      {editUser && (
        <Modal title="Edit User" onClose={() => setEditUser(null)}>
          <form onSubmit={handleEdit}>
            {formError && (
              <div style={{
                padding: '0.5rem 0.75rem', borderRadius: '0.375rem',
                backgroundColor: 'rgba(239,68,68,0.1)', color: '#f87171',
                marginBottom: '1rem', fontSize: '0.8125rem',
              }}>{formError}</div>
            )}

            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>Username</label>
              <input
                disabled
                value={editUser.username}
                style={{ ...inputStyle, opacity: 0.5, cursor: 'not-allowed' }}
              />
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>Full Name</label>
              <input
                required
                value={editForm.full_name}
                onChange={(e) => setEditForm(f => ({ ...f, full_name: e.target.value }))}
                style={inputStyle}
              />
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>Email</label>
              <input
                required
                type="email"
                value={editForm.email}
                onChange={(e) => setEditForm(f => ({ ...f, email: e.target.value }))}
                style={inputStyle}
              />
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>Role</label>
              <select
                required
                value={editForm.role_name}
                onChange={(e) => setEditForm(f => ({ ...f, role_name: e.target.value }))}
                style={selectStyle}
              >
                {roles.map(r => (
                  <option key={r.id} value={r.name}>{r.name} &mdash; {r.description}</option>
                ))}
              </select>
            </div>

            <div style={{ marginBottom: '1.25rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', color: '#94a3b8', fontSize: '0.875rem' }}>
                <input
                  type="checkbox"
                  checked={editForm.is_active}
                  onChange={(e) => setEditForm(f => ({ ...f, is_active: e.target.checked }))}
                  style={{ accentColor: 'var(--color-accent)' }}
                />
                Active
              </label>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setEditUser(null)}
                style={{
                  padding: '0.5rem 1rem', borderRadius: '0.5rem',
                  backgroundColor: 'rgba(255,255,255,0.06)', border: 'none',
                  color: '#94a3b8', fontSize: '0.875rem', cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                style={{
                  padding: '0.5rem 1rem', borderRadius: '0.5rem',
                  backgroundColor: 'var(--color-accent)', border: 'none',
                  color: 'white', fontSize: '0.875rem', fontWeight: 500,
                  cursor: saving ? 'default' : 'pointer',
                  opacity: saving ? 0.6 : 1,
                }}
              >
                {saving ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
}
