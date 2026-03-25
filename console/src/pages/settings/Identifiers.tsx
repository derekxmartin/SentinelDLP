/**
 * Data Identifiers settings page.
 *
 * Manage built-in and custom data identifiers used by detection rules.
 * Supports CRUD operations, active/inactive toggling, and search filtering.
 */

import { useEffect, useState } from 'react';
import {
  Plus,
  Pencil,
  Trash2,
  Search,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  X,
  ScanSearch,
  Lock,
} from 'lucide-react';
import useTitle from '../../hooks/useTitle';
import api from '../../api/client';

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface Identifier {
  id: string;
  name: string;
  description: string;
  config: Record<string, unknown>;
  is_builtin: boolean;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

interface IdentifierForm {
  name: string;
  description: string;
  config: string;
  is_active: boolean;
}

const emptyForm: IdentifierForm = {
  name: '',
  description: '',
  config: '{}',
  is_active: true,
};

/* ------------------------------------------------------------------ */
/*  Shared styles                                                      */
/* ------------------------------------------------------------------ */

const cardStyle: React.CSSProperties = {
  backgroundColor: 'var(--color-surface-card)',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '0.75rem',
};

const labelStyle: React.CSSProperties = {
  fontSize: '0.75rem',
  fontWeight: 500,
  color: 'var(--color-text-secondary)',
  textTransform: 'uppercase' as const,
  letterSpacing: '0.05em',
  marginBottom: '0.375rem',
  display: 'block',
};

const inputStyle: React.CSSProperties = {
  backgroundColor: 'rgba(0,0,0,0.2)',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: '0.5rem',
  padding: '0.5rem 0.75rem',
  color: 'var(--color-text-primary)',
  fontSize: '0.875rem',
  width: '100%',
  outline: 'none',
};

const thStyle: React.CSSProperties = {
  padding: '0.75rem 1rem',
  textAlign: 'left' as const,
  fontWeight: 500,
  color: '#64748b',
  fontSize: '0.75rem',
  textTransform: 'uppercase' as const,
  letterSpacing: '0.05em',
};

const tdStyle: React.CSSProperties = {
  padding: '0.625rem 1rem',
  fontSize: '0.8125rem',
};

const btnStyle: React.CSSProperties = {
  padding: '0.375rem 0.5rem',
  borderRadius: '0.375rem',
  background: 'none',
  border: '1px solid rgba(255,255,255,0.1)',
  cursor: 'pointer',
  display: 'inline-flex',
  alignItems: 'center',
  gap: '0.25rem',
  fontSize: '0.75rem',
};

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function Identifiers() {
  useTitle('Data Identifiers');

  const [identifiers, setIdentifiers] = useState<Identifier[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<IdentifierForm>(emptyForm);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  /* ---------- data loading ---------- */

  useEffect(() => {
    loadIdentifiers();
  }, []);

  useEffect(() => {
    if (toast) {
      const t = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(t);
    }
  }, [toast]);

  async function loadIdentifiers() {
    try {
      const data = await api.get<Identifier[]>('/identifiers');
      setIdentifiers(data);
    } catch {
      // empty list on error
    } finally {
      setLoading(false);
    }
  }

  /* ---------- filtering ---------- */

  const filtered = identifiers.filter((ident) => {
    const q = searchQuery.toLowerCase();
    return (
      ident.name.toLowerCase().includes(q) ||
      ident.description.toLowerCase().includes(q)
    );
  });

  /* ---------- active toggle ---------- */

  async function handleToggleActive(ident: Identifier) {
    try {
      await api.put(`/identifiers/${ident.id}`, { is_active: !ident.is_active });
      setIdentifiers((prev) =>
        prev.map((i) => (i.id === ident.id ? { ...i, is_active: !i.is_active } : i)),
      );
    } catch {
      setToast({ type: 'error', message: `Failed to update "${ident.name}".` });
    }
  }

  /* ---------- create / edit ---------- */

  function openCreate() {
    setEditingId(null);
    setForm(emptyForm);
    setFormError('');
    setModalOpen(true);
  }

  function openEdit(ident: Identifier) {
    setEditingId(ident.id);
    setForm({
      name: ident.name,
      description: ident.description,
      config: JSON.stringify(ident.config, null, 2),
      is_active: ident.is_active,
    });
    setFormError('');
    setModalOpen(true);
  }

  function closeModal() {
    setModalOpen(false);
    setEditingId(null);
    setForm(emptyForm);
    setFormError('');
  }

  async function handleSave() {
    if (!form.name.trim()) {
      setFormError('Name is required.');
      return;
    }

    let parsedConfig: Record<string, unknown>;
    try {
      parsedConfig = JSON.parse(form.config);
    } catch {
      setFormError('Config must be valid JSON.');
      return;
    }

    setSaving(true);
    setFormError('');

    try {
      const body = {
        name: form.name.trim(),
        description: form.description.trim(),
        config: parsedConfig,
        is_active: form.is_active,
      };

      if (editingId) {
        await api.put(`/identifiers/${editingId}`, body);
        setToast({ type: 'success', message: `Updated "${body.name}".` });
      } else {
        await api.post('/identifiers', body);
        setToast({ type: 'success', message: `Created "${body.name}".` });
      }

      closeModal();
      await loadIdentifiers();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Save failed';
      setFormError(message);
    } finally {
      setSaving(false);
    }
  }

  /* ---------- delete ---------- */

  async function handleDelete(ident: Identifier) {
    if (!confirm(`Delete identifier "${ident.name}"?`)) return;
    try {
      await api.delete(`/identifiers/${ident.id}`);
      setToast({ type: 'success', message: `Deleted "${ident.name}".` });
      await loadIdentifiers();
    } catch {
      setToast({ type: 'error', message: `Failed to delete "${ident.name}".` });
    }
  }

  /* ---------- render ---------- */

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '50vh' }}>
        <RefreshCw className="w-6 h-6 text-slate-400 animate-spin" />
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '72rem', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
            Data Identifiers
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginTop: '0.25rem' }}>
            Manage pattern-based data identifiers used by detection rules.
          </p>
        </div>
        <button
          onClick={openCreate}
          style={{
            ...btnStyle,
            backgroundColor: '#6366f1',
            color: 'white',
            border: 'none',
            padding: '0.5rem 0.75rem',
            fontSize: '0.8125rem',
            fontWeight: 500,
          }}
        >
          <Plus style={{ width: '0.875rem', height: '0.875rem' }} /> New Identifier
        </button>
      </div>

      {/* Toast */}
      {toast && (
        <div
          style={{
            ...cardStyle,
            marginBottom: '1rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            borderColor: toast.type === 'success' ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)',
            padding: '0.75rem 1rem',
          }}
        >
          {toast.type === 'success' ? (
            <CheckCircle className="w-4 h-4" style={{ color: '#22c55e' }} />
          ) : (
            <AlertTriangle className="w-4 h-4" style={{ color: '#ef4444' }} />
          )}
          <span style={{ fontSize: '0.875rem', color: 'var(--color-text-primary)' }}>{toast.message}</span>
        </div>
      )}

      {/* Search bar */}
      <div style={{ marginBottom: '1rem', position: 'relative', maxWidth: '20rem' }}>
        <Search
          className="w-4 h-4"
          style={{
            position: 'absolute',
            left: '0.625rem',
            top: '50%',
            transform: 'translateY(-50%)',
            color: 'var(--color-text-secondary)',
          }}
        />
        <input
          type="text"
          placeholder="Search identifiers..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={{ ...inputStyle, paddingLeft: '2rem' }}
        />
      </div>

      {/* Table */}
      <div style={{ ...cardStyle, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
              {['Name', 'Description', 'Type', 'Active', 'Updated', 'Actions'].map((h) => (
                <th key={h} style={thStyle}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ padding: '3rem', textAlign: 'center', color: '#64748b' }}>
                  {identifiers.length === 0
                    ? 'No identifiers configured yet.'
                    : 'No identifiers match your search.'}
                </td>
              </tr>
            ) : (
              filtered.map((ident) => (
                <tr key={ident.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  {/* Name */}
                  <td style={{ ...tdStyle, color: '#e2e8f0', fontWeight: 500 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <ScanSearch style={{ width: '0.875rem', height: '0.875rem', color: '#6366f1', flexShrink: 0 }} />
                      {ident.name}
                    </div>
                  </td>

                  {/* Description */}
                  <td style={{ ...tdStyle, color: '#94a3b8', maxWidth: '20rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {ident.description || '\u2014'}
                  </td>

                  {/* Type badge */}
                  <td style={tdStyle}>
                    {ident.is_builtin ? (
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.25rem',
                        padding: '0.125rem 0.5rem',
                        borderRadius: '9999px',
                        fontSize: '0.75rem',
                        fontWeight: 500,
                        backgroundColor: 'rgba(99,102,241,0.15)',
                        color: '#818cf8',
                      }}>
                        <Lock style={{ width: '0.625rem', height: '0.625rem' }} />
                        Built-in
                      </span>
                    ) : (
                      <span style={{
                        display: 'inline-block',
                        padding: '0.125rem 0.5rem',
                        borderRadius: '9999px',
                        fontSize: '0.75rem',
                        fontWeight: 500,
                        backgroundColor: 'rgba(34,197,94,0.15)',
                        color: '#22c55e',
                      }}>
                        Custom
                      </span>
                    )}
                  </td>

                  {/* Active toggle */}
                  <td style={tdStyle}>
                    <button
                      onClick={() => handleToggleActive(ident)}
                      style={{
                        width: '2.5rem',
                        height: '1.25rem',
                        borderRadius: '9999px',
                        border: 'none',
                        cursor: 'pointer',
                        position: 'relative',
                        backgroundColor: ident.is_active ? '#22c55e' : 'rgba(255,255,255,0.1)',
                        transition: 'background-color 0.2s',
                      }}
                      title={ident.is_active ? 'Active — click to deactivate' : 'Inactive — click to activate'}
                    >
                      <span
                        style={{
                          position: 'absolute',
                          top: '0.125rem',
                          left: ident.is_active ? '1.375rem' : '0.125rem',
                          width: '1rem',
                          height: '1rem',
                          borderRadius: '9999px',
                          backgroundColor: 'white',
                          transition: 'left 0.2s',
                        }}
                      />
                    </button>
                  </td>

                  {/* Updated */}
                  <td style={{ ...tdStyle, color: '#64748b' }}>
                    {new Date(ident.updated_at).toLocaleDateString()}
                  </td>

                  {/* Actions */}
                  <td style={tdStyle}>
                    <div style={{ display: 'flex', gap: '0.375rem' }}>
                      <button
                        onClick={() => openEdit(ident)}
                        title="Edit"
                        style={{ ...btnStyle, color: '#94a3b8' }}
                      >
                        <Pencil style={{ width: '0.75rem', height: '0.75rem' }} />
                      </button>
                      <button
                        onClick={() => handleDelete(ident)}
                        title="Delete"
                        disabled={ident.is_builtin}
                        style={{
                          ...btnStyle,
                          color: ident.is_builtin ? '#334155' : '#ef4444',
                          cursor: ident.is_builtin ? 'not-allowed' : 'pointer',
                          opacity: ident.is_builtin ? 0.4 : 1,
                        }}
                      >
                        <Trash2 style={{ width: '0.75rem', height: '0.75rem' }} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Create / Edit Modal */}
      {modalOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget) closeModal();
          }}
        >
          <div
            style={{
              ...cardStyle,
              width: '32rem',
              maxHeight: '90vh',
              overflowY: 'auto',
              padding: '1.5rem',
            }}
          >
            {/* Modal header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                {editingId ? 'Edit Identifier' : 'New Identifier'}
              </h2>
              <button
                onClick={closeModal}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748b' }}
              >
                <X style={{ width: '1.25rem', height: '1.25rem' }} />
              </button>
            </div>

            {/* Error banner */}
            {formError && (
              <div
                style={{
                  marginBottom: '1rem',
                  padding: '0.5rem 0.75rem',
                  borderRadius: '0.5rem',
                  backgroundColor: 'rgba(239,68,68,0.1)',
                  border: '1px solid rgba(239,68,68,0.2)',
                  fontSize: '0.8125rem',
                  color: '#ef4444',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <AlertTriangle style={{ width: '0.875rem', height: '0.875rem', flexShrink: 0 }} />
                {formError}
              </div>
            )}

            {/* Name */}
            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>Name</label>
              <input
                type="text"
                placeholder="e.g. Credit Card Number"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                style={inputStyle}
              />
            </div>

            {/* Description */}
            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>Description</label>
              <input
                type="text"
                placeholder="Optional description"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                style={inputStyle}
              />
            </div>

            {/* Config JSON */}
            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>Config (JSON)</label>
              <textarea
                value={form.config}
                onChange={(e) => setForm({ ...form, config: e.target.value })}
                rows={8}
                style={{
                  ...inputStyle,
                  fontFamily: 'monospace',
                  fontSize: '0.8125rem',
                  resize: 'vertical',
                  lineHeight: 1.5,
                }}
                placeholder='{"pattern": "\\\\b\\\\d{4}[- ]?\\\\d{4}[- ]?\\\\d{4}[- ]?\\\\d{4}\\\\b"}'
              />
            </div>

            {/* Active checkbox */}
            <div style={{ marginBottom: '1.5rem' }}>
              <label
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  cursor: 'pointer',
                  fontSize: '0.875rem',
                  color: 'var(--color-text-primary)',
                }}
              >
                <input
                  type="checkbox"
                  checked={form.is_active}
                  onChange={(e) => setForm({ ...form, is_active: e.target.checked })}
                  style={{ accentColor: '#6366f1' }}
                />
                Active
              </label>
            </div>

            {/* Modal actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                onClick={closeModal}
                style={{
                  ...btnStyle,
                  padding: '0.5rem 1rem',
                  fontSize: '0.8125rem',
                  color: '#94a3b8',
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving}
                style={{
                  ...btnStyle,
                  backgroundColor: '#6366f1',
                  color: 'white',
                  border: 'none',
                  padding: '0.5rem 1rem',
                  fontSize: '0.8125rem',
                  fontWeight: 500,
                  opacity: saving ? 0.6 : 1,
                  cursor: saving ? 'not-allowed' : 'pointer',
                }}
              >
                {saving ? 'Saving...' : editingId ? 'Update' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
