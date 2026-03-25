/**
 * Keyword Dictionaries settings page.
 *
 * Manage keyword dictionaries used in DLP detection rules.
 * Each dictionary contains a list of keywords stored in config.keywords.
 */

import { useEffect, useState } from 'react';
import {
  Book,
  Plus,
  Pencil,
  Trash2,
  Search,
  X,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react';
import useTitle from '../../hooks/useTitle';
import api from '../../api/client';

/* ── Types ─────────────────────────────────────────────────── */

interface DictionaryConfig {
  keywords: string[];
}

interface Dictionary {
  id: string;
  name: string;
  description: string;
  config: DictionaryConfig;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

interface DictionaryForm {
  name: string;
  description: string;
  keywordsText: string;
  is_active: boolean;
}

const emptyForm: DictionaryForm = {
  name: '',
  description: '',
  keywordsText: '',
  is_active: true,
};

/* ── Shared styles ─────────────────────────────────────────── */

const cardStyle: React.CSSProperties = {
  backgroundColor: 'var(--color-surface-card)',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '0.75rem',
  padding: '1.5rem',
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
  backgroundColor: '#1e293b',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: '0.5rem',
  padding: '0.5rem 0.75rem',
  color: 'white',
  fontSize: '0.875rem',
  width: '100%',
  outline: 'none',
};

const thStyle: React.CSSProperties = {
  color: '#64748b',
  fontWeight: 500,
  fontSize: '0.75rem',
  textTransform: 'uppercase' as const,
  letterSpacing: '0.05em',
  padding: '0.75rem 1rem',
  textAlign: 'left',
  borderBottom: '1px solid rgba(255,255,255,0.06)',
};

const tdStyle: React.CSSProperties = {
  padding: '0.75rem 1rem',
  fontSize: '0.875rem',
  color: 'var(--color-text-primary)',
  borderBottom: '1px solid rgba(255,255,255,0.04)',
};

const btnPrimary: React.CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: '0.5rem',
  padding: '0.5rem 1rem',
  borderRadius: '0.5rem',
  backgroundColor: '#6366f1',
  color: 'white',
  fontWeight: 500,
  fontSize: '0.875rem',
  border: 'none',
  cursor: 'pointer',
};

const btnDanger: React.CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  width: '2rem',
  height: '2rem',
  borderRadius: '0.375rem',
  backgroundColor: 'transparent',
  border: '1px solid rgba(239,68,68,0.2)',
  color: '#ef4444',
  cursor: 'pointer',
};

const btnGhost: React.CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  width: '2rem',
  height: '2rem',
  borderRadius: '0.375rem',
  backgroundColor: 'transparent',
  border: '1px solid rgba(255,255,255,0.1)',
  color: '#94a3b8',
  cursor: 'pointer',
};

/* ── Component ─────────────────────────────────────────────── */

export default function Dictionaries() {
  useTitle('Keyword Dictionaries');

  const [loading, setLoading] = useState(true);
  const [dictionaries, setDictionaries] = useState<Dictionary[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<DictionaryForm>(emptyForm);
  const [saving, setSaving] = useState(false);

  // Delete confirmation
  const [deleteTarget, setDeleteTarget] = useState<Dictionary | null>(null);

  useEffect(() => {
    loadDictionaries();
  }, []);

  useEffect(() => {
    if (toast) {
      const t = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(t);
    }
  }, [toast]);

  async function loadDictionaries() {
    try {
      const data = await api.get<Dictionary[]>('/dictionaries');
      setDictionaries(data);
    } catch {
      setToast({ type: 'error', message: 'Failed to load dictionaries.' });
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditingId(null);
    setForm(emptyForm);
    setModalOpen(true);
  }

  function openEdit(dict: Dictionary) {
    setEditingId(dict.id);
    setForm({
      name: dict.name,
      description: dict.description || '',
      keywordsText: (dict.config.keywords || []).join('\n'),
      is_active: dict.is_active,
    });
    setModalOpen(true);
  }

  function closeModal() {
    setModalOpen(false);
    setEditingId(null);
    setForm(emptyForm);
  }

  async function handleSave() {
    if (!form.name.trim()) {
      setToast({ type: 'error', message: 'Dictionary name is required.' });
      return;
    }

    const keywords = form.keywordsText
      .split('\n')
      .map((k) => k.trim())
      .filter(Boolean);

    if (keywords.length === 0) {
      setToast({ type: 'error', message: 'Add at least one keyword.' });
      return;
    }

    setSaving(true);
    try {
      const payload = {
        name: form.name.trim(),
        description: form.description.trim(),
        config: { keywords },
        is_active: form.is_active,
      };

      if (editingId) {
        await api.put(`/dictionaries/${editingId}`, payload);
        setToast({ type: 'success', message: `Dictionary "${payload.name}" updated.` });
      } else {
        await api.post('/dictionaries', payload);
        setToast({ type: 'success', message: `Dictionary "${payload.name}" created.` });
      }

      closeModal();
      await loadDictionaries();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Save failed';
      setToast({ type: 'error', message });
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.delete(`/dictionaries/${deleteTarget.id}`);
      setToast({ type: 'success', message: `Dictionary "${deleteTarget.name}" deleted.` });
      setDeleteTarget(null);
      await loadDictionaries();
    } catch {
      setToast({ type: 'error', message: `Failed to delete "${deleteTarget.name}".` });
      setDeleteTarget(null);
    }
  }

  const filtered = dictionaries.filter(
    (d) =>
      d.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (d.description || '').toLowerCase().includes(searchQuery.toLowerCase()),
  );

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '50vh' }}>
        <RefreshCw className="w-6 h-6 text-slate-400 animate-spin" />
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '64rem', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
            Keyword Dictionaries
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginTop: '0.25rem' }}>
            Manage keyword lists used for content detection in DLP policies.
          </p>
        </div>
        <button onClick={openCreate} style={btnPrimary}>
          <Plus className="w-4 h-4" />
          New Dictionary
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

      {/* Table card */}
      <div style={cardStyle}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: '2rem',
                height: '2rem',
                borderRadius: '0.5rem',
                backgroundColor: 'rgba(99,102,241,0.15)',
              }}
            >
              <Book className="w-4 h-4" style={{ color: '#6366f1' }} />
            </div>
            <div>
              <h2 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                Dictionaries
              </h2>
              <p style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                {dictionaries.length} dictionar{dictionaries.length === 1 ? 'y' : 'ies'} configured
              </p>
            </div>
          </div>

          {dictionaries.length > 0 && (
            <div style={{ position: 'relative' }}>
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
                placeholder="Search dictionaries..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  ...inputStyle,
                  paddingLeft: '2rem',
                  width: '16rem',
                }}
              />
            </div>
          )}
        </div>

        {filtered.length === 0 ? (
          <div
            style={{
              textAlign: 'center',
              padding: '2.5rem',
              color: 'var(--color-text-secondary)',
              fontSize: '0.875rem',
            }}
          >
            {dictionaries.length === 0
              ? 'No dictionaries configured yet. Create one to get started.'
              : 'No dictionaries match your search.'}
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={thStyle}>Name</th>
                  <th style={thStyle}>Description</th>
                  <th style={{ ...thStyle, textAlign: 'center' }}>Keywords</th>
                  <th style={{ ...thStyle, textAlign: 'center' }}>Status</th>
                  <th style={{ ...thStyle, textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((dict) => (
                  <tr key={dict.id}>
                    <td style={{ ...tdStyle, fontWeight: 600, whiteSpace: 'nowrap' }}>{dict.name}</td>
                    <td
                      style={{
                        ...tdStyle,
                        color: 'var(--color-text-secondary)',
                        maxWidth: '20rem',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {dict.description || '\u2014'}
                    </td>
                    <td style={{ ...tdStyle, textAlign: 'center' }}>
                      <span
                        style={{
                          display: 'inline-block',
                          padding: '0.125rem 0.5rem',
                          borderRadius: '9999px',
                          fontSize: '0.75rem',
                          fontWeight: 500,
                          backgroundColor: 'rgba(99,102,241,0.15)',
                          color: '#818cf8',
                        }}
                      >
                        {(dict.config.keywords || []).length}
                      </span>
                    </td>
                    <td style={{ ...tdStyle, textAlign: 'center' }}>
                      <span
                        style={{
                          display: 'inline-block',
                          padding: '0.125rem 0.5rem',
                          borderRadius: '9999px',
                          fontSize: '0.75rem',
                          fontWeight: 500,
                          backgroundColor: dict.is_active
                            ? 'rgba(34,197,94,0.15)'
                            : 'rgba(100,116,139,0.15)',
                          color: dict.is_active ? '#22c55e' : '#64748b',
                        }}
                      >
                        {dict.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td style={{ ...tdStyle, textAlign: 'right' }}>
                      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                        <button onClick={() => openEdit(dict)} title="Edit" style={btnGhost}>
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => setDeleteTarget(dict)} title="Delete" style={btnDanger}>
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create / Edit Modal */}
      {modalOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.6)',
            zIndex: 50,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget) closeModal();
          }}
        >
          <div
            style={{
              backgroundColor: '#1e293b',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '0.75rem',
              padding: '1.5rem',
              width: '100%',
              maxWidth: '32rem',
              maxHeight: '90vh',
              overflowY: 'auto',
            }}
          >
            {/* Modal header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'white' }}>
                {editingId ? 'Edit Dictionary' : 'New Dictionary'}
              </h2>
              <button
                onClick={closeModal}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#94a3b8',
                  cursor: 'pointer',
                  padding: '0.25rem',
                }}
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Name */}
            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>Name</label>
              <input
                type="text"
                placeholder="e.g. PCI Keywords"
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

            {/* Keywords */}
            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>
                Keywords{' '}
                <span style={{ textTransform: 'none', fontWeight: 400, color: '#64748b' }}>
                  (one per line)
                </span>
              </label>
              <textarea
                rows={8}
                placeholder={'credit card\nsocial security\npassport number\nbank account'}
                value={form.keywordsText}
                onChange={(e) => setForm({ ...form, keywordsText: e.target.value })}
                style={{
                  ...inputStyle,
                  resize: 'vertical',
                  fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace',
                  fontSize: '0.8125rem',
                  lineHeight: '1.6',
                }}
              />
              <p style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.375rem' }}>
                {form.keywordsText.split('\n').filter((k) => k.trim()).length} keyword
                {form.keywordsText.split('\n').filter((k) => k.trim()).length === 1 ? '' : 's'}
              </p>
            </div>

            {/* Active toggle */}
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
              <p style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem', marginLeft: '1.25rem' }}>
                Inactive dictionaries are ignored during content scanning.
              </p>
            </div>

            {/* Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                onClick={closeModal}
                style={{
                  padding: '0.5rem 1rem',
                  borderRadius: '0.5rem',
                  backgroundColor: 'transparent',
                  border: '1px solid rgba(255,255,255,0.1)',
                  color: '#94a3b8',
                  fontSize: '0.875rem',
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving}
                style={{
                  ...btnPrimary,
                  opacity: saving ? 0.6 : 1,
                  cursor: saving ? 'not-allowed' : 'pointer',
                }}
              >
                {saving && <RefreshCw className="w-4 h-4 animate-spin" />}
                {editingId ? 'Save Changes' : 'Create Dictionary'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirmation modal */}
      {deleteTarget && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.6)',
            zIndex: 50,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget) setDeleteTarget(null);
          }}
        >
          <div
            style={{
              backgroundColor: '#1e293b',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '0.75rem',
              padding: '1.5rem',
              width: '100%',
              maxWidth: '24rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  width: '2.5rem',
                  height: '2.5rem',
                  borderRadius: '0.5rem',
                  backgroundColor: 'rgba(239,68,68,0.15)',
                }}
              >
                <AlertTriangle className="w-5 h-5" style={{ color: '#ef4444' }} />
              </div>
              <div>
                <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'white' }}>Delete Dictionary</h3>
                <p style={{ fontSize: '0.8125rem', color: '#94a3b8' }}>This action cannot be undone.</p>
              </div>
            </div>

            <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginBottom: '1.5rem' }}>
              Are you sure you want to delete <strong style={{ color: 'white' }}>{deleteTarget.name}</strong>?
              Any policies referencing this dictionary may stop working.
            </p>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                onClick={() => setDeleteTarget(null)}
                style={{
                  padding: '0.5rem 1rem',
                  borderRadius: '0.5rem',
                  backgroundColor: 'transparent',
                  border: '1px solid rgba(255,255,255,0.1)',
                  color: '#94a3b8',
                  fontSize: '0.875rem',
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  padding: '0.5rem 1rem',
                  borderRadius: '0.5rem',
                  backgroundColor: '#ef4444',
                  color: 'white',
                  fontWeight: 500,
                  fontSize: '0.875rem',
                  border: 'none',
                  cursor: 'pointer',
                }}
              >
                <Trash2 className="w-4 h-4" />
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
