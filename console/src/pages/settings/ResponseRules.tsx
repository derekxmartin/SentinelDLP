/**
 * Response Rules management page.
 *
 * CRUD for response rules that define what actions are taken
 * when a DLP policy violation is detected.
 */

import { useEffect, useState } from 'react';
import {
  ShieldCheck,
  Plus,
  Pencil,
  Trash2,
  X,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  ChevronUp,
  ChevronDown,
} from 'lucide-react';
import useTitle from '../../hooks/useTitle';
import api from '../../api/client';

/* ------------------------------------------------------------------ */
/*  Types                                                             */
/* ------------------------------------------------------------------ */

interface RuleAction {
  id?: string;
  action_type: string;
  config: Record<string, unknown>;
  order: number;
}

interface ResponseRule {
  id: string;
  name: string;
  description: string;
  is_active: boolean;
  actions: RuleAction[];
  created_at: string;
  updated_at: string;
}

interface FormAction {
  action_type: string;
  config: string; // JSON string for editing
  order: number;
}

const ACTION_TYPES = [
  'block',
  'notify',
  'log',
  'quarantine',
  'user_cancel',
  'escalate',
  'send_email',
] as const;

const ACTION_COLORS: Record<string, string> = {
  block: '#ef4444',
  notify: '#3b82f6',
  log: '#64748b',
  quarantine: '#f97316',
  user_cancel: '#eab308',
  escalate: '#a855f7',
  send_email: '#06b6d4',
};

/* ------------------------------------------------------------------ */
/*  Shared styles                                                     */
/* ------------------------------------------------------------------ */

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

const overlayStyle: React.CSSProperties = {
  position: 'fixed',
  inset: 0,
  backgroundColor: 'rgba(0,0,0,0.6)',
  zIndex: 50,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
};

const modalStyle: React.CSSProperties = {
  backgroundColor: '#1e293b',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: '0.75rem',
  padding: '1.5rem',
  width: '40rem',
  maxHeight: '90vh',
  overflowY: 'auto',
};

const btnPrimary: React.CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: '0.5rem',
  padding: '0.5rem 1.25rem',
  borderRadius: '0.5rem',
  backgroundColor: '#3b82f6',
  color: 'white',
  fontWeight: 500,
  fontSize: '0.875rem',
  border: 'none',
  cursor: 'pointer',
};

const btnSecondary: React.CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: '0.5rem',
  padding: '0.5rem 1rem',
  borderRadius: '0.5rem',
  backgroundColor: 'transparent',
  color: 'var(--color-text-secondary)',
  fontWeight: 500,
  fontSize: '0.875rem',
  border: '1px solid rgba(255,255,255,0.1)',
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
  flexShrink: 0,
};

/* ------------------------------------------------------------------ */
/*  Badge                                                             */
/* ------------------------------------------------------------------ */

function ActionBadge({ type }: { type: string }) {
  const color = ACTION_COLORS[type] || '#64748b';
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '0.125rem 0.5rem',
        borderRadius: '9999px',
        fontSize: '0.75rem',
        fontWeight: 500,
        backgroundColor: `${color}1a`,
        color,
        textTransform: 'capitalize',
      }}
    >
      {type.replace('_', ' ')}
    </span>
  );
}

function StatusBadge({ active }: { active: boolean }) {
  const color = active ? '#22c55e' : '#64748b';
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '0.125rem 0.5rem',
        borderRadius: '9999px',
        fontSize: '0.75rem',
        fontWeight: 500,
        backgroundColor: `${color}1a`,
        color,
      }}
    >
      {active ? 'Active' : 'Inactive'}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  Component                                                         */
/* ------------------------------------------------------------------ */

export default function ResponseRules() {
  useTitle('Response Rules');

  const [rules, setRules] = useState<ResponseRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<ResponseRule | null>(null);
  const [formName, setFormName] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formIsActive, setFormIsActive] = useState(true);
  const [formActions, setFormActions] = useState<FormAction[]>([]);
  const [saving, setSaving] = useState(false);

  // Delete confirmation
  const [deleteTarget, setDeleteTarget] = useState<ResponseRule | null>(null);

  useEffect(() => {
    loadRules();
  }, []);

  useEffect(() => {
    if (toast) {
      const t = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(t);
    }
  }, [toast]);

  async function loadRules() {
    try {
      const data = await api.get<ResponseRule[]>('/response-rules');
      setRules(data);
    } catch {
      setToast({ type: 'error', message: 'Failed to load response rules.' });
    } finally {
      setLoading(false);
    }
  }

  /* ---------- Modal helpers ---------- */

  function openCreate() {
    setEditingRule(null);
    setFormName('');
    setFormDescription('');
    setFormIsActive(true);
    setFormActions([]);
    setModalOpen(true);
  }

  function openEdit(rule: ResponseRule) {
    setEditingRule(rule);
    setFormName(rule.name);
    setFormDescription(rule.description);
    setFormIsActive(rule.is_active);
    setFormActions(
      rule.actions.map((a) => ({
        action_type: a.action_type,
        config: JSON.stringify(a.config, null, 2),
        order: a.order,
      })),
    );
    setModalOpen(true);
  }

  function closeModal() {
    setModalOpen(false);
    setEditingRule(null);
  }

  function addAction() {
    const nextOrder = formActions.length > 0 ? Math.max(...formActions.map((a) => a.order)) + 1 : 1;
    setFormActions([...formActions, { action_type: 'log', config: '{}', order: nextOrder }]);
  }

  function removeAction(idx: number) {
    setFormActions(formActions.filter((_, i) => i !== idx));
  }

  function updateAction(idx: number, field: keyof FormAction, value: string | number) {
    setFormActions(
      formActions.map((a, i) => (i === idx ? { ...a, [field]: value } : a)),
    );
  }

  function moveAction(idx: number, direction: 'up' | 'down') {
    if (direction === 'up' && idx === 0) return;
    if (direction === 'down' && idx === formActions.length - 1) return;
    const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
    const updated = [...formActions];
    const tempOrder = updated[idx].order;
    updated[idx].order = updated[swapIdx].order;
    updated[swapIdx].order = tempOrder;
    [updated[idx], updated[swapIdx]] = [updated[swapIdx], updated[idx]];
    setFormActions(updated);
  }

  async function handleSave() {
    if (!formName.trim()) {
      setToast({ type: 'error', message: 'Rule name is required.' });
      return;
    }

    // Validate JSON configs
    const parsedActions: { action_type: string; config: Record<string, unknown>; order: number }[] = [];
    for (let i = 0; i < formActions.length; i++) {
      try {
        const config = JSON.parse(formActions[i].config);
        parsedActions.push({
          action_type: formActions[i].action_type,
          config,
          order: formActions[i].order,
        });
      } catch {
        setToast({ type: 'error', message: `Action #${i + 1}: invalid JSON config.` });
        return;
      }
    }

    const body = {
      name: formName.trim(),
      description: formDescription.trim(),
      is_active: formIsActive,
      actions: parsedActions,
    };

    setSaving(true);
    try {
      if (editingRule) {
        await api.put(`/response-rules/${editingRule.id}`, body);
        setToast({ type: 'success', message: `Rule "${body.name}" updated.` });
      } else {
        await api.post('/response-rules', body);
        setToast({ type: 'success', message: `Rule "${body.name}" created.` });
      }
      closeModal();
      await loadRules();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Save failed';
      setToast({ type: 'error', message });
    } finally {
      setSaving(false);
    }
  }

  /* ---------- Delete ---------- */

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.delete(`/response-rules/${deleteTarget.id}`);
      setToast({ type: 'success', message: `Rule "${deleteTarget.name}" deleted.` });
      setDeleteTarget(null);
      await loadRules();
    } catch {
      setToast({ type: 'error', message: `Failed to delete "${deleteTarget.name}".` });
    }
  }

  /* ---------- Render ---------- */

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
            Response Rules
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginTop: '0.25rem' }}>
            Configure actions taken when policy violations are detected.
          </p>
        </div>
        <button onClick={openCreate} style={btnPrimary}>
          <Plus className="w-4 h-4" />
          New Rule
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

      {/* Rules table */}
      <div style={cardStyle}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '2rem',
              height: '2rem',
              borderRadius: '0.5rem',
              backgroundColor: 'rgba(59,130,246,0.15)',
            }}
          >
            <ShieldCheck className="w-4 h-4" style={{ color: '#3b82f6' }} />
          </div>
          <div>
            <h2 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
              Rules
            </h2>
            <p style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
              {rules.length} rule{rules.length !== 1 ? 's' : ''} configured
            </p>
          </div>
        </div>

        {rules.length === 0 ? (
          <div
            style={{
              textAlign: 'center',
              padding: '2rem',
              color: 'var(--color-text-secondary)',
              fontSize: '0.875rem',
            }}
          >
            No response rules configured yet. Click &ldquo;New Rule&rdquo; to get started.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={thStyle}>Name</th>
                  <th style={thStyle}>Description</th>
                  <th style={thStyle}>Actions</th>
                  <th style={thStyle}>Status</th>
                  <th style={{ ...thStyle, textAlign: 'right' }}>Manage</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr
                    key={rule.id}
                    style={{ transition: 'background-color 0.15s' }}
                    onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)')}
                    onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                  >
                    <td style={{ ...tdStyle, fontWeight: 600, whiteSpace: 'nowrap' }}>{rule.name}</td>
                    <td style={{ ...tdStyle, color: 'var(--color-text-secondary)', maxWidth: '16rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {rule.description || '\u2014'}
                    </td>
                    <td style={tdStyle}>
                      <div style={{ display: 'flex', gap: '0.375rem', flexWrap: 'wrap' }}>
                        {rule.actions.length === 0 ? (
                          <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.75rem' }}>None</span>
                        ) : (
                          rule.actions
                            .slice()
                            .sort((a, b) => a.order - b.order)
                            .map((a, i) => <ActionBadge key={i} type={a.action_type} />)
                        )}
                      </div>
                    </td>
                    <td style={tdStyle}>
                      <StatusBadge active={rule.is_active} />
                    </td>
                    <td style={{ ...tdStyle, textAlign: 'right' }}>
                      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                        <button
                          onClick={() => openEdit(rule)}
                          title="Edit rule"
                          style={{
                            ...btnDanger,
                            border: '1px solid rgba(255,255,255,0.1)',
                            color: 'var(--color-text-secondary)',
                          }}
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => setDeleteTarget(rule)}
                          title="Delete rule"
                          style={btnDanger}
                        >
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

      {/* ---- Create / Edit Modal ---- */}
      {modalOpen && (
        <div style={overlayStyle} onClick={closeModal}>
          <div style={modalStyle} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                {editingRule ? 'Edit Rule' : 'New Response Rule'}
              </h2>
              <button onClick={closeModal} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-text-secondary)' }}>
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Name / Description */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
              <div>
                <label style={labelStyle}>Name *</label>
                <input
                  type="text"
                  placeholder="e.g. Block & Notify"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  style={inputStyle}
                />
              </div>
              <div>
                <label style={labelStyle}>Description</label>
                <input
                  type="text"
                  placeholder="Optional description"
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  style={inputStyle}
                />
              </div>
            </div>

            {/* Active toggle */}
            <div style={{ marginBottom: '1.25rem' }}>
              <label
                style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', cursor: 'pointer' }}
                onClick={() => setFormIsActive(!formIsActive)}
              >
                <div
                  style={{
                    width: '2.5rem',
                    height: '1.375rem',
                    borderRadius: '9999px',
                    backgroundColor: formIsActive ? '#3b82f6' : 'rgba(255,255,255,0.15)',
                    position: 'relative',
                    transition: 'background-color 0.2s',
                    cursor: 'pointer',
                    flexShrink: 0,
                  }}
                >
                  <div
                    style={{
                      width: '1rem',
                      height: '1rem',
                      borderRadius: '9999px',
                      backgroundColor: 'white',
                      position: 'absolute',
                      top: '0.1875rem',
                      left: formIsActive ? '1.3125rem' : '0.1875rem',
                      transition: 'left 0.2s',
                    }}
                  />
                </div>
                <span style={{ fontSize: '0.875rem', color: 'var(--color-text-primary)' }}>
                  {formIsActive ? 'Active' : 'Inactive'}
                </span>
              </label>
            </div>

            {/* Actions editor */}
            <div style={{ marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                <label style={{ ...labelStyle, marginBottom: 0 }}>Actions</label>
                <button onClick={addAction} style={{ ...btnSecondary, padding: '0.25rem 0.75rem', fontSize: '0.75rem' }}>
                  <Plus className="w-3.5 h-3.5" />
                  Add Action
                </button>
              </div>

              {formActions.length === 0 && (
                <div
                  style={{
                    textAlign: 'center',
                    padding: '1.25rem',
                    color: 'var(--color-text-secondary)',
                    fontSize: '0.8125rem',
                    backgroundColor: 'rgba(0,0,0,0.15)',
                    borderRadius: '0.5rem',
                    border: '1px dashed rgba(255,255,255,0.1)',
                  }}
                >
                  No actions yet. Click &ldquo;Add Action&rdquo; to define what happens on violation.
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {formActions.map((action, idx) => (
                  <div
                    key={idx}
                    style={{
                      display: 'flex',
                      gap: '0.75rem',
                      alignItems: 'flex-start',
                      padding: '0.75rem',
                      backgroundColor: 'rgba(0,0,0,0.15)',
                      borderRadius: '0.5rem',
                      border: '1px solid rgba(255,255,255,0.05)',
                    }}
                  >
                    {/* Order buttons */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.125rem', paddingTop: '0.25rem' }}>
                      <button
                        onClick={() => moveAction(idx, 'up')}
                        disabled={idx === 0}
                        style={{
                          background: 'none',
                          border: 'none',
                          cursor: idx === 0 ? 'default' : 'pointer',
                          color: idx === 0 ? 'rgba(255,255,255,0.15)' : 'var(--color-text-secondary)',
                          padding: 0,
                          lineHeight: 1,
                        }}
                      >
                        <ChevronUp className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => moveAction(idx, 'down')}
                        disabled={idx === formActions.length - 1}
                        style={{
                          background: 'none',
                          border: 'none',
                          cursor: idx === formActions.length - 1 ? 'default' : 'pointer',
                          color: idx === formActions.length - 1 ? 'rgba(255,255,255,0.15)' : 'var(--color-text-secondary)',
                          padding: 0,
                          lineHeight: 1,
                        }}
                      >
                        <ChevronDown className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    {/* Action type */}
                    <div style={{ width: '9rem', flexShrink: 0 }}>
                      <label style={{ ...labelStyle, fontSize: '0.625rem' }}>Type</label>
                      <select
                        value={action.action_type}
                        onChange={(e) => updateAction(idx, 'action_type', e.target.value)}
                        style={{ ...inputStyle, cursor: 'pointer' }}
                      >
                        {ACTION_TYPES.map((t) => (
                          <option key={t} value={t} style={{ backgroundColor: '#1e293b' }}>
                            {t.replace('_', ' ')}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Order */}
                    <div style={{ width: '4.5rem', flexShrink: 0 }}>
                      <label style={{ ...labelStyle, fontSize: '0.625rem' }}>Order</label>
                      <input
                        type="number"
                        min={0}
                        value={action.order}
                        onChange={(e) => updateAction(idx, 'order', parseInt(e.target.value, 10) || 0)}
                        style={inputStyle}
                      />
                    </div>

                    {/* Config JSON */}
                    <div style={{ flex: 1 }}>
                      <label style={{ ...labelStyle, fontSize: '0.625rem' }}>Config (JSON)</label>
                      <textarea
                        value={action.config}
                        onChange={(e) => updateAction(idx, 'config', e.target.value)}
                        rows={2}
                        style={{
                          ...inputStyle,
                          resize: 'vertical',
                          fontFamily: 'monospace',
                          fontSize: '0.75rem',
                        }}
                      />
                    </div>

                    {/* Remove */}
                    <button
                      onClick={() => removeAction(idx)}
                      title="Remove action"
                      style={{ ...btnDanger, marginTop: '1.25rem' }}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* Modal footer */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', paddingTop: '0.75rem', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
              <button onClick={closeModal} style={btnSecondary}>
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving}
                style={{ ...btnPrimary, opacity: saving ? 0.6 : 1, cursor: saving ? 'not-allowed' : 'pointer' }}
              >
                {saving && <RefreshCw className="w-4 h-4 animate-spin" />}
                {editingRule ? 'Update Rule' : 'Create Rule'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ---- Delete Confirmation Modal ---- */}
      {deleteTarget && (
        <div style={overlayStyle} onClick={() => setDeleteTarget(null)}>
          <div
            style={{ ...modalStyle, width: '26rem', textAlign: 'center' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: '3rem',
                height: '3rem',
                borderRadius: '9999px',
                backgroundColor: 'rgba(239,68,68,0.15)',
                margin: '0 auto 1rem',
              }}
            >
              <AlertTriangle className="w-6 h-6" style={{ color: '#ef4444' }} />
            </div>
            <h3 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '0.5rem' }}>
              Delete Rule
            </h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginBottom: '1.5rem' }}>
              Are you sure you want to delete <strong style={{ color: 'var(--color-text-primary)' }}>{deleteTarget.name}</strong>?
              This action cannot be undone.
            </p>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '0.75rem' }}>
              <button onClick={() => setDeleteTarget(null)} style={btnSecondary}>
                Cancel
              </button>
              <button
                onClick={handleDelete}
                style={{ ...btnPrimary, backgroundColor: '#ef4444' }}
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
