/**
 * Policy list page (P2-T10).
 * Status badges, create from template, activate/suspend.
 */

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, Play, Pause, Trash2, Copy } from 'lucide-react';
import useTitle from '../hooks/useTitle';
import api from '../api/client';

interface Policy {
  id: string;
  name: string;
  description: string | null;
  status: string;
  severity: string;
  is_template: boolean;
  template_name: string | null;
  detection_rules: unknown[];
  exceptions: unknown[];
  created_at: string;
}

interface PolicyList {
  items: Policy[];
  total: number;
}

interface Template {
  id: string;
  name: string;
  template_name: string;
  description: string | null;
  severity: string;
}

const STATUS_COLORS: Record<string, string> = {
  active: '#22c55e', suspended: '#f97316', draft: '#64748b',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#64748b',
};

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      display: 'inline-block', padding: '0.125rem 0.5rem', borderRadius: '9999px',
      fontSize: '0.75rem', fontWeight: 500, backgroundColor: `${color}1a`, color,
      textTransform: 'capitalize',
    }}>
      {label}
    </span>
  );
}

const btnStyle: React.CSSProperties = {
  padding: '0.375rem 0.5rem', borderRadius: '0.375rem', background: 'none',
  border: '1px solid rgba(255,255,255,0.1)', cursor: 'pointer',
  display: 'inline-flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.75rem',
};

export default function Policies() {
  useTitle('Policies');
  const navigate = useNavigate();

  const [policies, setPolicies] = useState<Policy[]>([]);
  const [templates, setTemplates] = useState<Template[]>([]);
  const [showTemplates, setShowTemplates] = useState(false);
  const [loading, setLoading] = useState(true);

  function loadPolicies() {
    api.get<PolicyList>('/policies', { page_size: '50' })
      .then((data) => setPolicies(data.items))
      .catch(() => {})
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    loadPolicies();
    api.get<Template[]>('/policies/templates').then(setTemplates).catch(() => {});
  }, []);

  async function handleActivate(id: string) {
    await api.post(`/policies/${id}/activate`);
    loadPolicies();
  }

  async function handleSuspend(id: string) {
    await api.post(`/policies/${id}/suspend`);
    loadPolicies();
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this policy?')) return;
    await api.delete(`/policies/${id}`);
    loadPolicies();
  }

  async function handleCreateFromTemplate(templateName: string) {
    const name = prompt('Policy name:');
    if (!name) return;
    const created = await api.post<Policy>('/policies/from-template', {
      template_name: templateName,
      name,
    });
    setShowTemplates(false);
    loadPolicies();
    navigate(`/policies/${created.id}`);
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'white' }}>Policies</h1>
        <button
          onClick={() => setShowTemplates(!showTemplates)}
          style={{ ...btnStyle, backgroundColor: '#6366f1', color: 'white', border: 'none', padding: '0.5rem 0.75rem', fontSize: '0.8125rem' }}
        >
          <Plus style={{ width: '0.875rem', height: '0.875rem' }} /> Create from Template
        </button>
      </div>

      {/* Template picker */}
      {showTemplates && (
        <div style={{
          backgroundColor: 'var(--color-surface-card)', border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: '0.75rem', padding: '1rem', marginBottom: '1rem',
          display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem',
        }}>
          {templates.map((t) => (
            <button
              key={t.id}
              onClick={() => handleCreateFromTemplate(t.template_name)}
              style={{
                padding: '0.75rem', borderRadius: '0.5rem', border: '1px solid rgba(255,255,255,0.08)',
                backgroundColor: 'rgba(255,255,255,0.02)', cursor: 'pointer', textAlign: 'left',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.05)')}
              onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)')}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.375rem' }}>
                <Copy style={{ width: '0.875rem', height: '0.875rem', color: '#6366f1' }} />
                <span style={{ fontSize: '0.8125rem', fontWeight: 500, color: '#e2e8f0' }}>{t.name}</span>
              </div>
              <p style={{ fontSize: '0.75rem', color: '#64748b' }}>{t.description || 'No description'}</p>
            </button>
          ))}
        </div>
      )}

      {/* Policy table */}
      <div style={{
        backgroundColor: 'var(--color-surface-card)', border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '0.75rem', overflow: 'hidden',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
              {['Name', 'Status', 'Severity', 'Rules', 'Exceptions', 'Created', 'Actions'].map((h) => (
                <th key={h} style={{ padding: '0.75rem 1rem', textAlign: 'left', fontWeight: 500, color: '#64748b', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} style={{ padding: '3rem', textAlign: 'center', color: '#64748b' }}>Loading...</td></tr>
            ) : policies.length === 0 ? (
              <tr><td colSpan={7} style={{ padding: '3rem', textAlign: 'center', color: '#64748b' }}>No policies. Create one from a template.</td></tr>
            ) : policies.map((pol) => (
              <tr
                key={pol.id}
                style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}
              >
                <td
                  onClick={() => navigate(`/policies/${pol.id}`)}
                  style={{ padding: '0.625rem 1rem', color: '#e2e8f0', cursor: 'pointer' }}
                >
                  {pol.name}
                </td>
                <td style={{ padding: '0.625rem 1rem' }}><Badge label={pol.status} color={STATUS_COLORS[pol.status] || '#64748b'} /></td>
                <td style={{ padding: '0.625rem 1rem' }}><Badge label={pol.severity} color={SEVERITY_COLORS[pol.severity] || '#64748b'} /></td>
                <td style={{ padding: '0.625rem 1rem', color: '#94a3b8' }}>{pol.detection_rules.length}</td>
                <td style={{ padding: '0.625rem 1rem', color: '#94a3b8' }}>{pol.exceptions.length}</td>
                <td style={{ padding: '0.625rem 1rem', color: '#64748b' }}>{new Date(pol.created_at).toLocaleDateString()}</td>
                <td style={{ padding: '0.625rem 1rem' }}>
                  <div style={{ display: 'flex', gap: '0.375rem' }}>
                    {pol.status !== 'active' && (
                      <button onClick={() => handleActivate(pol.id)} title="Activate" style={{ ...btnStyle, color: '#22c55e' }}>
                        <Play style={{ width: '0.75rem', height: '0.75rem' }} />
                      </button>
                    )}
                    {pol.status === 'active' && (
                      <button onClick={() => handleSuspend(pol.id)} title="Suspend" style={{ ...btnStyle, color: '#f97316' }}>
                        <Pause style={{ width: '0.75rem', height: '0.75rem' }} />
                      </button>
                    )}
                    <button onClick={() => handleDelete(pol.id)} title="Delete" style={{ ...btnStyle, color: '#ef4444' }}>
                      <Trash2 style={{ width: '0.75rem', height: '0.75rem' }} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
