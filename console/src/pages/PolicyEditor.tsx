/**
 * Policy editor/detail page (P2-T10).
 * Metadata, rules with conditions, exceptions, activate/suspend.
 */

import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Plus, Trash2, Play, Pause } from 'lucide-react';
import useTitle from '../hooks/useTitle';
import api from '../api/client';

interface Condition {
  id: string;
  condition_type: string;
  component: string;
  config: Record<string, unknown>;
  match_count_min: number;
}

interface Rule {
  id: string;
  name: string;
  description: string | null;
  rule_type: string;
  conditions: Condition[];
}

interface Exception {
  id: string;
  name: string;
  description: string | null;
  scope: string;
  exception_type: string;
  conditions: Condition[];
}

interface Policy {
  id: string;
  name: string;
  description: string | null;
  status: string;
  severity: string;
  is_template: boolean;
  ttd_fallback: string;
  severity_thresholds: { threshold: number; severity: string }[] | null;
  detection_rules: Rule[];
  exceptions: Exception[];
  created_at: string;
  updated_at: string;
}

const STATUS_COLORS: Record<string, string> = {
  active: '#22c55e', suspended: '#f97316', draft: '#64748b',
};

const cardStyle: React.CSSProperties = {
  backgroundColor: 'var(--color-surface-card)', border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '0.75rem', padding: '1.25rem',
};

const btnSmall: React.CSSProperties = {
  padding: '0.375rem 0.625rem', borderRadius: '0.375rem', fontSize: '0.75rem',
  border: 'none', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
};

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      display: 'inline-block', padding: '0.25rem 0.625rem', borderRadius: '9999px',
      fontSize: '0.75rem', fontWeight: 600, backgroundColor: `${color}1a`, color,
      textTransform: 'capitalize',
    }}>
      {label}
    </span>
  );
}

export default function PolicyEditor() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [policy, setPolicy] = useState<Policy | null>(null);
  const [loading, setLoading] = useState(true);

  useTitle(policy ? `Policy — ${policy.name}` : 'Policy');

  function loadPolicy() {
    if (!id) return;
    api.get<Policy>(`/policies/${id}`)
      .then(setPolicy)
      .catch(() => navigate('/policies'))
      .finally(() => setLoading(false));
  }

  useEffect(() => { loadPolicy(); }, [id]);

  async function handleActivate() {
    if (!id) return;
    const updated = await api.post<Policy>(`/policies/${id}/activate`);
    setPolicy(updated);
  }

  async function handleSuspend() {
    if (!id) return;
    const updated = await api.post<Policy>(`/policies/${id}/suspend`);
    setPolicy(updated);
  }

  async function handleDeleteRule(ruleId: string) {
    if (!id) return;
    await api.delete(`/policies/${id}/rules/${ruleId}`);
    loadPolicy();
  }

  async function handleDeleteException(excId: string) {
    if (!id) return;
    await api.delete(`/policies/${id}/exceptions/${excId}`);
    loadPolicy();
  }

  async function handleAddRule() {
    if (!id) return;
    const name = prompt('Rule name:');
    if (!name) return;
    await api.post(`/policies/${id}/rules`, {
      name,
      rule_type: 'detection',
      conditions: [],
    });
    loadPolicy();
  }

  async function handleAddException() {
    if (!id) return;
    const name = prompt('Exception name:');
    if (!name) return;
    await api.post(`/policies/${id}/exceptions`, {
      name,
      scope: 'entire_message',
      exception_type: 'detection',
      conditions: [],
    });
    loadPolicy();
  }

  if (loading) {
    return <div style={{ padding: '3rem', textAlign: 'center', color: '#64748b' }}>Loading...</div>;
  }

  if (!policy) return null;

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem' }}>
        <button
          onClick={() => navigate('/policies')}
          style={{ padding: '0.375rem', borderRadius: '0.375rem', background: 'none', border: '1px solid rgba(255,255,255,0.1)', color: '#94a3b8', cursor: 'pointer' }}
        >
          <ArrowLeft style={{ width: '1rem', height: '1rem' }} />
        </button>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <h1 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'white' }}>{policy.name}</h1>
            <Badge label={policy.status} color={STATUS_COLORS[policy.status] || '#64748b'} />
          </div>
          <p style={{ fontSize: '0.8125rem', color: '#64748b' }}>{policy.description || 'No description'}</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {policy.status !== 'active' ? (
            <button onClick={handleActivate} style={{ ...btnSmall, backgroundColor: '#22c55e', color: 'white' }}>
              <Play style={{ width: '0.75rem', height: '0.75rem' }} /> Activate
            </button>
          ) : (
            <button onClick={handleSuspend} style={{ ...btnSmall, backgroundColor: '#f97316', color: 'white' }}>
              <Pause style={{ width: '0.75rem', height: '0.75rem' }} /> Suspend
            </button>
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem' }}>
        {/* Left column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Detection Rules */}
          <div style={cardStyle}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
              <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0' }}>
                Detection Rules ({policy.detection_rules.length})
              </h2>
              <button onClick={handleAddRule} style={{ ...btnSmall, backgroundColor: 'rgba(99,102,241,0.15)', color: '#6366f1' }}>
                <Plus style={{ width: '0.75rem', height: '0.75rem' }} /> Add Rule
              </button>
            </div>

            {policy.detection_rules.length === 0 ? (
              <p style={{ fontSize: '0.8125rem', color: '#64748b' }}>No detection rules.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {policy.detection_rules.map((rule) => (
                  <div key={rule.id} style={{
                    padding: '0.75rem', borderRadius: '0.5rem', border: '1px solid rgba(255,255,255,0.06)',
                    backgroundColor: 'rgba(255,255,255,0.02)',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <p style={{ fontSize: '0.8125rem', fontWeight: 500, color: '#e2e8f0' }}>{rule.name}</p>
                        <p style={{ fontSize: '0.75rem', color: '#64748b' }}>
                          Type: {rule.rule_type} &middot; {rule.conditions.length} condition(s)
                        </p>
                      </div>
                      <button onClick={() => handleDeleteRule(rule.id)} style={{ ...btnSmall, color: '#ef4444', background: 'none', border: 'none', padding: '0.25rem' }}>
                        <Trash2 style={{ width: '0.75rem', height: '0.75rem' }} />
                      </button>
                    </div>
                    {rule.conditions.length > 0 && (
                      <div style={{ marginTop: '0.5rem', paddingTop: '0.5rem', borderTop: '1px solid rgba(255,255,255,0.04)' }}>
                        {rule.conditions.map((c) => (
                          <div key={c.id} style={{ display: 'flex', gap: '0.5rem', fontSize: '0.75rem', color: '#94a3b8', padding: '0.125rem 0' }}>
                            <span style={{ color: '#6366f1', textTransform: 'capitalize' }}>{c.condition_type.replace('_', ' ')}</span>
                            <span>&middot;</span>
                            <span>Component: {c.component}</span>
                            <span>&middot;</span>
                            <span>Min matches: {c.match_count_min}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Exceptions */}
          <div style={cardStyle}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
              <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0' }}>
                Exceptions ({policy.exceptions.length})
              </h2>
              <button onClick={handleAddException} style={{ ...btnSmall, backgroundColor: 'rgba(99,102,241,0.15)', color: '#6366f1' }}>
                <Plus style={{ width: '0.75rem', height: '0.75rem' }} /> Add Exception
              </button>
            </div>

            {policy.exceptions.length === 0 ? (
              <p style={{ fontSize: '0.8125rem', color: '#64748b' }}>No exceptions.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {policy.exceptions.map((exc) => (
                  <div key={exc.id} style={{
                    padding: '0.75rem', borderRadius: '0.5rem', border: '1px solid rgba(255,255,255,0.06)',
                    backgroundColor: 'rgba(255,255,255,0.02)',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <p style={{ fontSize: '0.8125rem', fontWeight: 500, color: '#e2e8f0' }}>{exc.name}</p>
                        <p style={{ fontSize: '0.75rem', color: '#64748b' }}>
                          Scope: {exc.scope.replace('_', ' ')} &middot; {exc.conditions.length} condition(s)
                        </p>
                      </div>
                      <button onClick={() => handleDeleteException(exc.id)} style={{ ...btnSmall, color: '#ef4444', background: 'none', border: 'none', padding: '0.25rem' }}>
                        <Trash2 style={{ width: '0.75rem', height: '0.75rem' }} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right column — metadata */}
        <div style={cardStyle}>
          <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0', marginBottom: '0.75rem' }}>Metadata</h2>
          {[
            ['Severity', policy.severity],
            ['TTD Fallback', policy.ttd_fallback],
            ['Created', new Date(policy.created_at).toLocaleString()],
            ['Updated', new Date(policy.updated_at).toLocaleString()],
            ['ID', policy.id],
          ].map(([label, value]) => (
            <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              <span style={{ fontSize: '0.8125rem', color: '#64748b' }}>{label}</span>
              <span style={{ fontSize: '0.8125rem', color: '#e2e8f0', textTransform: 'capitalize' }}>{value}</span>
            </div>
          ))}

          {policy.severity_thresholds && policy.severity_thresholds.length > 0 && (
            <>
              <h3 style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#e2e8f0', marginTop: '1rem', marginBottom: '0.5rem' }}>Severity Thresholds</h3>
              {policy.severity_thresholds.map((t, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.25rem 0', fontSize: '0.75rem' }}>
                  <span style={{ color: '#94a3b8' }}>{t.threshold}+ matches</span>
                  <span style={{ color: '#e2e8f0', textTransform: 'capitalize' }}>{t.severity}</span>
                </div>
              ))}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
