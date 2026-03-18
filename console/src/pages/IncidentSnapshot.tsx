/**
 * Incident snapshot page (P2-T9).
 * Full detail view: status/severity dropdowns, matched content,
 * notes, history timeline.
 */

import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Send, Clock } from 'lucide-react';
import useTitle from '../hooks/useTitle';
import api from '../api/client';

interface Incident {
  id: string;
  policy_name: string;
  severity: string;
  status: string;
  channel: string;
  source_type: string;
  file_path: string | null;
  file_name: string | null;
  file_size: number | null;
  file_type: string | null;
  user: string | null;
  source_ip: string | null;
  destination: string | null;
  match_count: number;
  matched_content: Record<string, unknown> | null;
  data_identifiers: Record<string, unknown> | null;
  action_taken: string;
  user_justification: string | null;
  custom_attributes: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

interface Note {
  id: string;
  author_id: string | null;
  content: string;
  created_at: string;
}

interface HistoryEntry {
  id: string;
  actor_id: string | null;
  field: string;
  old_value: string | null;
  new_value: string | null;
  created_at: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#64748b',
};

const selectStyle: React.CSSProperties = {
  padding: '0.375rem 0.5rem', borderRadius: '0.375rem', fontSize: '0.8125rem',
  backgroundColor: 'var(--color-surface-page)', color: '#cbd5e1',
  border: '1px solid rgba(255,255,255,0.1)', outline: 'none',
};

const cardStyle: React.CSSProperties = {
  backgroundColor: 'var(--color-surface-card)', border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '0.75rem', padding: '1.25rem',
};

function DetailRow({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
      <span style={{ fontSize: '0.8125rem', color: '#64748b' }}>{label}</span>
      <span style={{ fontSize: '0.8125rem', color: '#e2e8f0' }}>{value || '—'}</span>
    </div>
  );
}

export default function IncidentSnapshot() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [incident, setIncident] = useState<Incident | null>(null);
  const [notes, setNotes] = useState<Note[]>([]);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [newNote, setNewNote] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useTitle(incident ? `Incident — ${incident.policy_name}` : 'Incident');

  useEffect(() => {
    if (!id) return;
    Promise.all([
      api.get<Incident>(`/incidents/${id}`),
      api.get<Note[]>(`/incidents/${id}/notes`),
      api.get<HistoryEntry[]>(`/incidents/${id}/history`),
    ])
      .then(([inc, n, h]) => { setIncident(inc); setNotes(n); setHistory(h); })
      .catch(() => navigate('/incidents'))
      .finally(() => setLoading(false));
  }, [id, navigate]);

  async function handleStatusChange(newStatus: string) {
    if (!id || !incident) return;
    const updated = await api.patch<Incident>(`/incidents/${id}`, { status: newStatus });
    setIncident(updated);
    const h = await api.get<HistoryEntry[]>(`/incidents/${id}/history`);
    setHistory(h);
  }

  async function handleSeverityChange(newSeverity: string) {
    if (!id || !incident) return;
    const updated = await api.patch<Incident>(`/incidents/${id}`, { severity: newSeverity });
    setIncident(updated);
    const h = await api.get<HistoryEntry[]>(`/incidents/${id}/history`);
    setHistory(h);
  }

  async function handleAddNote() {
    if (!id || !newNote.trim()) return;
    setSaving(true);
    try {
      await api.post(`/incidents/${id}/notes`, { content: newNote });
      const n = await api.get<Note[]>(`/incidents/${id}/notes`);
      setNotes(n);
      setNewNote('');
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return <div style={{ padding: '3rem', textAlign: 'center', color: '#64748b' }}>Loading...</div>;
  }

  if (!incident) return null;

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem' }}>
        <button
          onClick={() => navigate('/incidents')}
          style={{ padding: '0.375rem', borderRadius: '0.375rem', background: 'none', border: '1px solid rgba(255,255,255,0.1)', color: '#94a3b8', cursor: 'pointer' }}
        >
          <ArrowLeft style={{ width: '1rem', height: '1rem' }} />
        </button>
        <div>
          <h1 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'white' }}>{incident.policy_name}</h1>
          <p style={{ fontSize: '0.8125rem', color: '#64748b' }}>ID: {incident.id}</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem' }}>
        {/* Left column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Status controls */}
          <div style={{ ...cardStyle, display: 'flex', gap: '1rem', alignItems: 'center' }}>
            <div>
              <label style={{ fontSize: '0.75rem', color: '#64748b', display: 'block', marginBottom: '0.25rem' }}>Status</label>
              <select value={incident.status} onChange={(e) => handleStatusChange(e.target.value)} style={selectStyle}>
                <option value="new">New</option>
                <option value="in_progress">In Progress</option>
                <option value="resolved">Resolved</option>
                <option value="dismissed">Dismissed</option>
                <option value="escalated">Escalated</option>
              </select>
            </div>
            <div>
              <label style={{ fontSize: '0.75rem', color: '#64748b', display: 'block', marginBottom: '0.25rem' }}>Severity</label>
              <select value={incident.severity} onChange={(e) => handleSeverityChange(e.target.value)} style={selectStyle}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
            <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
              <span style={{ fontSize: '0.75rem', color: '#64748b' }}>Matches</span>
              <p style={{ fontSize: '1.25rem', fontWeight: 600, color: SEVERITY_COLORS[incident.severity] || '#64748b' }}>{incident.match_count}</p>
            </div>
          </div>

          {/* Matched content */}
          {incident.matched_content && (
            <div style={cardStyle}>
              <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0', marginBottom: '0.75rem' }}>Matched Content</h2>
              <pre style={{
                fontSize: '0.75rem', color: '#94a3b8', backgroundColor: 'var(--color-surface-page)',
                padding: '0.75rem', borderRadius: '0.5rem', overflow: 'auto', maxHeight: '12rem',
                whiteSpace: 'pre-wrap', wordBreak: 'break-all',
              }}>
                {JSON.stringify(incident.matched_content, null, 2)}
              </pre>
            </div>
          )}

          {/* Notes */}
          <div style={cardStyle}>
            <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0', marginBottom: '0.75rem' }}>Notes</h2>
            {notes.length === 0 ? (
              <p style={{ fontSize: '0.8125rem', color: '#64748b', marginBottom: '0.75rem' }}>No notes yet.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '0.75rem' }}>
                {notes.map((note) => (
                  <div key={note.id} style={{ padding: '0.5rem 0.75rem', borderRadius: '0.375rem', backgroundColor: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                    <p style={{ fontSize: '0.8125rem', color: '#e2e8f0' }}>{note.content}</p>
                    <p style={{ fontSize: '0.6875rem', color: '#475569', marginTop: '0.25rem' }}>
                      {new Date(note.created_at).toLocaleString()}
                    </p>
                  </div>
                ))}
              </div>
            )}
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <input
                type="text"
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleAddNote()}
                placeholder="Add a note..."
                style={{
                  flex: 1, padding: '0.375rem 0.75rem', borderRadius: '0.375rem',
                  backgroundColor: 'var(--color-surface-page)', border: '1px solid rgba(255,255,255,0.1)',
                  color: 'white', fontSize: '0.8125rem', outline: 'none',
                }}
              />
              <button
                onClick={handleAddNote}
                disabled={saving || !newNote.trim()}
                style={{
                  padding: '0.375rem 0.75rem', borderRadius: '0.375rem',
                  backgroundColor: '#6366f1', color: 'white', border: 'none',
                  cursor: saving ? 'not-allowed' : 'pointer', opacity: saving || !newNote.trim() ? 0.5 : 1,
                  display: 'flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.8125rem',
                }}
              >
                <Send style={{ width: '0.75rem', height: '0.75rem' }} /> Add
              </button>
            </div>
          </div>
        </div>

        {/* Right column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Details */}
          <div style={cardStyle}>
            <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0', marginBottom: '0.75rem' }}>Details</h2>
            <DetailRow label="Channel" value={incident.channel.replace('_', ' ')} />
            <DetailRow label="Source" value={incident.source_type} />
            <DetailRow label="File" value={incident.file_name} />
            <DetailRow label="File Path" value={incident.file_path} />
            <DetailRow label="File Size" value={incident.file_size ? `${(incident.file_size / 1024).toFixed(1)} KB` : null} />
            <DetailRow label="User" value={incident.user} />
            <DetailRow label="Source IP" value={incident.source_ip} />
            <DetailRow label="Destination" value={incident.destination} />
            <DetailRow label="Action" value={incident.action_taken} />
            <DetailRow label="Created" value={new Date(incident.created_at).toLocaleString()} />
          </div>

          {/* History */}
          <div style={cardStyle}>
            <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0', marginBottom: '0.75rem' }}>History</h2>
            {history.length === 0 ? (
              <p style={{ fontSize: '0.8125rem', color: '#64748b' }}>No changes yet.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {history.map((h) => (
                  <div key={h.id} style={{ display: 'flex', gap: '0.5rem', fontSize: '0.75rem' }}>
                    <Clock style={{ width: '0.75rem', height: '0.75rem', color: '#475569', marginTop: '0.125rem', flexShrink: 0 }} />
                    <div>
                      <p style={{ color: '#94a3b8' }}>
                        <span style={{ color: '#e2e8f0', textTransform: 'capitalize' }}>{h.field}</span> changed from{' '}
                        <span style={{ color: '#f87171' }}>{h.old_value || '—'}</span> to{' '}
                        <span style={{ color: '#4ade80' }}>{h.new_value || '—'}</span>
                      </p>
                      <p style={{ color: '#475569' }}>{new Date(h.created_at).toLocaleString()}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
