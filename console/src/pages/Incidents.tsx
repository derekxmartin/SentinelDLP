/**
 * Incidents list page (P2-T9).
 * Filterable table with severity, status, policy, channel.
 * Sortable, paginated. Click row → snapshot.
 */

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronLeft, ChevronRight, Filter } from 'lucide-react';
import useTitle from '../hooks/useTitle';
import api from '../api/client';

interface Incident {
  id: string;
  policy_name: string;
  severity: string;
  status: string;
  channel: string;
  source_type: string;
  file_name: string | null;
  user: string | null;
  source_ip: string | null;
  match_count: number;
  action_taken: string;
  created_at: string;
}

interface IncidentList {
  items: Incident[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#64748b',
};

const STATUS_COLORS: Record<string, string> = {
  new: '#3b82f6', in_progress: '#eab308', resolved: '#22c55e', dismissed: '#64748b', escalated: '#ef4444',
};

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      display: 'inline-block', padding: '0.125rem 0.5rem', borderRadius: '9999px',
      fontSize: '0.75rem', fontWeight: 500, backgroundColor: `${color}1a`, color,
      textTransform: 'capitalize', whiteSpace: 'nowrap',
    }}>
      {label.replace('_', ' ')}
    </span>
  );
}

const selectStyle: React.CSSProperties = {
  padding: '0.375rem 0.5rem', borderRadius: '0.375rem', fontSize: '0.8125rem',
  backgroundColor: 'var(--color-surface-card)', color: '#cbd5e1',
  border: '1px solid rgba(255,255,255,0.1)', outline: 'none',
};

export default function Incidents() {
  useTitle('Incidents');
  const navigate = useNavigate();

  const [data, setData] = useState<IncidentList | null>(null);
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [channel, setChannel] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    const params: Record<string, string> = { page: String(page), page_size: '15' };
    if (severity) params.severity = severity;
    if (status) params.status = status;
    if (channel) params.channel = channel;

    api.get<IncidentList>('/incidents', params)
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [page, severity, status, channel]);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'white' }}>Incidents</h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Filter style={{ width: '0.875rem', height: '0.875rem', color: '#64748b' }} />
          <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} style={selectStyle}>
            <option value="">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} style={selectStyle}>
            <option value="">All Status</option>
            <option value="new">New</option>
            <option value="in_progress">In Progress</option>
            <option value="resolved">Resolved</option>
            <option value="dismissed">Dismissed</option>
            <option value="escalated">Escalated</option>
          </select>
          <select value={channel} onChange={(e) => { setChannel(e.target.value); setPage(1); }} style={selectStyle}>
            <option value="">All Channels</option>
            <option value="usb">USB</option>
            <option value="email">Email</option>
            <option value="network_share">Network Share</option>
            <option value="clipboard">Clipboard</option>
            <option value="browser_upload">Browser Upload</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div style={{
        backgroundColor: 'var(--color-surface-card)', border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '0.75rem', overflow: 'hidden',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
              {['Policy', 'Severity', 'Status', 'Channel', 'User', 'Matches', 'Action', 'Date'].map((h) => (
                <th key={h} style={{ padding: '0.75rem 1rem', textAlign: 'left', fontWeight: 500, color: '#64748b', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={8} style={{ padding: '3rem', textAlign: 'center', color: '#64748b' }}>Loading...</td></tr>
            ) : !data || data.items.length === 0 ? (
              <tr><td colSpan={8} style={{ padding: '3rem', textAlign: 'center', color: '#64748b' }}>No incidents found.</td></tr>
            ) : data.items.map((inc) => (
              <tr
                key={inc.id}
                onClick={() => navigate(`/incidents/${inc.id}`)}
                style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', cursor: 'pointer' }}
                onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)')}
                onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
              >
                <td style={{ padding: '0.625rem 1rem', color: '#e2e8f0', maxWidth: '14rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inc.policy_name}</td>
                <td style={{ padding: '0.625rem 1rem' }}><Badge label={inc.severity} color={SEVERITY_COLORS[inc.severity] || '#64748b'} /></td>
                <td style={{ padding: '0.625rem 1rem' }}><Badge label={inc.status} color={STATUS_COLORS[inc.status] || '#64748b'} /></td>
                <td style={{ padding: '0.625rem 1rem', color: '#94a3b8', textTransform: 'capitalize' }}>{inc.channel.replace('_', ' ')}</td>
                <td style={{ padding: '0.625rem 1rem', color: '#94a3b8' }}>{inc.user || '—'}</td>
                <td style={{ padding: '0.625rem 1rem', color: '#94a3b8' }}>{inc.match_count}</td>
                <td style={{ padding: '0.625rem 1rem', color: '#94a3b8', textTransform: 'capitalize' }}>{inc.action_taken}</td>
                <td style={{ padding: '0.625rem 1rem', color: '#64748b', whiteSpace: 'nowrap' }}>{new Date(inc.created_at).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Pagination */}
        {data && data.pages > 1 && (
          <div style={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            padding: '0.75rem 1rem', borderTop: '1px solid rgba(255,255,255,0.08)',
          }}>
            <span style={{ fontSize: '0.8125rem', color: '#64748b' }}>
              Showing {(page - 1) * 15 + 1}–{Math.min(page * 15, data.total)} of {data.total}
            </span>
            <div style={{ display: 'flex', gap: '0.25rem' }}>
              <button
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
                style={{ padding: '0.375rem', borderRadius: '0.375rem', background: 'none', border: '1px solid rgba(255,255,255,0.1)', color: page <= 1 ? '#334155' : '#94a3b8', cursor: page <= 1 ? 'not-allowed' : 'pointer' }}
              >
                <ChevronLeft style={{ width: '1rem', height: '1rem' }} />
              </button>
              <button
                disabled={page >= data.pages}
                onClick={() => setPage(page + 1)}
                style={{ padding: '0.375rem', borderRadius: '0.375rem', background: 'none', border: '1px solid rgba(255,255,255,0.1)', color: page >= data.pages ? '#334155' : '#94a3b8', cursor: page >= data.pages ? 'not-allowed' : 'pointer' }}
              >
                <ChevronRight style={{ width: '1rem', height: '1rem' }} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
