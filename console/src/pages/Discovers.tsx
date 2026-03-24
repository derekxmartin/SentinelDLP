/**
 * Discover scan management page (P7-T5).
 *
 * View, create, and trigger data-at-rest discover scans.
 * Shows scan status, results, and violation findings.
 */

import { useEffect, useState } from 'react';
import { HardDrive, Plus, Play, CheckCircle, XCircle, Clock, Loader2 } from 'lucide-react';
import useTitle from '../hooks/useTitle';
import api from '../api/client';

interface DiscoverScan {
  id: string;
  name: string;
  status: string;
  agent_id: string | null;
  scan_path: string;
  recursive: boolean;
  file_extensions: string[] | null;
  path_exclusions: string[] | null;
  started_at: string | null;
  completed_at: string | null;
  files_examined: number;
  files_scanned: number;
  violations_found: number;
  files_quarantined: number;
  duration_ms: number | null;
  findings: Array<Record<string, unknown>> | null;
  created_at: string;
  updated_at: string;
}

interface DiscoverListResponse {
  items: DiscoverScan[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

const cardStyle: React.CSSProperties = {
  backgroundColor: 'var(--color-surface-card)',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '0.75rem',
  padding: '1.5rem',
};

const STATUS_BADGE: Record<string, { bg: string; text: string; icon: typeof Clock }> = {
  pending:   { bg: 'rgba(156,163,175,0.15)', text: '#9ca3af', icon: Clock },
  running:   { bg: 'rgba(59,130,246,0.15)',  text: '#3b82f6', icon: Loader2 },
  completed: { bg: 'rgba(34,197,94,0.15)',   text: '#22c55e', icon: CheckCircle },
  failed:    { bg: 'rgba(239,68,68,0.15)',   text: '#ef4444', icon: XCircle },
  cancelled: { bg: 'rgba(156,163,175,0.15)', text: '#9ca3af', icon: XCircle },
};

export default function Discovers() {
  useTitle('Discover Scans');

  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<DiscoverListResponse | null>(null);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);

  // Create form
  const [newName, setNewName] = useState('');
  const [newPath, setNewPath] = useState('');
  const [newExtensions, setNewExtensions] = useState('.txt,.csv,.docx,.xlsx,.pdf');

  useEffect(() => {
    loadScans();
  }, [page, statusFilter]);

  async function loadScans() {
    setLoading(true);
    try {
      const params: Record<string, string> = { page: String(page), page_size: '25' };
      if (statusFilter) params.status = statusFilter;
      const resp = await api.get<DiscoverListResponse>('/discovers', params);
      setData(resp);
    } catch {
      // empty
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate() {
    if (!newName || !newPath) return;
    setCreating(true);
    try {
      const extensions = newExtensions
        .split(',')
        .map(e => e.trim())
        .filter(Boolean);
      await api.post('/discovers', {
        name: newName,
        scan_path: newPath,
        recursive: true,
        file_extensions: extensions.length ? extensions : null,
      });
      setShowCreate(false);
      setNewName('');
      setNewPath('');
      loadScans();
    } catch {
      // empty
    } finally {
      setCreating(false);
    }
  }

  async function handleTrigger(id: string) {
    try {
      await api.post(`/discovers/${id}/trigger`);
      loadScans();
    } catch {
      // empty
    }
  }

  function formatDate(iso: string | null) {
    if (!iso) return '—';
    return new Date(iso).toLocaleString();
  }

  function formatDuration(ms: number | null) {
    if (ms === null || ms === undefined) return '—';
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <HardDrive style={{ width: 28, height: 28, color: 'var(--color-accent)' }} />
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Discover Scans</h1>
          {data && (
            <span style={{ color: 'var(--color-text-muted)', fontSize: '0.875rem' }}>
              {data.total} scan{data.total !== 1 ? 's' : ''}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <select
            value={statusFilter}
            onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
            style={{
              backgroundColor: 'var(--color-surface-card)',
              color: 'var(--color-text)',
              border: '1px solid rgba(255,255,255,0.12)',
              borderRadius: '0.5rem',
              padding: '0.5rem 0.75rem',
              fontSize: '0.875rem',
            }}
          >
            <option value="">All Statuses</option>
            <option value="pending">Pending</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
          </select>
          <button
            onClick={() => setShowCreate(true)}
            style={{
              display: 'flex', alignItems: 'center', gap: '0.5rem',
              backgroundColor: 'var(--color-accent)',
              color: '#fff', border: 'none', borderRadius: '0.5rem',
              padding: '0.5rem 1rem', cursor: 'pointer', fontWeight: 600,
            }}
          >
            <Plus style={{ width: 16, height: 16 }} /> New Scan
          </button>
        </div>
      </div>

      {/* Create dialog */}
      {showCreate && (
        <div style={cardStyle}>
          <h3 style={{ margin: '0 0 1rem', fontWeight: 600 }}>Create Discover Scan</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <input
              placeholder="Scan name (e.g., Weekly PII Scan)"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              style={inputStyle}
            />
            <input
              placeholder="Scan path (e.g., C:\Users\Public\Documents)"
              value={newPath}
              onChange={(e) => setNewPath(e.target.value)}
              style={inputStyle}
            />
            <input
              placeholder="File extensions (comma-separated, e.g., .txt,.csv,.docx)"
              value={newExtensions}
              onChange={(e) => setNewExtensions(e.target.value)}
              style={inputStyle}
            />
            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
              <button onClick={() => setShowCreate(false)} style={cancelBtnStyle}>Cancel</button>
              <button onClick={handleCreate} disabled={creating || !newName || !newPath} style={primaryBtnStyle}>
                {creating ? 'Creating...' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Table */}
      <div style={{ ...cardStyle, padding: 0, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
              {['Name', 'Status', 'Scan Path', 'Files Scanned', 'Violations', 'Quarantined', 'Duration', 'Created'].map(h => (
                <th key={h} style={{
                  textAlign: 'left', padding: '0.75rem 1rem',
                  color: 'var(--color-text-muted)', fontWeight: 500, fontSize: '0.75rem',
                  textTransform: 'uppercase', letterSpacing: '0.05em',
                }}>{h}</th>
              ))}
              <th style={{ width: 60 }} />
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={9} style={{ padding: '2rem', textAlign: 'center', color: 'var(--color-text-muted)' }}>Loading...</td></tr>
            ) : !data?.items.length ? (
              <tr><td colSpan={9} style={{ padding: '2rem', textAlign: 'center', color: 'var(--color-text-muted)' }}>No discover scans found</td></tr>
            ) : data.items.map(scan => {
              const badge = STATUS_BADGE[scan.status] || STATUS_BADGE.pending;
              const Icon = badge.icon;
              return (
                <tr key={scan.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', cursor: 'default' }}>
                  <td style={cellStyle}><strong>{scan.name}</strong></td>
                  <td style={cellStyle}>
                    <span style={{
                      display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
                      padding: '0.25rem 0.625rem', borderRadius: '9999px',
                      backgroundColor: badge.bg, color: badge.text,
                      fontSize: '0.75rem', fontWeight: 600,
                    }}>
                      <Icon style={{ width: 12, height: 12 }} />
                      {scan.status}
                    </span>
                  </td>
                  <td style={{ ...cellStyle, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {scan.scan_path}
                  </td>
                  <td style={cellStyle}>{scan.files_scanned}</td>
                  <td style={cellStyle}>
                    <span style={{ color: scan.violations_found > 0 ? '#ef4444' : 'inherit', fontWeight: scan.violations_found > 0 ? 600 : 400 }}>
                      {scan.violations_found}
                    </span>
                  </td>
                  <td style={cellStyle}>{scan.files_quarantined}</td>
                  <td style={cellStyle}>{formatDuration(scan.duration_ms)}</td>
                  <td style={cellStyle}>{formatDate(scan.created_at)}</td>
                  <td style={cellStyle}>
                    {['pending', 'completed', 'failed', 'cancelled'].includes(scan.status) && (
                      <button
                        onClick={() => handleTrigger(scan.id)}
                        title="Trigger scan"
                        style={{
                          background: 'none', border: 'none', cursor: 'pointer',
                          color: 'var(--color-accent)', padding: '0.25rem',
                        }}
                      >
                        <Play style={{ width: 16, height: 16 }} />
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {data && data.pages > 1 && (
        <div style={{ display: 'flex', justifyContent: 'center', gap: '0.5rem' }}>
          <button disabled={page <= 1} onClick={() => setPage(p => p - 1)} style={pageBtnStyle}>Previous</button>
          <span style={{ color: 'var(--color-text-muted)', padding: '0.5rem', fontSize: '0.875rem' }}>
            Page {page} of {data.pages}
          </span>
          <button disabled={page >= data.pages} onClick={() => setPage(p => p + 1)} style={pageBtnStyle}>Next</button>
        </div>
      )}
    </div>
  );
}

const cellStyle: React.CSSProperties = {
  padding: '0.75rem 1rem',
  color: 'var(--color-text)',
};

const inputStyle: React.CSSProperties = {
  backgroundColor: 'rgba(0,0,0,0.2)',
  color: 'var(--color-text)',
  border: '1px solid rgba(255,255,255,0.12)',
  borderRadius: '0.5rem',
  padding: '0.625rem 0.75rem',
  fontSize: '0.875rem',
  width: '100%',
};

const primaryBtnStyle: React.CSSProperties = {
  backgroundColor: 'var(--color-accent)',
  color: '#fff',
  border: 'none',
  borderRadius: '0.5rem',
  padding: '0.5rem 1rem',
  cursor: 'pointer',
  fontWeight: 600,
};

const cancelBtnStyle: React.CSSProperties = {
  backgroundColor: 'transparent',
  color: 'var(--color-text-muted)',
  border: '1px solid rgba(255,255,255,0.12)',
  borderRadius: '0.5rem',
  padding: '0.5rem 1rem',
  cursor: 'pointer',
};

const pageBtnStyle: React.CSSProperties = {
  backgroundColor: 'var(--color-surface-card)',
  color: 'var(--color-text)',
  border: '1px solid rgba(255,255,255,0.12)',
  borderRadius: '0.5rem',
  padding: '0.5rem 1rem',
  cursor: 'pointer',
  fontSize: '0.875rem',
};
