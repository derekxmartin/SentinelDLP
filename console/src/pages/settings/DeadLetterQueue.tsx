/**
 * Dead Letter Queue management page.
 *
 * Displays failed operations with retry/dismiss actions,
 * stats bar, and filtering by operation type.
 */

import { useEffect, useState, useCallback } from 'react';
import {
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  XCircle,
  RotateCcw,
  EyeOff,
  Filter,
  Inbox,
} from 'lucide-react';
import useTitle from '../../hooks/useTitle';
import api from '../../api/client';

/* ------------------------------------------------------------------ */
/*  Types                                                             */
/* ------------------------------------------------------------------ */

interface DlqItem {
  id: string;
  operation_type: string;
  source: string;
  error_message: string;
  error_type: string;
  retry_count: number;
  max_retries: number;
  is_permanent: boolean;
  is_dismissed: boolean;
  created_at: string;
  last_retry_at: string | null;
}

interface DlqListResponse {
  items: DlqItem[];
  total: number;
  page: number;
  page_size: number;
}

interface DlqStats {
  total: number;
  pending_retry: number;
  permanent_failure: number;
}

/* ------------------------------------------------------------------ */
/*  Shared styles                                                     */
/* ------------------------------------------------------------------ */

const cardStyle: React.CSSProperties = {
  backgroundColor: 'var(--color-surface-card)',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '0.75rem',
  padding: '1.5rem',
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

const selectStyle: React.CSSProperties = {
  backgroundColor: '#1e293b',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: '0.5rem',
  padding: '0.5rem 0.75rem',
  color: 'var(--color-text-primary)',
  fontSize: '0.875rem',
  outline: 'none',
  cursor: 'pointer',
};

const btnIcon: React.CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  gap: '0.375rem',
  padding: '0.375rem 0.75rem',
  borderRadius: '0.375rem',
  fontSize: '0.75rem',
  fontWeight: 500,
  border: 'none',
  cursor: 'pointer',
};

/* ------------------------------------------------------------------ */
/*  Status badge                                                      */
/* ------------------------------------------------------------------ */

function getStatus(item: DlqItem): 'pending' | 'permanent' | 'dismissed' {
  if (item.is_dismissed) return 'dismissed';
  if (item.is_permanent) return 'permanent';
  return 'pending';
}

const STATUS_COLORS: Record<string, { bg: string; text: string }> = {
  pending:   { bg: 'rgba(234,179,8,0.15)',  text: '#eab308' },
  permanent: { bg: 'rgba(239,68,68,0.15)',  text: '#ef4444' },
  dismissed: { bg: 'rgba(100,116,139,0.15)', text: '#64748b' },
};

function StatusBadge({ status }: { status: 'pending' | 'permanent' | 'dismissed' }) {
  const cfg = STATUS_COLORS[status];
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '0.125rem 0.5rem',
        borderRadius: '9999px',
        fontSize: '0.75rem',
        fontWeight: 500,
        backgroundColor: cfg.bg,
        color: cfg.text,
        textTransform: 'capitalize',
      }}
    >
      {status === 'permanent' ? 'Permanent' : status === 'dismissed' ? 'Dismissed' : 'Pending'}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  Stats card                                                        */
/* ------------------------------------------------------------------ */

function StatBox({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div
      style={{
        flex: 1,
        padding: '1rem 1.25rem',
        backgroundColor: 'var(--color-surface-card)',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '0.75rem',
      }}
    >
      <div style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.25rem' }}>
        {label}
      </div>
      <div style={{ fontSize: '1.5rem', fontWeight: 700, color }}>{value}</div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Component                                                         */
/* ------------------------------------------------------------------ */

export default function DeadLetterQueue() {
  useTitle('Dead Letter Queue');

  const [items, setItems] = useState<DlqItem[]>([]);
  const [stats, setStats] = useState<DlqStats>({ total: 0, pending_retry: 0, permanent_failure: 0 });
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [filterType, setFilterType] = useState<string>('');
  const [operationTypes, setOperationTypes] = useState<string[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [actionInFlight, setActionInFlight] = useState<string | null>(null);

  const pageSize = 25;

  useEffect(() => {
    if (toast) {
      const t = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(t);
    }
  }, [toast]);

  const loadStats = useCallback(async () => {
    try {
      const data = await api.get<DlqStats>('/dlq/stats');
      setStats(data);
    } catch {
      // non-critical
    }
  }, []);

  const loadItems = useCallback(async () => {
    try {
      const params: Record<string, string> = {
        page: String(page),
        page_size: String(pageSize),
      };
      if (filterType) params.operation_type = filterType;

      const data = await api.get<DlqListResponse>('/dlq', params);
      setItems(data.items);
      setTotal(data.total);

      // Derive unique operation types for filter dropdown
      const types = Array.from(new Set(data.items.map((i) => i.operation_type)));
      setOperationTypes((prev) => {
        const merged = Array.from(new Set([...prev, ...types]));
        merged.sort();
        return merged;
      });
    } catch {
      setToast({ type: 'error', message: 'Failed to load dead letter queue.' });
    } finally {
      setLoading(false);
    }
  }, [page, filterType]);

  useEffect(() => {
    setLoading(true);
    loadItems();
    loadStats();
  }, [loadItems, loadStats]);

  /* ---------- Actions ---------- */

  async function handleRetry(item: DlqItem) {
    setActionInFlight(item.id);
    try {
      await api.post(`/dlq/${item.id}/retry`);
      setToast({ type: 'success', message: `Retried "${item.operation_type}" from ${item.source}.` });
      await Promise.all([loadItems(), loadStats()]);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Retry failed';
      setToast({ type: 'error', message });
    } finally {
      setActionInFlight(null);
    }
  }

  async function handleDismiss(item: DlqItem) {
    setActionInFlight(item.id);
    try {
      await api.post(`/dlq/${item.id}/dismiss`);
      setToast({ type: 'success', message: `Dismissed "${item.operation_type}" from ${item.source}.` });
      await Promise.all([loadItems(), loadStats()]);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Dismiss failed';
      setToast({ type: 'error', message });
    } finally {
      setActionInFlight(null);
    }
  }

  function formatDate(iso: string): string {
    return new Date(iso).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  }

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  /* ---------- Render ---------- */

  if (loading && items.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '50vh' }}>
        <RefreshCw className="w-6 h-6 text-slate-400 animate-spin" />
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '76rem', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
            Dead Letter Queue
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginTop: '0.25rem' }}>
            Operations that failed and may be retried or dismissed.
          </p>
        </div>
        <button
          onClick={() => { setLoading(true); loadItems(); loadStats(); }}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 1.25rem',
            borderRadius: '0.5rem',
            backgroundColor: 'transparent',
            color: 'var(--color-text-secondary)',
            fontWeight: 500,
            fontSize: '0.875rem',
            border: '1px solid rgba(255,255,255,0.1)',
            cursor: 'pointer',
          }}
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
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
            <CheckCircle className="w-4 h-4" style={{ color: '#22c55e', flexShrink: 0 }} />
          ) : (
            <AlertTriangle className="w-4 h-4" style={{ color: '#ef4444', flexShrink: 0 }} />
          )}
          <span style={{ fontSize: '0.875rem', color: 'var(--color-text-primary)' }}>{toast.message}</span>
        </div>
      )}

      {/* Stats bar */}
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem' }}>
        <StatBox label="Total Entries" value={stats.total} color="var(--color-text-primary)" />
        <StatBox label="Pending Retry" value={stats.pending_retry} color="#eab308" />
        <StatBox label="Permanent Failure" value={stats.permanent_failure} color="#ef4444" />
      </div>

      {/* Filter */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
        <Filter className="w-4 h-4" style={{ color: '#64748b' }} />
        <select
          value={filterType}
          onChange={(e) => { setFilterType(e.target.value); setPage(1); }}
          style={selectStyle}
        >
          <option value="" style={{ backgroundColor: '#1e293b' }}>All Operation Types</option>
          {operationTypes.map((t) => (
            <option key={t} value={t} style={{ backgroundColor: '#1e293b' }}>
              {t}
            </option>
          ))}
        </select>
        {filterType && (
          <button
            onClick={() => { setFilterType(''); setPage(1); }}
            style={{
              background: 'none',
              border: 'none',
              color: '#64748b',
              cursor: 'pointer',
              fontSize: '0.75rem',
              textDecoration: 'underline',
            }}
          >
            Clear filter
          </button>
        )}
      </div>

      {/* Table */}
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
              backgroundColor: 'rgba(239,68,68,0.15)',
            }}
          >
            <Inbox className="w-4 h-4" style={{ color: '#ef4444' }} />
          </div>
          <div>
            <h2 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
              Queue Entries
            </h2>
            <p style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
              {total} entr{total !== 1 ? 'ies' : 'y'}{filterType ? ` matching "${filterType}"` : ''}
            </p>
          </div>
        </div>

        {items.length === 0 ? (
          <div
            style={{
              textAlign: 'center',
              padding: '2rem',
              color: 'var(--color-text-secondary)',
              fontSize: '0.875rem',
            }}
          >
            No entries in the dead letter queue.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={thStyle}>Operation Type</th>
                  <th style={thStyle}>Source</th>
                  <th style={thStyle}>Error</th>
                  <th style={thStyle}>Retries</th>
                  <th style={thStyle}>Status</th>
                  <th style={thStyle}>Created</th>
                  <th style={{ ...thStyle, textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => {
                  const status = getStatus(item);
                  const isActioning = actionInFlight === item.id;
                  return (
                    <tr
                      key={item.id}
                      style={{ transition: 'background-color 0.15s' }}
                      onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)')}
                      onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                    >
                      <td style={{ ...tdStyle, fontWeight: 600, whiteSpace: 'nowrap' }}>
                        {item.operation_type}
                      </td>
                      <td style={{ ...tdStyle, color: 'var(--color-text-secondary)', maxWidth: '10rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {item.source}
                      </td>
                      <td style={{ ...tdStyle, color: '#f87171', maxWidth: '16rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={item.error_message}>
                        {item.error_message}
                      </td>
                      <td style={tdStyle}>
                        <span style={{ fontVariantNumeric: 'tabular-nums' }}>
                          {item.retry_count}/{item.max_retries}
                        </span>
                      </td>
                      <td style={tdStyle}>
                        <StatusBadge status={status} />
                      </td>
                      <td style={{ ...tdStyle, color: 'var(--color-text-secondary)', whiteSpace: 'nowrap' }}>
                        {formatDate(item.created_at)}
                      </td>
                      <td style={{ ...tdStyle, textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                          <button
                            onClick={() => handleRetry(item)}
                            disabled={item.is_permanent || item.is_dismissed || isActioning}
                            title={item.is_permanent ? 'Cannot retry permanent failures' : 'Retry this operation'}
                            style={{
                              ...btnIcon,
                              backgroundColor: item.is_permanent || item.is_dismissed
                                ? 'rgba(255,255,255,0.03)'
                                : 'rgba(59,130,246,0.15)',
                              color: item.is_permanent || item.is_dismissed
                                ? 'rgba(100,116,139,0.5)'
                                : '#3b82f6',
                              cursor: item.is_permanent || item.is_dismissed || isActioning
                                ? 'not-allowed'
                                : 'pointer',
                              opacity: isActioning ? 0.6 : 1,
                            }}
                          >
                            <RotateCcw style={{ width: '0.75rem', height: '0.75rem' }} />
                            Retry
                          </button>
                          <button
                            onClick={() => handleDismiss(item)}
                            disabled={item.is_dismissed || isActioning}
                            title={item.is_dismissed ? 'Already dismissed' : 'Dismiss this entry'}
                            style={{
                              ...btnIcon,
                              backgroundColor: item.is_dismissed
                                ? 'rgba(255,255,255,0.03)'
                                : 'rgba(100,116,139,0.15)',
                              color: item.is_dismissed
                                ? 'rgba(100,116,139,0.5)'
                                : '#94a3b8',
                              cursor: item.is_dismissed || isActioning
                                ? 'not-allowed'
                                : 'pointer',
                              opacity: isActioning ? 0.6 : 1,
                            }}
                          >
                            <EyeOff style={{ width: '0.75rem', height: '0.75rem' }} />
                            Dismiss
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              paddingTop: '1rem',
              borderTop: '1px solid rgba(255,255,255,0.06)',
              marginTop: '0.5rem',
            }}
          >
            <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
              Page {page} of {totalPages}
            </span>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                style={{
                  padding: '0.375rem 0.75rem',
                  borderRadius: '0.375rem',
                  backgroundColor: 'transparent',
                  border: '1px solid rgba(255,255,255,0.1)',
                  color: page <= 1 ? 'rgba(100,116,139,0.5)' : 'var(--color-text-secondary)',
                  fontSize: '0.75rem',
                  cursor: page <= 1 ? 'not-allowed' : 'pointer',
                }}
              >
                Previous
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                style={{
                  padding: '0.375rem 0.75rem',
                  borderRadius: '0.375rem',
                  backgroundColor: 'transparent',
                  border: '1px solid rgba(255,255,255,0.1)',
                  color: page >= totalPages ? 'rgba(100,116,139,0.5)' : 'var(--color-text-secondary)',
                  fontSize: '0.75rem',
                  cursor: page >= totalPages ? 'not-allowed' : 'pointer',
                }}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
