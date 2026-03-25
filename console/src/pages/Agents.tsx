/**
 * Agent management page (P9-T1).
 *
 * Displays registered agents with status, version info, and group
 * assignment. Supports search, status filtering, and navigation
 * to agent detail view.
 */

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Monitor, Wifi, WifiOff, AlertTriangle, Clock, Search, ChevronLeft, ChevronRight } from 'lucide-react';
import useTitle from '../hooks/useTitle';
import api from '../api/client';

interface AgentGroup {
  id: string;
  name: string;
  description: string | null;
}

interface Agent {
  id: string;
  hostname: string;
  os_version: string | null;
  agent_version: string | null;
  driver_version: string | null;
  policy_version: number;
  ip_address: string | null;
  status: string;
  last_heartbeat: string | null;
  group: AgentGroup | null;
  capabilities: Record<string, boolean> | null;
  created_at: string;
  updated_at: string;
}

interface AgentListResponse {
  items: Agent[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

interface AgentStats {
  total: number;
  online: number;
  offline: number;
  stale: number;
  error: number;
}

const STATUS_CONFIG: Record<string, { bg: string; text: string; icon: typeof Wifi; label: string }> = {
  online:  { bg: 'rgba(34,197,94,0.15)',  text: '#22c55e', icon: Wifi,           label: 'Online' },
  offline: { bg: 'rgba(107,114,128,0.15)', text: '#6b7280', icon: WifiOff,       label: 'Offline' },
  stale:   { bg: 'rgba(234,179,8,0.15)',   text: '#eab308', icon: Clock,          label: 'Stale' },
  error:   { bg: 'rgba(239,68,68,0.15)',   text: '#ef4444', icon: AlertTriangle,  label: 'Error' },
};

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.offline;
  const Icon = cfg.icon;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
      padding: '0.25rem 0.625rem', borderRadius: '9999px',
      backgroundColor: cfg.bg, color: cfg.text,
      fontSize: '0.75rem', fontWeight: 500,
    }}>
      <Icon style={{ width: '0.75rem', height: '0.75rem' }} />
      {cfg.label}
    </span>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{
      backgroundColor: 'var(--color-surface-card)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: '0.75rem',
      padding: '1.25rem',
      flex: 1,
      minWidth: '120px',
    }}>
      <div style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '0.25rem' }}>{label}</div>
      <div style={{ fontSize: '1.5rem', fontWeight: 700, color }}>{value}</div>
    </div>
  );
}

export default function Agents() {
  useTitle('Agents');
  const navigate = useNavigate();

  const [agents, setAgents] = useState<Agent[]>([]);
  const [stats, setStats] = useState<AgentStats | null>(null);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  async function fetchAgents() {
    setLoading(true);
    setError('');
    try {
      const params = new URLSearchParams({ page: String(page), page_size: '25' });
      if (search) params.set('search', search);
      if (statusFilter) params.set('status', statusFilter);
      const data: AgentListResponse = await api.get(`/agents?${params}`);
      setAgents(data.items);
      setPages(data.pages);
      setTotal(data.total);
    } catch {
      setError('Failed to load agents.');
    } finally {
      setLoading(false);
    }
  }

  async function fetchStats() {
    try {
      const data: AgentStats = await api.get('/agents/stats');
      setStats(data);
    } catch {
      // Non-critical
    }
  }

  useEffect(() => { fetchAgents(); }, [page, statusFilter]);
  useEffect(() => { fetchStats(); }, []);

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setPage(1);
    fetchAgents();
  }

  function timeAgo(iso: string | null): string {
    if (!iso) return 'Never';
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'Just now';
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
  }

  return (
    <div style={{ maxWidth: '1200px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Monitor style={{ width: '1.5rem', height: '1.5rem', color: 'var(--color-accent)' }} />
          <h1 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'white' }}>Agents</h1>
          <span style={{ fontSize: '0.875rem', color: '#64748b' }}>({total})</span>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
          <StatCard label="Total" value={stats.total} color="white" />
          <StatCard label="Online" value={stats.online} color="#22c55e" />
          <StatCard label="Offline" value={stats.offline} color="#6b7280" />
          <StatCard label="Stale" value={stats.stale} color="#eab308" />
          <StatCard label="Error" value={stats.error} color="#ef4444" />
        </div>
      )}

      {/* Filters */}
      <div style={{
        display: 'flex', gap: '0.75rem', marginBottom: '1rem',
        alignItems: 'center', flexWrap: 'wrap',
      }}>
        <form onSubmit={handleSearch} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: '0.5rem',
            backgroundColor: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: '0.5rem', padding: '0.375rem 0.75rem',
          }}>
            <Search style={{ width: '0.875rem', height: '0.875rem', color: '#64748b' }} />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search hostname..."
              style={{
                background: 'transparent', border: 'none', outline: 'none',
                color: 'white', fontSize: '0.875rem', width: '180px',
              }}
            />
          </div>
        </form>
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
          style={{
            backgroundColor: '#1e293b', border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: '0.5rem', padding: '0.5rem 0.75rem',
            color: 'white', fontSize: '0.875rem', appearance: 'none',
            backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%2394a3b8' d='M3 5l3 3 3-3'/%3E%3C/svg%3E")`,
            backgroundRepeat: 'no-repeat', backgroundPosition: 'right 0.75rem center',
            paddingRight: '2rem', cursor: 'pointer',
          }}
        >
          <option value="" style={{ backgroundColor: '#1e293b', color: '#94a3b8' }}>All statuses</option>
          <option value="online" style={{ backgroundColor: '#1e293b', color: 'white' }}>Online</option>
          <option value="offline" style={{ backgroundColor: '#1e293b', color: 'white' }}>Offline</option>
          <option value="stale" style={{ backgroundColor: '#1e293b', color: 'white' }}>Stale</option>
          <option value="error" style={{ backgroundColor: '#1e293b', color: 'white' }}>Error</option>
        </select>
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
              {['Hostname', 'Status', 'IP Address', 'Agent Version', 'Driver', 'Policy Ver.', 'Group', 'Last Heartbeat'].map(h => (
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
              <tr><td colSpan={8} style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>Loading...</td></tr>
            ) : agents.length === 0 ? (
              <tr><td colSpan={8} style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>No agents found</td></tr>
            ) : agents.map((agent) => (
              <tr
                key={agent.id}
                onClick={() => navigate(`/agents/${agent.id}`)}
                style={{
                  borderBottom: '1px solid rgba(255,255,255,0.04)',
                  cursor: 'pointer',
                  transition: 'background-color 0.15s',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.03)')}
                onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
              >
                <td style={{ padding: '0.75rem 1rem', color: 'white', fontWeight: 500, fontSize: '0.875rem' }}>
                  {agent.hostname}
                </td>
                <td style={{ padding: '0.75rem 1rem' }}>
                  <StatusBadge status={agent.status} />
                </td>
                <td style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontSize: '0.875rem' }}>
                  {agent.ip_address || '-'}
                </td>
                <td style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontSize: '0.875rem' }}>
                  {agent.agent_version || '-'}
                </td>
                <td style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontSize: '0.875rem' }}>
                  {agent.driver_version || '-'}
                </td>
                <td style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontSize: '0.875rem' }}>
                  v{agent.policy_version}
                </td>
                <td style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontSize: '0.875rem' }}>
                  {agent.group?.name || '-'}
                </td>
                <td style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontSize: '0.875rem' }}>
                  {timeAgo(agent.last_heartbeat)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {pages > 1 && (
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          gap: '1rem', marginTop: '1rem',
        }}>
          <button
            disabled={page <= 1}
            onClick={() => setPage(p => p - 1)}
            style={{
              padding: '0.375rem', borderRadius: '0.375rem',
              backgroundColor: 'rgba(255,255,255,0.06)', border: 'none',
              color: page <= 1 ? '#334155' : '#94a3b8', cursor: page <= 1 ? 'default' : 'pointer',
            }}
          >
            <ChevronLeft style={{ width: '1rem', height: '1rem' }} />
          </button>
          <span style={{ fontSize: '0.875rem', color: '#94a3b8' }}>
            Page {page} of {pages}
          </span>
          <button
            disabled={page >= pages}
            onClick={() => setPage(p => p + 1)}
            style={{
              padding: '0.375rem', borderRadius: '0.375rem',
              backgroundColor: 'rgba(255,255,255,0.06)', border: 'none',
              color: page >= pages ? '#334155' : '#94a3b8', cursor: page >= pages ? 'default' : 'pointer',
            }}
          >
            <ChevronRight style={{ width: '1rem', height: '1rem' }} />
          </button>
        </div>
      )}
    </div>
  );
}
