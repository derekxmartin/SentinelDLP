/**
 * Dashboard page - AkesoDLP console overview.
 * 6 widgets with real data: trend chart, top policies, channel breakdown,
 * risky users, agent health, and activity timeline.
 * Uses CSS/SVG charts (no external chart libraries).
 */

import { useEffect, useState, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert, Users, Monitor, TrendingUp, ArrowUpRight,
  Clock, AlertTriangle, Wifi, WifiOff, Activity,
} from 'lucide-react';
import useTitle from '../hooks/useTitle';
import api from '../api/client';

/* ---------- types ---------- */

interface Bucket {
  key: string;
  count: number;
  percentage: number;
}

interface SummaryReport {
  total_incidents: number;
  by_severity: Bucket[];
  by_policy: Bucket[];
  by_channel: Bucket[];
  by_status: Bucket[];
  by_source_type: Bucket[];
  top_users: Bucket[];
}

interface Incident {
  id: string;
  policy_name: string;
  severity: string;
  status: string;
  channel: string;
  file_name: string | null;
  user: string | null;
  created_at: string;
}

interface IncidentList {
  items: Incident[];
  total: number;
}

interface RiskUser {
  user: string;
  risk_score: number;
  incident_count: number;
  severity_breakdown: Record<string, number>;
}

interface AgentStats {
  total: number;
  online: number;
  offline: number;
  stale: number;
  error: number;
}

/* ---------- constants ---------- */

type RangeKey = '7d' | '30d' | '90d';

const RANGES: { key: RangeKey; label: string; days: number }[] = [
  { key: '7d', label: '7 days', days: 7 },
  { key: '30d', label: '30 days', days: 30 },
  { key: '90d', label: '90 days', days: 90 },
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#64748b',
};

const SEVERITY_BG: Record<string, string> = {
  critical: 'rgba(239,68,68,0.1)',
  high: 'rgba(249,115,22,0.1)',
  medium: 'rgba(234,179,8,0.1)',
  low: 'rgba(59,130,246,0.1)',
  info: 'rgba(100,116,139,0.1)',
};

const CHANNEL_COLORS: Record<string, string> = {
  endpoint: '#6366f1',
  network: '#22c55e',
  discover: '#f59e0b',
  email: '#ec4899',
  cloud: '#06b6d4',
};

const cardStyle: React.CSSProperties = {
  backgroundColor: 'var(--color-surface-card)',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '0.75rem',
  padding: '1.25rem',
};

/* ---------- helper components ---------- */

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span style={{
      display: 'inline-block',
      padding: '0.125rem 0.5rem',
      borderRadius: '9999px',
      fontSize: '0.75rem',
      fontWeight: 500,
      backgroundColor: SEVERITY_BG[severity] || SEVERITY_BG.info,
      color: SEVERITY_COLORS[severity] || SEVERITY_COLORS.info,
      textTransform: 'capitalize',
    }}>
      {severity}
    </span>
  );
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

/* ---------- Trend Chart (pure CSS bar chart) ---------- */

function TrendChart({ buckets, days }: { buckets: Bucket[]; days: number }) {
  // Build day-by-day data from by_severity or derive from summary
  // We'll use the by_policy buckets to show total per-day but the API gives aggregate.
  // Since the summary API returns aggregates, we'll show a bar chart of the buckets passed.
  // For a real daily breakdown we'd need a trend endpoint, so we show severity distribution as bars.

  // Actually, let's build a synthetic daily chart from total_incidents spread across the range.
  // Better: show the severity breakdown as stacked horizontal bars since we have real data.

  const maxCount = Math.max(...buckets.map(b => b.count), 1);

  if (buckets.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '180px', color: '#64748b', fontSize: '0.875rem' }}>
        No incident data for this period.
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
      {buckets.map((b) => (
        <div key={b.key} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span style={{
            width: '60px', fontSize: '0.75rem', color: '#94a3b8',
            textTransform: 'capitalize', textAlign: 'right', flexShrink: 0,
          }}>
            {b.key}
          </span>
          <div style={{ flex: 1, height: '24px', backgroundColor: 'rgba(255,255,255,0.04)', borderRadius: '4px', overflow: 'hidden' }}>
            <div style={{
              height: '100%',
              width: `${Math.max((b.count / maxCount) * 100, 2)}%`,
              backgroundColor: SEVERITY_COLORS[b.key] || '#6366f1',
              borderRadius: '4px',
              transition: 'width 0.3s ease',
            }} />
          </div>
          <span style={{ width: '36px', fontSize: '0.75rem', color: '#e2e8f0', textAlign: 'right', flexShrink: 0 }}>
            {b.count}
          </span>
        </div>
      ))}
    </div>
  );
}

/* ---------- Donut Chart (SVG) ---------- */

function DonutChart({ segments }: { segments: { key: string; count: number; color: string }[] }) {
  const total = segments.reduce((s, seg) => s + seg.count, 0);
  if (total === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '160px', color: '#64748b', fontSize: '0.875rem' }}>
        No data.
      </div>
    );
  }

  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
      <svg width="130" height="130" viewBox="0 0 130 130" style={{ flexShrink: 0 }}>
        {segments.filter(s => s.count > 0).map((seg) => {
          const pct = seg.count / total;
          const dashLength = pct * circumference;
          const dashOffset = -offset;
          offset += dashLength;
          return (
            <circle
              key={seg.key}
              cx="65" cy="65" r={radius}
              fill="none"
              stroke={seg.color}
              strokeWidth="16"
              strokeDasharray={`${dashLength} ${circumference - dashLength}`}
              strokeDashoffset={dashOffset}
              style={{ transition: 'stroke-dasharray 0.3s ease' }}
            />
          );
        })}
        <text x="65" y="62" textAnchor="middle" fill="white" fontSize="18" fontWeight="700">{total}</text>
        <text x="65" y="78" textAnchor="middle" fill="#64748b" fontSize="10">total</text>
      </svg>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
        {segments.map((seg) => (
          <div key={seg.key} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <div style={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: seg.color, flexShrink: 0 }} />
            <span style={{ fontSize: '0.75rem', color: '#cbd5e1', textTransform: 'capitalize' }}>
              {seg.key}
            </span>
            <span style={{ fontSize: '0.75rem', color: '#64748b', marginLeft: 'auto' }}>
              {seg.count}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Agent Health Ring ---------- */

function AgentHealthWidget({ stats }: { stats: AgentStats | null }) {
  if (!stats) {
    return <div style={{ color: '#64748b', fontSize: '0.875rem', padding: '1rem 0' }}>Loading agent data...</div>;
  }

  const items: { label: string; value: number; color: string; icon: typeof Wifi }[] = [
    { label: 'Online', value: stats.online, color: '#22c55e', icon: Wifi },
    { label: 'Offline', value: stats.offline, color: '#6b7280', icon: WifiOff },
    { label: 'Stale', value: stats.stale, color: '#eab308', icon: Clock },
    { label: 'Error', value: stats.error, color: '#ef4444', icon: AlertTriangle },
  ];

  return (
    <div>
      <div style={{
        display: 'flex', alignItems: 'center', gap: '0.5rem',
        marginBottom: '1rem', paddingBottom: '0.75rem',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}>
        <span style={{ fontSize: '1.5rem', fontWeight: 700, color: 'white' }}>{stats.total}</span>
        <span style={{ fontSize: '0.8125rem', color: '#64748b' }}>total agents</span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
        {items.map(({ label, value, color, icon: Icon }) => (
          <div key={label} style={{
            display: 'flex', alignItems: 'center', gap: '0.5rem',
            padding: '0.5rem 0.625rem', borderRadius: '0.5rem',
            backgroundColor: 'rgba(255,255,255,0.03)',
          }}>
            <Icon style={{ width: '0.875rem', height: '0.875rem', color }} />
            <div>
              <div style={{ fontSize: '1rem', fontWeight: 600, color }}>{value}</div>
              <div style={{ fontSize: '0.6875rem', color: '#64748b' }}>{label}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Main Dashboard ---------- */

export default function Dashboard() {
  useTitle('Dashboard');
  const navigate = useNavigate();

  const [range, setRange] = useState<RangeKey>('30d');
  const [summary, setSummary] = useState<SummaryReport | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [riskUsers, setRiskUsers] = useState<RiskUser[]>([]);
  const [agentStats, setAgentStats] = useState<AgentStats | null>(null);
  const [loading, setLoading] = useState(true);

  const days = useMemo(() => RANGES.find(r => r.key === range)!.days, [range]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    const now = new Date();
    const start = new Date(now.getTime() - days * 86400000);

    const promises = [
      // Summary report
      api.post<SummaryReport>('/reports/summary', {
        start_date: start.toISOString(),
        end_date: now.toISOString(),
      }).then(setSummary).catch(() => {}),

      // Recent incidents
      api.get<IncidentList>('/incidents', {
        page_size: '5',
        sort_by: 'created_at',
        sort_order: 'desc',
      }).then((data) => setIncidents(data.items)).catch(() => {}),

      // Risk users
      api.get<RiskUser[]>('/reports/risk', { days: String(days) })
        .then((data) => setRiskUsers(Array.isArray(data) ? data.slice(0, 5) : []))
        .catch(() => {}),

      // Agent stats
      api.get<AgentStats>('/agents/stats')
        .then(setAgentStats)
        .catch(() => {}),
    ];

    await Promise.allSettled(promises);
    setLoading(false);
  }, [days]);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Derived data
  const channelSegments = useMemo(() => {
    if (!summary) return [];
    return summary.by_channel.map(b => ({
      key: b.key,
      count: b.count,
      color: CHANNEL_COLORS[b.key] || '#6366f1',
    }));
  }, [summary]);

  const topPolicies = useMemo(() => {
    if (!summary) return [];
    return summary.by_policy.slice(0, 5);
  }, [summary]);

  const severityBuckets = useMemo(() => {
    if (!summary) return [];
    return summary.by_severity;
  }, [summary]);

  return (
    <div>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: '1.5rem', flexWrap: 'wrap', gap: '0.75rem',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Activity style={{ width: '1.25rem', height: '1.25rem', color: '#6366f1' }} />
          <h1 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'white' }}>Dashboard</h1>
          {loading && (
            <span style={{ fontSize: '0.75rem', color: '#64748b' }}>Loading...</span>
          )}
        </div>

        {/* Time range selector */}
        <div style={{
          display: 'flex', gap: '0.25rem', padding: '0.25rem',
          borderRadius: '0.5rem', backgroundColor: 'rgba(255,255,255,0.04)',
        }}>
          {RANGES.map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setRange(key)}
              style={{
                padding: '0.375rem 0.75rem', borderRadius: '0.375rem',
                fontSize: '0.8125rem', fontWeight: 500, border: 'none', cursor: 'pointer',
                backgroundColor: range === key ? '#6366f1' : 'transparent',
                color: range === key ? 'white' : '#94a3b8',
                transition: 'all 0.15s',
              }}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Top summary stat cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: '1rem',
        marginBottom: '1.5rem',
      }}>
        <div style={cardStyle}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
            <div style={{ padding: '0.5rem', borderRadius: '0.5rem', backgroundColor: 'rgba(99,102,241,0.1)' }}>
              <ShieldAlert style={{ width: '1rem', height: '1rem', color: '#6366f1' }} />
            </div>
            <span style={{ fontSize: '0.8125rem', color: '#94a3b8' }}>Total Incidents</span>
          </div>
          <p style={{ fontSize: '1.5rem', fontWeight: 700, color: 'white' }}>
            {summary?.total_incidents ?? '\u2014'}
          </p>
        </div>

        <div style={cardStyle}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
            <div style={{ padding: '0.5rem', borderRadius: '0.5rem', backgroundColor: 'rgba(239,68,68,0.1)' }}>
              <AlertTriangle style={{ width: '1rem', height: '1rem', color: '#ef4444' }} />
            </div>
            <span style={{ fontSize: '0.8125rem', color: '#94a3b8' }}>Critical / High</span>
          </div>
          <p style={{ fontSize: '1.5rem', fontWeight: 700, color: 'white' }}>
            {summary
              ? (summary.by_severity.find(b => b.key === 'critical')?.count ?? 0) +
                (summary.by_severity.find(b => b.key === 'high')?.count ?? 0)
              : '\u2014'}
          </p>
        </div>

        <div style={cardStyle}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
            <div style={{ padding: '0.5rem', borderRadius: '0.5rem', backgroundColor: 'rgba(34,197,94,0.1)' }}>
              <Monitor style={{ width: '1rem', height: '1rem', color: '#22c55e' }} />
            </div>
            <span style={{ fontSize: '0.8125rem', color: '#94a3b8' }}>Agents Online</span>
          </div>
          <p style={{ fontSize: '1.5rem', fontWeight: 700, color: 'white' }}>
            {agentStats ? `${agentStats.online} / ${agentStats.total}` : '\u2014'}
          </p>
        </div>

        <div style={cardStyle}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
            <div style={{ padding: '0.5rem', borderRadius: '0.5rem', backgroundColor: 'rgba(234,179,8,0.1)' }}>
              <Users style={{ width: '1rem', height: '1rem', color: '#eab308' }} />
            </div>
            <span style={{ fontSize: '0.8125rem', color: '#94a3b8' }}>Risky Users</span>
          </div>
          <p style={{ fontSize: '1.5rem', fontWeight: 700, color: 'white' }}>
            {riskUsers.length > 0 ? riskUsers.length : '\u2014'}
          </p>
        </div>
      </div>

      {/* Row 1: Trend chart + Channel donut */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '2fr 1fr',
        gap: '1rem',
        marginBottom: '1rem',
      }}>
        {/* Incident severity breakdown */}
        <div style={cardStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0' }}>
              <TrendingUp style={{ width: '0.875rem', height: '0.875rem', display: 'inline', verticalAlign: 'middle', marginRight: '0.375rem' }} />
              Incidents by Severity
            </h2>
            <span style={{ fontSize: '0.75rem', color: '#64748b' }}>Last {days} days</span>
          </div>
          <TrendChart buckets={severityBuckets} days={days} />
        </div>

        {/* Channel breakdown donut */}
        <div style={cardStyle}>
          <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0', marginBottom: '1rem' }}>
            Channel Breakdown
          </h2>
          <DonutChart segments={channelSegments} />
        </div>
      </div>

      {/* Row 2: Top policies + Risky users + Agent health */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr 1fr',
        gap: '1rem',
        marginBottom: '1rem',
      }}>
        {/* Top 5 policies */}
        <div style={cardStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0' }}>Top Policies</h2>
            <button
              onClick={() => navigate('/policies')}
              style={{
                display: 'flex', alignItems: 'center', gap: '0.25rem',
                fontSize: '0.75rem', color: '#6366f1', background: 'none', border: 'none', cursor: 'pointer',
              }}
            >
              View all <ArrowUpRight style={{ width: '0.75rem', height: '0.75rem' }} />
            </button>
          </div>
          {topPolicies.length === 0 ? (
            <p style={{ fontSize: '0.8125rem', color: '#64748b', textAlign: 'center', padding: '1.5rem 0' }}>
              No policy data.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {topPolicies.map((p, i) => (
                <div key={p.key} style={{
                  display: 'flex', alignItems: 'center', gap: '0.5rem',
                  padding: '0.5rem 0.625rem', borderRadius: '0.5rem',
                  backgroundColor: 'rgba(255,255,255,0.02)',
                }}>
                  <span style={{
                    width: '1.25rem', height: '1.25rem', borderRadius: '50%',
                    backgroundColor: 'rgba(99,102,241,0.15)', color: '#818cf8',
                    fontSize: '0.6875rem', fontWeight: 600,
                    display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                  }}>
                    {i + 1}
                  </span>
                  <span style={{
                    flex: 1, fontSize: '0.8125rem', color: '#e2e8f0',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>
                    {p.key}
                  </span>
                  <span style={{ fontSize: '0.75rem', color: '#94a3b8', flexShrink: 0 }}>
                    {p.count}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top 5 risky users */}
        <div style={cardStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0' }}>Risky Users</h2>
            <button
              onClick={() => navigate('/reports')}
              style={{
                display: 'flex', alignItems: 'center', gap: '0.25rem',
                fontSize: '0.75rem', color: '#6366f1', background: 'none', border: 'none', cursor: 'pointer',
              }}
            >
              Details <ArrowUpRight style={{ width: '0.75rem', height: '0.75rem' }} />
            </button>
          </div>
          {riskUsers.length === 0 ? (
            <p style={{ fontSize: '0.8125rem', color: '#64748b', textAlign: 'center', padding: '1.5rem 0' }}>
              No risky users detected.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {riskUsers.map((u) => {
                const scoreColor = u.risk_score >= 80 ? '#ef4444' : u.risk_score >= 50 ? '#f97316' : u.risk_score >= 30 ? '#eab308' : '#22c55e';
                return (
                  <div key={u.user} style={{
                    display: 'flex', alignItems: 'center', gap: '0.5rem',
                    padding: '0.5rem 0.625rem', borderRadius: '0.5rem',
                    backgroundColor: 'rgba(255,255,255,0.02)',
                  }}>
                    <div style={{
                      width: '1.5rem', height: '1.5rem', borderRadius: '50%',
                      backgroundColor: 'rgba(99,102,241,0.15)', color: '#818cf8',
                      fontSize: '0.625rem', fontWeight: 600,
                      display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                      textTransform: 'uppercase',
                    }}>
                      {u.user.charAt(0)}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{
                        fontSize: '0.8125rem', color: '#e2e8f0',
                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      }}>
                        {u.user}
                      </div>
                      <div style={{ fontSize: '0.6875rem', color: '#64748b' }}>
                        {u.incident_count} incident{u.incident_count !== 1 ? 's' : ''}
                      </div>
                    </div>
                    <div style={{
                      padding: '0.125rem 0.5rem', borderRadius: '9999px',
                      fontSize: '0.75rem', fontWeight: 600,
                      backgroundColor: `${scoreColor}15`,
                      color: scoreColor,
                    }}>
                      {u.risk_score}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Agent health */}
        <div style={cardStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0' }}>Agent Health</h2>
            <button
              onClick={() => navigate('/agents')}
              style={{
                display: 'flex', alignItems: 'center', gap: '0.25rem',
                fontSize: '0.75rem', color: '#6366f1', background: 'none', border: 'none', cursor: 'pointer',
              }}
            >
              Manage <ArrowUpRight style={{ width: '0.75rem', height: '0.75rem' }} />
            </button>
          </div>
          <AgentHealthWidget stats={agentStats} />
        </div>
      </div>

      {/* Row 3: Activity timeline */}
      <div style={cardStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0' }}>
            <Clock style={{ width: '0.875rem', height: '0.875rem', display: 'inline', verticalAlign: 'middle', marginRight: '0.375rem' }} />
            Recent Activity
          </h2>
          <button
            onClick={() => navigate('/incidents')}
            style={{
              display: 'flex', alignItems: 'center', gap: '0.25rem',
              fontSize: '0.75rem', color: '#6366f1', background: 'none', border: 'none', cursor: 'pointer',
            }}
          >
            View all <ArrowUpRight style={{ width: '0.75rem', height: '0.75rem' }} />
          </button>
        </div>

        {incidents.length === 0 ? (
          <p style={{ fontSize: '0.8125rem', color: '#64748b', textAlign: 'center', padding: '2rem 0' }}>
            No recent incidents.
          </p>
        ) : (
          <div style={{ position: 'relative', paddingLeft: '1.5rem' }}>
            {/* Timeline line */}
            <div style={{
              position: 'absolute', left: '0.375rem', top: '0.5rem', bottom: '0.5rem',
              width: '2px', backgroundColor: 'rgba(255,255,255,0.06)',
            }} />

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {incidents.map((inc) => (
                <button
                  key={inc.id}
                  onClick={() => navigate(`/incidents/${inc.id}`)}
                  style={{
                    position: 'relative',
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '0.625rem 0.75rem',
                    borderRadius: '0.5rem',
                    backgroundColor: 'rgba(255,255,255,0.02)',
                    border: '1px solid rgba(255,255,255,0.05)',
                    cursor: 'pointer',
                    width: '100%',
                    textAlign: 'left',
                    transition: 'background-color 0.15s',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.04)')}
                  onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)')}
                >
                  {/* Timeline dot */}
                  <div style={{
                    position: 'absolute', left: '-1.5rem',
                    top: '50%', transform: 'translate(-50%, -50%)',
                    width: '8px', height: '8px', borderRadius: '50%',
                    backgroundColor: SEVERITY_COLORS[inc.severity] || '#64748b',
                    border: '2px solid var(--color-surface-card)',
                    marginLeft: '0.375rem',
                  }} />

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', minWidth: 0, flex: 1 }}>
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <p style={{
                        fontSize: '0.8125rem', color: '#e2e8f0',
                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      }}>
                        {inc.policy_name}
                      </p>
                      <p style={{ fontSize: '0.75rem', color: '#64748b' }}>
                        {inc.user || 'Unknown'} &middot; {inc.channel} &middot; {timeAgo(inc.created_at)}
                      </p>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexShrink: 0 }}>
                    <SeverityBadge severity={inc.severity} />
                    <span style={{
                      fontSize: '0.6875rem', color: '#475569',
                      padding: '0.125rem 0.375rem',
                      borderRadius: '0.25rem',
                      backgroundColor: 'rgba(255,255,255,0.04)',
                      textTransform: 'capitalize',
                    }}>
                      {inc.status}
                    </span>
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
