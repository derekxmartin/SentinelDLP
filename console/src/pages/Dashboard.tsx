/**
 * Dashboard page (P2-T8).
 * Severity cards, trend chart (Recharts), recent incidents,
 * active policies count, agent count.
 */

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, FileText, Monitor, Activity, ArrowUpRight } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import useTitle from '../hooks/useTitle';
import api from '../api/client';

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

interface PolicyList {
  items: { id: string; status: string }[];
  total: number;
}

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

// Generate mock trend data (last 7 days)
function generateTrendData() {
  const data = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    data.push({
      date: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      incidents: Math.floor(Math.random() * 15) + 1,
      blocked: Math.floor(Math.random() * 8),
    });
  }
  return data;
}

function StatCard({
  icon: Icon,
  label,
  value,
  color,
  bgColor,
}: {
  icon: typeof ShieldAlert;
  label: string;
  value: string | number;
  color: string;
  bgColor: string;
}) {
  return (
    <div style={{
      backgroundColor: 'var(--color-surface-card)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: '0.75rem',
      padding: '1.25rem',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
        <div style={{ padding: '0.5rem', borderRadius: '0.5rem', backgroundColor: bgColor }}>
          <Icon style={{ width: '1rem', height: '1rem', color }} />
        </div>
        <span style={{ fontSize: '0.875rem', color: '#94a3b8' }}>{label}</span>
      </div>
      <p style={{ fontSize: '1.5rem', fontWeight: 600, color: 'white' }}>{value}</p>
    </div>
  );
}

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

export default function Dashboard() {
  useTitle('Dashboard');

  const navigate = useNavigate();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [totalIncidents, setTotalIncidents] = useState(0);
  const [activePolicies, setActivePolicies] = useState(0);
  const [trendData] = useState(generateTrendData);

  useEffect(() => {
    api.get<IncidentList>('/incidents', { page_size: '5', sort_by: 'created_at', sort_order: 'desc' })
      .then((data) => {
        setIncidents(data.items);
        setTotalIncidents(data.total);
      })
      .catch(() => {});

    api.get<PolicyList>('/policies', { status: 'active' })
      .then((data) => setActivePolicies(data.total))
      .catch(() => {});
  }, []);

  return (
    <div>
      <h1 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'white', marginBottom: '1.5rem' }}>
        Dashboard
      </h1>

      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
        <StatCard icon={ShieldAlert} label="Open Incidents" value={totalIncidents} color="#ef4444" bgColor="rgba(239,68,68,0.1)" />
        <StatCard icon={FileText} label="Active Policies" value={activePolicies} color="#6366f1" bgColor="rgba(99,102,241,0.1)" />
        <StatCard icon={Monitor} label="Agents Online" value="—" color="#22c55e" bgColor="rgba(34,197,94,0.1)" />
        <StatCard icon={Activity} label="Scans Today" value="—" color="#eab308" bgColor="rgba(234,179,8,0.1)" />
      </div>

      {/* Charts + Recent incidents row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        {/* Trend chart */}
        <div style={{
          backgroundColor: 'var(--color-surface-card)',
          border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: '0.75rem',
          padding: '1.25rem',
        }}>
          <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0', marginBottom: '1rem' }}>
            Incident Trend (7 days)
          </h2>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={trendData}>
              <defs>
                <linearGradient id="incidentGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="date" tick={{ fill: '#64748b', fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#64748b', fontSize: 12 }} axisLine={false} tickLine={false} width={30} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '0.5rem', fontSize: '0.75rem' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Area type="monotone" dataKey="incidents" stroke="#6366f1" fill="url(#incidentGrad)" strokeWidth={2} />
              <Area type="monotone" dataKey="blocked" stroke="#ef4444" fill="url(#blockedGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Recent incidents */}
        <div style={{
          backgroundColor: 'var(--color-surface-card)',
          border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: '0.75rem',
          padding: '1.25rem',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h2 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0' }}>
              Recent Incidents
            </h2>
            <button
              onClick={() => navigate('/incidents')}
              style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.75rem', color: '#6366f1', background: 'none', border: 'none', cursor: 'pointer' }}
            >
              View all <ArrowUpRight style={{ width: '0.75rem', height: '0.75rem' }} />
            </button>
          </div>

          {incidents.length === 0 ? (
            <p style={{ fontSize: '0.875rem', color: '#64748b', textAlign: 'center', padding: '2rem 0' }}>
              No incidents yet.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {incidents.map((inc) => (
                <button
                  key={inc.id}
                  onClick={() => navigate(`/incidents/${inc.id}`)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '0.625rem 0.75rem',
                    borderRadius: '0.5rem',
                    backgroundColor: 'rgba(255,255,255,0.02)',
                    border: '1px solid rgba(255,255,255,0.05)',
                    cursor: 'pointer',
                    width: '100%',
                    textAlign: 'left',
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <p style={{ fontSize: '0.8125rem', color: '#e2e8f0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {inc.policy_name}
                    </p>
                    <p style={{ fontSize: '0.75rem', color: '#64748b' }}>
                      {inc.user || 'Unknown'} &middot; {inc.channel}
                    </p>
                  </div>
                  <SeverityBadge severity={inc.severity} />
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
