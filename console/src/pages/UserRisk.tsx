/**
 * User Risk page (P8-T7).
 * Displays user risk scores sorted by normalized score descending.
 * Color-coded risk levels with severity breakdown.
 */

import { useEffect, useState } from 'react';
import { ShieldAlert, RefreshCw, User } from 'lucide-react';
import useTitle from '../hooks/useTitle';
import api from '../api/client';

interface UserScore {
  user: string;
  raw_score: number;
  normalized_score: number;
  risk_level: string;
  incident_count: number;
  severity_breakdown: Record<string, number>;
  latest_incident: string | null;
  oldest_incident: string | null;
}

interface RiskResponse {
  generated_at: string;
  lookback_days: number;
  users: UserScore[];
}

const RISK_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  minimal: '#64748b',
};

const RISK_BG: Record<string, string> = {
  critical: 'rgba(239,68,68,0.12)',
  high: 'rgba(249,115,22,0.12)',
  medium: 'rgba(234,179,8,0.12)',
  low: 'rgba(59,130,246,0.12)',
  minimal: 'rgba(100,116,139,0.12)',
};

const cardStyle: React.CSSProperties = {
  backgroundColor: 'var(--color-surface-card)', border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '0.75rem', padding: '1.25rem',
};

export default function UserRisk() {
  useTitle('User Risk');

  const [data, setData] = useState<RiskResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [days, setDays] = useState(90);
  const [error, setError] = useState('');

  async function fetchRisk(lookback: number) {
    setLoading(true);
    setError('');
    try {
      const result = await api.get<RiskResponse>(`/reports/risk?days=${lookback}`);
      setData(result);
    } catch {
      setError('Failed to load risk scores. Is the server running?');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { fetchRisk(days); }, [days]);

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <ShieldAlert style={{ width: '1.25rem', height: '1.25rem', color: '#f97316' }} />
          <h1 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'white' }}>User Risk Scores</h1>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <label style={{ fontSize: '0.8125rem', color: '#64748b' }}>Lookback:</label>
          <select
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            style={{
              padding: '0.375rem 0.5rem', borderRadius: '0.375rem', fontSize: '0.8125rem',
              backgroundColor: 'var(--color-surface-page)', color: '#cbd5e1',
              border: '1px solid rgba(255,255,255,0.1)', outline: 'none',
            }}
          >
            <option value={30}>30 days</option>
            <option value={60}>60 days</option>
            <option value={90}>90 days</option>
            <option value={180}>180 days</option>
            <option value={365}>1 year</option>
          </select>
          <button
            onClick={() => fetchRisk(days)}
            disabled={loading}
            style={{
              padding: '0.375rem 0.75rem', borderRadius: '0.375rem', fontSize: '0.8125rem',
              backgroundColor: 'rgba(255,255,255,0.06)', color: '#94a3b8',
              border: '1px solid rgba(255,255,255,0.1)', cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: '0.25rem',
            }}
          >
            <RefreshCw style={{ width: '0.75rem', height: '0.75rem' }} /> Refresh
          </button>
        </div>
      </div>

      {error && (
        <div style={{ padding: '0.75rem 1rem', borderRadius: '0.5rem', backgroundColor: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)', color: '#fca5a5', fontSize: '0.8125rem', marginBottom: '1rem' }}>
          {error}
        </div>
      )}

      {loading && (
        <div style={{ textAlign: 'center', padding: '3rem', color: '#64748b' }}>Loading...</div>
      )}

      {!loading && data && data.users.length === 0 && (
        <div style={{ ...cardStyle, textAlign: 'center', padding: '3rem' }}>
          <User style={{ width: '2rem', height: '2rem', color: '#475569', margin: '0 auto 0.75rem' }} />
          <p style={{ color: '#64748b', fontSize: '0.875rem' }}>
            No user risk data for the selected period.
          </p>
        </div>
      )}

      {!loading && data && data.users.length > 0 && (
        <div style={cardStyle}>
          {data.generated_at && (
            <p style={{ fontSize: '0.75rem', color: '#475569', marginBottom: '1rem' }}>
              Generated: {new Date(data.generated_at).toLocaleString()} | Lookback: {data.lookback_days} days | Users: {data.users.length}
            </p>
          )}
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                <th style={{ textAlign: 'left', padding: '0.5rem', color: '#64748b', fontWeight: 500 }}>User</th>
                <th style={{ textAlign: 'center', padding: '0.5rem', color: '#64748b', fontWeight: 500 }}>Risk Score</th>
                <th style={{ textAlign: 'center', padding: '0.5rem', color: '#64748b', fontWeight: 500 }}>Level</th>
                <th style={{ textAlign: 'center', padding: '0.5rem', color: '#64748b', fontWeight: 500 }}>Incidents</th>
                <th style={{ textAlign: 'left', padding: '0.5rem', color: '#64748b', fontWeight: 500 }}>Severity Breakdown</th>
                <th style={{ textAlign: 'left', padding: '0.5rem', color: '#64748b', fontWeight: 500 }}>Latest</th>
              </tr>
            </thead>
            <tbody>
              {data.users.map((u) => (
                <tr key={u.user} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <td style={{ padding: '0.5rem', color: '#e2e8f0', fontWeight: 500 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <div style={{
                        width: '1.5rem', height: '1.5rem', borderRadius: '50%',
                        backgroundColor: RISK_BG[u.risk_level] || RISK_BG.minimal,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontSize: '0.625rem', fontWeight: 700, color: RISK_COLORS[u.risk_level] || RISK_COLORS.minimal,
                      }}>
                        {u.user.charAt(0).toUpperCase()}
                      </div>
                      {u.user}
                    </div>
                  </td>
                  <td style={{ textAlign: 'center', padding: '0.5rem' }}>
                    {/* Score bar */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', justifyContent: 'center' }}>
                      <div style={{ width: '4rem', height: '0.375rem', borderRadius: '0.25rem', backgroundColor: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
                        <div style={{
                          width: `${u.normalized_score}%`,
                          height: '100%', borderRadius: '0.25rem',
                          backgroundColor: RISK_COLORS[u.risk_level] || RISK_COLORS.minimal,
                        }} />
                      </div>
                      <span style={{ color: '#e2e8f0', fontWeight: 600, fontSize: '0.8125rem' }}>{u.normalized_score}</span>
                    </div>
                  </td>
                  <td style={{ textAlign: 'center', padding: '0.5rem' }}>
                    <span style={{
                      padding: '0.125rem 0.5rem', borderRadius: '9999px', fontSize: '0.6875rem', fontWeight: 600,
                      backgroundColor: RISK_BG[u.risk_level] || RISK_BG.minimal,
                      color: RISK_COLORS[u.risk_level] || RISK_COLORS.minimal,
                      textTransform: 'capitalize',
                    }}>
                      {u.risk_level}
                    </span>
                  </td>
                  <td style={{ textAlign: 'center', padding: '0.5rem', color: '#94a3b8' }}>{u.incident_count}</td>
                  <td style={{ padding: '0.5rem' }}>
                    <div style={{ display: 'flex', gap: '0.375rem', flexWrap: 'wrap' }}>
                      {Object.entries(u.severity_breakdown).map(([sev, count]) => (
                        <span key={sev} style={{
                          fontSize: '0.6875rem', padding: '0.125rem 0.375rem', borderRadius: '0.25rem',
                          backgroundColor: 'rgba(255,255,255,0.04)', color: RISK_COLORS[sev] || '#94a3b8',
                        }}>
                          {sev}: {count}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td style={{ padding: '0.5rem', color: '#64748b', whiteSpace: 'nowrap', fontSize: '0.75rem' }}>
                    {u.latest_incident ? new Date(u.latest_incident).toLocaleDateString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
