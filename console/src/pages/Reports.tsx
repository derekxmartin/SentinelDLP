/**
 * Reports page (P8-T7).
 * Generate summary/detail/trend reports with date filtering.
 * Export as CSV download.
 */

import { useState } from 'react';
import { FileText, Download, BarChart3, TrendingUp, List } from 'lucide-react';
import useTitle from '../hooks/useTitle';
import api, { getAccessToken } from '../api/client';

interface Bucket {
  key: string;
  count: number;
  percentage: number;
}

interface SummaryReport {
  start_date: string;
  end_date: string;
  total_incidents: number;
  by_severity: Bucket[];
  by_policy: Bucket[];
  by_channel: Bucket[];
  by_status: Bucket[];
  by_source_type: Bucket[];
  top_users: Bucket[];
}

interface DetailIncident {
  id: string;
  policy_name: string;
  severity: string;
  status: string;
  channel: string;
  source_type: string;
  user: string | null;
  file_name: string | null;
  action_taken: string;
  match_count: number;
  created_at: string;
}

interface DetailReport {
  start_date: string;
  end_date: string;
  total_incidents: number;
  incidents: DetailIncident[];
}

interface TrendDelta {
  metric: string;
  current_value: number;
  previous_value: number;
  delta: number;
  delta_percent: number;
}

interface TrendReport {
  current_period: SummaryReport;
  previous_period: SummaryReport;
  deltas: TrendDelta[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#64748b',
};

const cardStyle: React.CSSProperties = {
  backgroundColor: 'var(--color-surface-card)', border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '0.75rem', padding: '1.25rem',
};

const inputStyle: React.CSSProperties = {
  padding: '0.375rem 0.75rem', borderRadius: '0.375rem', fontSize: '0.8125rem',
  backgroundColor: 'var(--color-surface-page)', color: '#cbd5e1',
  border: '1px solid rgba(255,255,255,0.1)', outline: 'none',
};

const btnStyle: React.CSSProperties = {
  padding: '0.5rem 1rem', borderRadius: '0.375rem', fontSize: '0.8125rem', fontWeight: 500,
  border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.375rem',
};

function BucketTable({ title, buckets }: { title: string; buckets: Bucket[] }) {
  if (!buckets.length) return null;
  return (
    <div>
      <h3 style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.5rem' }}>{title}</h3>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
            <th style={{ textAlign: 'left', padding: '0.375rem 0', color: '#64748b', fontWeight: 500 }}>Category</th>
            <th style={{ textAlign: 'right', padding: '0.375rem 0', color: '#64748b', fontWeight: 500 }}>Count</th>
            <th style={{ textAlign: 'right', padding: '0.375rem 0', color: '#64748b', fontWeight: 500 }}>%</th>
          </tr>
        </thead>
        <tbody>
          {buckets.map((b) => (
            <tr key={b.key} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              <td style={{ padding: '0.375rem 0', color: '#e2e8f0' }}>{b.key}</td>
              <td style={{ textAlign: 'right', padding: '0.375rem 0', color: '#e2e8f0' }}>{b.count}</td>
              <td style={{ textAlign: 'right', padding: '0.375rem 0', color: '#94a3b8' }}>{b.percentage}%</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Reports() {
  useTitle('Reports');

  const today = new Date().toISOString().slice(0, 10);
  const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);

  const [startDate, setStartDate] = useState(thirtyDaysAgo);
  const [endDate, setEndDate] = useState(today);
  const [tab, setTab] = useState<'summary' | 'detail' | 'trend'>('summary');
  const [loading, setLoading] = useState(false);
  const [summaryData, setSummaryData] = useState<SummaryReport | null>(null);
  const [detailData, setDetailData] = useState<DetailReport | null>(null);
  const [trendData, setTrendData] = useState<TrendReport | null>(null);
  const [error, setError] = useState('');

  async function generateReport() {
    setLoading(true);
    setError('');
    try {
      const body = {
        start_date: new Date(startDate).toISOString(),
        end_date: new Date(endDate + 'T23:59:59').toISOString(),
      };

      if (tab === 'summary') {
        const data = await api.post<SummaryReport>('/reports/summary', body);
        setSummaryData(data);
      } else if (tab === 'detail') {
        const data = await api.post<DetailReport>('/reports/detail', body);
        setDetailData(data);
      } else {
        const data = await api.post<TrendReport>('/reports/trend', body);
        setTrendData(data);
      }
    } catch {
      setError('Failed to generate report. Is the server running?');
    } finally {
      setLoading(false);
    }
  }

  async function downloadCSV() {
    try {
      const body = {
        start_date: new Date(startDate).toISOString(),
        end_date: new Date(endDate + 'T23:59:59').toISOString(),
      };
      const endpoint = tab === 'detail' ? '/reports/detail/csv' : '/reports/summary/csv';
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      const token = getAccessToken();
      if (token) headers['Authorization'] = `Bearer ${token}`;
      const resp = await fetch(`/api${endpoint}`, {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify(body),
      });
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${tab}_report.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setError('Failed to download CSV');
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
        <FileText style={{ width: '1.25rem', height: '1.25rem', color: '#6366f1' }} />
        <h1 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'white' }}>Reports</h1>
      </div>

      {/* Controls */}
      <div style={{ ...cardStyle, marginBottom: '1rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'flex-end' }}>
          {/* Tab selector */}
          <div style={{ display: 'flex', gap: '0.25rem', padding: '0.25rem', borderRadius: '0.5rem', backgroundColor: 'rgba(255,255,255,0.04)' }}>
            {([
              { key: 'summary', label: 'Summary', icon: BarChart3 },
              { key: 'detail', label: 'Detail', icon: List },
              { key: 'trend', label: 'Trend', icon: TrendingUp },
            ] as const).map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                style={{
                  ...btnStyle,
                  backgroundColor: tab === key ? '#6366f1' : 'transparent',
                  color: tab === key ? 'white' : '#94a3b8',
                }}
              >
                <Icon style={{ width: '0.875rem', height: '0.875rem' }} /> {label}
              </button>
            ))}
          </div>

          {/* Date range */}
          <div>
            <label style={{ fontSize: '0.75rem', color: '#64748b', display: 'block', marginBottom: '0.25rem' }}>Start</label>
            <input type="date" value={startDate} onChange={(e) => setStartDate(e.target.value)} style={inputStyle} />
          </div>
          <div>
            <label style={{ fontSize: '0.75rem', color: '#64748b', display: 'block', marginBottom: '0.25rem' }}>End</label>
            <input type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)} style={inputStyle} />
          </div>

          {/* Generate */}
          <button
            onClick={generateReport}
            disabled={loading}
            style={{ ...btnStyle, backgroundColor: '#6366f1', color: 'white', opacity: loading ? 0.6 : 1 }}
          >
            {loading ? 'Generating...' : 'Generate'}
          </button>

          {/* CSV download (not for trend) */}
          {tab !== 'trend' && (summaryData || detailData) && (
            <button onClick={downloadCSV} style={{ ...btnStyle, backgroundColor: 'rgba(255,255,255,0.06)', color: '#94a3b8', border: '1px solid rgba(255,255,255,0.1)' }}>
              <Download style={{ width: '0.875rem', height: '0.875rem' }} /> CSV
            </button>
          )}
        </div>
      </div>

      {error && (
        <div style={{ padding: '0.75rem 1rem', borderRadius: '0.5rem', backgroundColor: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)', color: '#fca5a5', fontSize: '0.8125rem', marginBottom: '1rem' }}>
          {error}
        </div>
      )}

      {/* Summary Report */}
      {tab === 'summary' && summaryData && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={cardStyle}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h2 style={{ fontSize: '1rem', fontWeight: 600, color: '#e2e8f0' }}>Summary</h2>
              <span style={{ fontSize: '2rem', fontWeight: 700, color: '#6366f1' }}>{summaryData.total_incidents}</span>
            </div>
            <p style={{ fontSize: '0.8125rem', color: '#64748b' }}>
              {new Date(summaryData.start_date).toLocaleDateString()} — {new Date(summaryData.end_date).toLocaleDateString()}
            </p>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
            {[
              { title: 'By Severity', data: summaryData.by_severity },
              { title: 'By Policy', data: summaryData.by_policy },
              { title: 'By Channel', data: summaryData.by_channel },
              { title: 'By Status', data: summaryData.by_status },
              { title: 'By Source Type', data: summaryData.by_source_type },
              { title: 'Top Users', data: summaryData.top_users },
            ].map(({ title, data }) => (
              <div key={title} style={cardStyle}>
                <BucketTable title={title} buckets={data} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Detail Report */}
      {tab === 'detail' && detailData && (
        <div style={cardStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
            <h2 style={{ fontSize: '1rem', fontWeight: 600, color: '#e2e8f0' }}>
              Incidents ({detailData.total_incidents})
            </h2>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                  {['Policy', 'Severity', 'Status', 'Channel', 'User', 'Action', 'Matches', 'Date'].map((h) => (
                    <th key={h} style={{ textAlign: 'left', padding: '0.5rem', color: '#64748b', fontWeight: 500, whiteSpace: 'nowrap' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {detailData.incidents.map((inc) => (
                  <tr key={inc.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <td style={{ padding: '0.5rem', color: '#e2e8f0' }}>{inc.policy_name}</td>
                    <td style={{ padding: '0.5rem' }}>
                      <span style={{ color: SEVERITY_COLORS[inc.severity] || '#64748b', fontWeight: 500 }}>{inc.severity}</span>
                    </td>
                    <td style={{ padding: '0.5rem', color: '#94a3b8' }}>{inc.status}</td>
                    <td style={{ padding: '0.5rem', color: '#94a3b8' }}>{inc.channel}</td>
                    <td style={{ padding: '0.5rem', color: '#94a3b8' }}>{inc.user || '—'}</td>
                    <td style={{ padding: '0.5rem', color: '#94a3b8' }}>{inc.action_taken}</td>
                    <td style={{ padding: '0.5rem', color: '#94a3b8', textAlign: 'center' }}>{inc.match_count}</td>
                    <td style={{ padding: '0.5rem', color: '#64748b', whiteSpace: 'nowrap' }}>{new Date(inc.created_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Trend Report */}
      {tab === 'trend' && trendData && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={cardStyle}>
            <h2 style={{ fontSize: '1rem', fontWeight: 600, color: '#e2e8f0', marginBottom: '1rem' }}>Trend Comparison</h2>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                  {['Metric', 'Current', 'Previous', 'Delta', 'Change'].map((h) => (
                    <th key={h} style={{ textAlign: h === 'Metric' ? 'left' : 'right', padding: '0.5rem', color: '#64748b', fontWeight: 500 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {trendData.deltas.map((d) => (
                  <tr key={d.metric} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <td style={{ padding: '0.5rem', color: '#e2e8f0', textTransform: 'capitalize' }}>
                      {d.metric.replace(/_/g, ' ')}
                    </td>
                    <td style={{ textAlign: 'right', padding: '0.5rem', color: '#e2e8f0', fontWeight: 600 }}>{d.current_value}</td>
                    <td style={{ textAlign: 'right', padding: '0.5rem', color: '#94a3b8' }}>{d.previous_value}</td>
                    <td style={{ textAlign: 'right', padding: '0.5rem', color: d.delta > 0 ? '#f87171' : d.delta < 0 ? '#4ade80' : '#64748b', fontWeight: 500 }}>
                      {d.delta > 0 ? '+' : ''}{d.delta}
                    </td>
                    <td style={{ textAlign: 'right', padding: '0.5rem', color: d.delta_percent > 0 ? '#f87171' : d.delta_percent < 0 ? '#4ade80' : '#64748b' }}>
                      {d.delta_percent > 0 ? '+' : ''}{d.delta_percent}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Side-by-side period summaries */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div style={cardStyle}>
              <h3 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0', marginBottom: '0.75rem' }}>
                Current Period ({trendData.current_period.total_incidents} incidents)
              </h3>
              <BucketTable title="By Severity" buckets={trendData.current_period.by_severity} />
            </div>
            <div style={cardStyle}>
              <h3 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0', marginBottom: '0.75rem' }}>
                Previous Period ({trendData.previous_period.total_incidents} incidents)
              </h3>
              <BucketTable title="By Severity" buckets={trendData.previous_period.by_severity} />
            </div>
          </div>
        </div>
      )}

      {/* Empty state */}
      {!loading && !summaryData && !detailData && !trendData && !error && (
        <div style={{ ...cardStyle, textAlign: 'center', padding: '3rem' }}>
          <BarChart3 style={{ width: '2rem', height: '2rem', color: '#475569', margin: '0 auto 0.75rem' }} />
          <p style={{ color: '#64748b', fontSize: '0.875rem' }}>
            Select a report type and date range, then click Generate.
          </p>
        </div>
      )}
    </div>
  );
}
