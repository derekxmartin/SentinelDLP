/**
 * Agent detail page (P9-T1).
 *
 * Shows full agent info, capabilities, group assignment,
 * and recent incidents for this agent.
 */

import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Monitor, Wifi, WifiOff, AlertTriangle, Clock, Cpu, HardDrive, Clipboard, Globe, Search } from 'lucide-react';
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

const STATUS_COLORS: Record<string, string> = {
  online: '#22c55e',
  offline: '#6b7280',
  stale: '#eab308',
  error: '#ef4444',
};

const cardStyle: React.CSSProperties = {
  backgroundColor: 'var(--color-surface-card)',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '0.75rem',
  padding: '1.5rem',
};

const labelStyle: React.CSSProperties = {
  fontSize: '0.75rem',
  color: '#64748b',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
  marginBottom: '0.25rem',
};

const valueStyle: React.CSSProperties = {
  fontSize: '0.875rem',
  color: 'white',
  fontWeight: 500,
};

const CAPABILITY_ICONS: Record<string, { icon: typeof Cpu; label: string }> = {
  usb_monitor: { icon: HardDrive, label: 'USB Monitor' },
  clipboard_monitor: { icon: Clipboard, label: 'Clipboard Monitor' },
  browser_monitor: { icon: Globe, label: 'Browser Upload Monitor' },
  network_share_monitor: { icon: Globe, label: 'Network Share Monitor' },
  discover: { icon: Search, label: 'Discover Scanner' },
};

export default function AgentDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [agent, setAgent] = useState<Agent | null>(null);
  const [groups, setGroups] = useState<AgentGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useTitle(agent ? `Agent: ${agent.hostname}` : 'Agent Detail');

  useEffect(() => {
    async function load() {
      try {
        const [agentData, groupData] = await Promise.all([
          api.get(`/agents/${id}`),
          api.get('/agents/groups'),
        ]);
        setAgent(agentData);
        setGroups(groupData);
      } catch {
        setError('Failed to load agent.');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [id]);

  async function handleGroupChange(groupId: string) {
    if (!agent) return;
    try {
      const updated = await api.put(`/agents/${agent.id}`, {
        group_id: groupId || null,
      });
      setAgent(updated);
    } catch {
      setError('Failed to update group.');
    }
  }

  function formatDate(iso: string | null): string {
    if (!iso) return 'Never';
    return new Date(iso).toLocaleString();
  }

  if (loading) {
    return <div style={{ color: '#64748b', padding: '2rem' }}>Loading...</div>;
  }

  if (error || !agent) {
    return (
      <div style={{ padding: '2rem' }}>
        <div style={{ color: '#f87171', marginBottom: '1rem' }}>{error || 'Agent not found'}</div>
        <button onClick={() => navigate('/agents')} style={{
          padding: '0.5rem 1rem', borderRadius: '0.5rem',
          backgroundColor: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)',
          color: '#94a3b8', cursor: 'pointer', fontSize: '0.875rem',
        }}>
          Back to Agents
        </button>
      </div>
    );
  }

  const statusColor = STATUS_COLORS[agent.status] || '#6b7280';

  return (
    <div style={{ maxWidth: '900px' }}>
      {/* Back button */}
      <button
        onClick={() => navigate('/agents')}
        style={{
          display: 'flex', alignItems: 'center', gap: '0.5rem',
          color: '#94a3b8', fontSize: '0.875rem', background: 'none',
          border: 'none', cursor: 'pointer', marginBottom: '1rem',
          padding: 0,
        }}
      >
        <ArrowLeft style={{ width: '1rem', height: '1rem' }} />
        Back to Agents
      </button>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem' }}>
        <div style={{
          width: '3rem', height: '3rem', borderRadius: '0.75rem',
          backgroundColor: `${statusColor}20`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Monitor style={{ width: '1.5rem', height: '1.5rem', color: statusColor }} />
        </div>
        <div>
          <h1 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'white' }}>{agent.hostname}</h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.25rem' }}>
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
              padding: '0.125rem 0.5rem', borderRadius: '9999px',
              backgroundColor: `${statusColor}20`, color: statusColor,
              fontSize: '0.75rem', fontWeight: 500,
            }}>
              {agent.status.charAt(0).toUpperCase() + agent.status.slice(1)}
            </span>
            <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
              Last seen: {formatDate(agent.last_heartbeat)}
            </span>
          </div>
        </div>
      </div>

      {/* Info grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
        <div style={cardStyle}>
          <h3 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#94a3b8', marginBottom: '1rem' }}>
            System Information
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div>
              <div style={labelStyle}>OS Version</div>
              <div style={valueStyle}>{agent.os_version || '-'}</div>
            </div>
            <div>
              <div style={labelStyle}>IP Address</div>
              <div style={valueStyle}>{agent.ip_address || '-'}</div>
            </div>
            <div>
              <div style={labelStyle}>Agent Version</div>
              <div style={valueStyle}>{agent.agent_version || '-'}</div>
            </div>
            <div>
              <div style={labelStyle}>Driver Version</div>
              <div style={valueStyle}>{agent.driver_version || '-'}</div>
            </div>
            <div>
              <div style={labelStyle}>Policy Version</div>
              <div style={valueStyle}>v{agent.policy_version}</div>
            </div>
            <div>
              <div style={labelStyle}>Registered</div>
              <div style={valueStyle}>{formatDate(agent.created_at)}</div>
            </div>
          </div>
        </div>

        <div style={cardStyle}>
          <h3 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#94a3b8', marginBottom: '1rem' }}>
            Group Assignment
          </h3>
          <select
            value={agent.group?.id || ''}
            onChange={(e) => handleGroupChange(e.target.value)}
            style={{
              width: '100%', padding: '0.5rem 0.75rem',
              backgroundColor: '#1e293b', border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '0.5rem', color: 'white', fontSize: '0.875rem',
              marginBottom: '1rem', appearance: 'none',
              backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%2394a3b8' d='M3 5l3 3 3-3'/%3E%3C/svg%3E")`,
              backgroundRepeat: 'no-repeat', backgroundPosition: 'right 0.75rem center',
              paddingRight: '2rem', cursor: 'pointer',
            }}
          >
            <option value="" style={{ backgroundColor: '#1e293b', color: '#94a3b8' }}>No group</option>
            {groups.map(g => (
              <option key={g.id} value={g.id} style={{ backgroundColor: '#1e293b', color: 'white' }}>{g.name}</option>
            ))}
          </select>

          <h3 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.75rem', marginTop: '1rem' }}>
            Capabilities
          </h3>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {agent.capabilities && Object.entries(agent.capabilities).map(([key, enabled]) => {
              const cap = CAPABILITY_ICONS[key];
              if (!cap || !enabled) return null;
              const Icon = cap.icon;
              return (
                <span key={key} style={{
                  display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
                  padding: '0.25rem 0.625rem', borderRadius: '0.375rem',
                  backgroundColor: 'rgba(99,102,241,0.1)', color: '#818cf8',
                  fontSize: '0.75rem',
                }}>
                  <Icon style={{ width: '0.75rem', height: '0.75rem' }} />
                  {cap.label}
                </span>
              );
            })}
            {(!agent.capabilities || Object.values(agent.capabilities).every(v => !v)) && (
              <span style={{ color: '#64748b', fontSize: '0.875rem' }}>No capabilities reported</span>
            )}
          </div>
        </div>
      </div>

      {/* Agent ID */}
      <div style={cardStyle}>
        <div style={labelStyle}>Agent ID</div>
        <div style={{ fontSize: '0.8125rem', color: '#94a3b8', fontFamily: 'monospace' }}>{agent.id}</div>
      </div>
    </div>
  );
}
