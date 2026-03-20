/**
 * Network Settings page (P5-T5).
 *
 * Allows admins to configure HTTP proxy and SMTP relay
 * DLP modes, thresholds, domain allowlist, and quarantine settings.
 */

import { useEffect, useState } from 'react';
import {
  Globe,
  Mail,
  Save,
  AlertTriangle,
  CheckCircle,
  Plus,
  X,
  RefreshCw,
} from 'lucide-react';
import useTitle from '../hooks/useTitle';
import api from '../api/client';

interface HttpProxySettings {
  mode: 'monitor' | 'prevent';
  blockThreshold: number;
  domainAllowlist: string[];
}

interface SmtpRelaySettings {
  mode: 'monitor' | 'prevent';
  upstreamHost: string;
  upstreamPort: number;
  blockThreshold: number;
  modifyThreshold: number;
  quarantineAddress: string;
}

interface NetworkSettings {
  httpProxy: HttpProxySettings;
  smtpRelay: SmtpRelaySettings;
}

const cardStyle: React.CSSProperties = {
  backgroundColor: 'var(--color-surface-card)',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '0.75rem',
  padding: '1.5rem',
};

const inputStyle: React.CSSProperties = {
  backgroundColor: 'rgba(0,0,0,0.2)',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: '0.5rem',
  padding: '0.5rem 0.75rem',
  color: 'var(--color-text-primary)',
  fontSize: '0.875rem',
  width: '100%',
  outline: 'none',
};

const labelStyle: React.CSSProperties = {
  fontSize: '0.75rem',
  fontWeight: 500,
  color: 'var(--color-text-secondary)',
  textTransform: 'uppercase' as const,
  letterSpacing: '0.05em',
  marginBottom: '0.375rem',
  display: 'block',
};

export default function NetworkSettings() {
  useTitle('Network Settings');

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const [http, setHttp] = useState<HttpProxySettings>({
    mode: 'monitor',
    blockThreshold: 1,
    domainAllowlist: [],
  });

  const [smtp, setSmtp] = useState<SmtpRelaySettings>({
    mode: 'monitor',
    upstreamHost: 'mailhog',
    upstreamPort: 1025,
    blockThreshold: 5,
    modifyThreshold: 1,
    quarantineAddress: 'quarantine@dlp.local',
  });

  const [newDomain, setNewDomain] = useState('');

  useEffect(() => {
    api.get<Record<string, unknown>>('/settings/network')
      .then((data) => {
        // Server returns snake_case keys
        const hp = (data.http_proxy ?? data.httpProxy) as Record<string, unknown> | undefined;
        const sr = (data.smtp_relay ?? data.smtpRelay) as Record<string, unknown> | undefined;
        if (hp) {
          setHttp({
            mode: (hp.mode as 'monitor' | 'prevent') ?? 'monitor',
            blockThreshold: (hp.block_threshold ?? hp.blockThreshold ?? 1) as number,
            domainAllowlist: (hp.domain_allowlist ?? hp.domainAllowlist ?? []) as string[],
          });
        }
        if (sr) {
          setSmtp({
            mode: (sr.mode as 'monitor' | 'prevent') ?? 'monitor',
            upstreamHost: (sr.upstream_host ?? sr.upstreamHost ?? 'mailhog') as string,
            upstreamPort: (sr.upstream_port ?? sr.upstreamPort ?? 1025) as number,
            blockThreshold: (sr.block_threshold ?? sr.blockThreshold ?? 5) as number,
            modifyThreshold: (sr.modify_threshold ?? sr.modifyThreshold ?? 1) as number,
            quarantineAddress: (sr.quarantine_address ?? sr.quarantineAddress ?? 'quarantine@dlp.local') as string,
          });
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (toast) {
      const t = setTimeout(() => setToast(null), 3000);
      return () => clearTimeout(t);
    }
  }, [toast]);

  async function handleSave() {
    setSaving(true);
    try {
      await api.put('/settings/network', {
        http_proxy: {
          mode: http.mode,
          block_threshold: http.blockThreshold,
          domain_allowlist: http.domainAllowlist,
        },
        smtp_relay: {
          mode: smtp.mode,
          upstream_host: smtp.upstreamHost,
          upstream_port: smtp.upstreamPort,
          block_threshold: smtp.blockThreshold,
          modify_threshold: smtp.modifyThreshold,
          quarantine_address: smtp.quarantineAddress,
        },
      });
      setToast({ type: 'success', message: 'Settings saved. Restart network services to apply.' });
    } catch {
      setToast({ type: 'error', message: 'Failed to save settings.' });
    } finally {
      setSaving(false);
    }
  }

  function addDomain() {
    const d = newDomain.trim().toLowerCase();
    if (d && !http.domainAllowlist.includes(d)) {
      setHttp({ ...http, domainAllowlist: [...http.domainAllowlist, d] });
      setNewDomain('');
    }
  }

  function removeDomain(domain: string) {
    setHttp({ ...http, domainAllowlist: http.domainAllowlist.filter((d) => d !== domain) });
  }

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '50vh' }}>
        <RefreshCw className="w-6 h-6 text-slate-400 animate-spin" />
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '56rem', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
            Network Settings
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginTop: '0.25rem' }}>
            Configure HTTP proxy and SMTP relay DLP inspection.
          </p>
        </div>
        <button
          onClick={handleSave}
          disabled={saving}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 1rem',
            borderRadius: '0.5rem',
            backgroundColor: 'var(--color-accent)',
            color: 'white',
            fontWeight: 500,
            fontSize: '0.875rem',
            border: 'none',
            cursor: saving ? 'not-allowed' : 'pointer',
            opacity: saving ? 0.6 : 1,
          }}
        >
          <Save className="w-4 h-4" />
          {saving ? 'Saving...' : 'Save Settings'}
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
            <CheckCircle className="w-4 h-4" style={{ color: '#22c55e' }} />
          ) : (
            <AlertTriangle className="w-4 h-4" style={{ color: '#ef4444' }} />
          )}
          <span style={{ fontSize: '0.875rem', color: 'var(--color-text-primary)' }}>{toast.message}</span>
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* HTTP Proxy */}
        <div style={cardStyle}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              width: '2rem', height: '2rem', borderRadius: '0.5rem',
              backgroundColor: 'rgba(59,130,246,0.15)',
            }}>
              <Globe className="w-4 h-4" style={{ color: '#3b82f6' }} />
            </div>
            <div>
              <h2 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                HTTP Proxy
              </h2>
              <p style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                Port 8080 — mitmproxy HTTPS inspection
              </p>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            {/* Mode toggle */}
            <div>
              <label style={labelStyle}>Mode</label>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                {(['monitor', 'prevent'] as const).map((m) => (
                  <button
                    key={m}
                    onClick={() => setHttp({ ...http, mode: m })}
                    style={{
                      flex: 1,
                      padding: '0.5rem',
                      borderRadius: '0.5rem',
                      fontSize: '0.875rem',
                      fontWeight: 500,
                      border: '1px solid',
                      borderColor: http.mode === m ? 'var(--color-accent)' : 'rgba(255,255,255,0.1)',
                      backgroundColor: http.mode === m ? 'rgba(var(--color-accent-rgb),0.15)' : 'transparent',
                      color: http.mode === m ? 'var(--color-accent)' : 'var(--color-text-secondary)',
                      cursor: 'pointer',
                      textTransform: 'capitalize',
                    }}
                  >
                    {m}
                  </button>
                ))}
              </div>
            </div>

            {/* Block threshold */}
            <div>
              <label style={labelStyle}>Block Threshold</label>
              <input
                type="number"
                min={1}
                max={100}
                value={http.blockThreshold}
                onChange={(e) => setHttp({ ...http, blockThreshold: parseInt(e.target.value) || 1 })}
                style={inputStyle}
              />
              <p style={{ fontSize: '0.7rem', color: 'var(--color-text-secondary)', marginTop: '0.25rem' }}>
                Minimum matches to trigger block (prevent mode)
              </p>
            </div>
          </div>

          {/* Domain allowlist */}
          <div style={{ marginTop: '1rem' }}>
            <label style={labelStyle}>Domain Allowlist</label>
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <input
                type="text"
                placeholder="example.com"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && addDomain()}
                style={{ ...inputStyle, flex: 1 }}
              />
              <button
                onClick={addDomain}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  width: '2.25rem', borderRadius: '0.5rem',
                  backgroundColor: 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  color: 'var(--color-text-secondary)',
                  cursor: 'pointer',
                }}
              >
                <Plus className="w-4 h-4" />
              </button>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
              {http.domainAllowlist.map((d) => (
                <span
                  key={d}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
                    padding: '0.25rem 0.625rem', borderRadius: '9999px',
                    backgroundColor: 'rgba(59,130,246,0.1)',
                    color: '#93c5fd', fontSize: '0.75rem',
                  }}
                >
                  {d}
                  <button
                    onClick={() => removeDomain(d)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: 'inherit', display: 'flex' }}
                  >
                    <X className="w-3 h-3" />
                  </button>
                </span>
              ))}
              {http.domainAllowlist.length === 0 && (
                <span style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                  No domains — all traffic will be inspected
                </span>
              )}
            </div>
          </div>
        </div>

        {/* SMTP Relay */}
        <div style={cardStyle}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              width: '2rem', height: '2rem', borderRadius: '0.5rem',
              backgroundColor: 'rgba(168,85,247,0.15)',
            }}>
              <Mail className="w-4 h-4" style={{ color: '#a855f7' }} />
            </div>
            <div>
              <h2 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                SMTP Relay
              </h2>
              <p style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                Port 2525 — email inspection relay
              </p>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            {/* Mode toggle */}
            <div>
              <label style={labelStyle}>Mode</label>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                {(['monitor', 'prevent'] as const).map((m) => (
                  <button
                    key={m}
                    onClick={() => setSmtp({ ...smtp, mode: m })}
                    style={{
                      flex: 1,
                      padding: '0.5rem',
                      borderRadius: '0.5rem',
                      fontSize: '0.875rem',
                      fontWeight: 500,
                      border: '1px solid',
                      borderColor: smtp.mode === m ? 'var(--color-accent)' : 'rgba(255,255,255,0.1)',
                      backgroundColor: smtp.mode === m ? 'rgba(var(--color-accent-rgb),0.15)' : 'transparent',
                      color: smtp.mode === m ? 'var(--color-accent)' : 'var(--color-text-secondary)',
                      cursor: 'pointer',
                      textTransform: 'capitalize',
                    }}
                  >
                    {m}
                  </button>
                ))}
              </div>
            </div>

            {/* Quarantine address */}
            <div>
              <label style={labelStyle}>Quarantine Address</label>
              <input
                type="text"
                value={smtp.quarantineAddress}
                onChange={(e) => setSmtp({ ...smtp, quarantineAddress: e.target.value })}
                style={inputStyle}
              />
            </div>

            {/* Block threshold */}
            <div>
              <label style={labelStyle}>Block Threshold</label>
              <input
                type="number"
                min={1}
                max={100}
                value={smtp.blockThreshold}
                onChange={(e) => setSmtp({ ...smtp, blockThreshold: parseInt(e.target.value) || 1 })}
                style={inputStyle}
              />
              <p style={{ fontSize: '0.7rem', color: 'var(--color-text-secondary)', marginTop: '0.25rem' }}>
                Matches to reject email (550)
              </p>
            </div>

            {/* Modify threshold */}
            <div>
              <label style={labelStyle}>Modify Threshold</label>
              <input
                type="number"
                min={1}
                max={100}
                value={smtp.modifyThreshold}
                onChange={(e) => setSmtp({ ...smtp, modifyThreshold: parseInt(e.target.value) || 1 })}
                style={inputStyle}
              />
              <p style={{ fontSize: '0.7rem', color: 'var(--color-text-secondary)', marginTop: '0.25rem' }}>
                Matches to add DLP headers / redirect
              </p>
            </div>

            {/* Upstream host */}
            <div>
              <label style={labelStyle}>Upstream MTA Host</label>
              <input
                type="text"
                value={smtp.upstreamHost}
                onChange={(e) => setSmtp({ ...smtp, upstreamHost: e.target.value })}
                style={inputStyle}
              />
            </div>

            {/* Upstream port */}
            <div>
              <label style={labelStyle}>Upstream MTA Port</label>
              <input
                type="number"
                min={1}
                max={65535}
                value={smtp.upstreamPort}
                onChange={(e) => setSmtp({ ...smtp, upstreamPort: parseInt(e.target.value) || 1025 })}
                style={inputStyle}
              />
            </div>
          </div>
        </div>

        {/* Info note */}
        <div style={{
          ...cardStyle,
          display: 'flex',
          alignItems: 'flex-start',
          gap: '0.75rem',
          borderColor: 'rgba(234,179,8,0.2)',
          backgroundColor: 'rgba(234,179,8,0.05)',
        }}>
          <AlertTriangle className="w-4 h-4 mt-0.5" style={{ color: '#eab308', flexShrink: 0 }} />
          <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
            <strong style={{ color: 'var(--color-text-primary)' }}>Restart required.</strong>{' '}
            Changes to network settings take effect after restarting the HTTP proxy and SMTP relay
            services via <code style={{ fontSize: '0.75rem', backgroundColor: 'rgba(255,255,255,0.05)', padding: '0.125rem 0.375rem', borderRadius: '0.25rem' }}>docker compose restart http-proxy smtp-relay</code>.
          </div>
        </div>
      </div>
    </div>
  );
}
