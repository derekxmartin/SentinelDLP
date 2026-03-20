/**
 * Login page with username/password form.
 * On MFA-enabled accounts, redirects to MFA verification.
 *
 * NOTE: Uses inline styles due to Tailwind v4 dev mode issue (see #22).
 */

import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { useAuthStore } from '../stores/authStore';
import useTitle from '../hooks/useTitle';

const inputStyle: React.CSSProperties = {
  display: 'block',
  width: '100%',
  borderRadius: '0.375rem',
  backgroundColor: 'rgba(255,255,255,0.05)',
  padding: '0.5rem 0.75rem',
  fontSize: '0.875rem',
  color: 'white',
  outline: '1px solid rgba(255,255,255,0.1)',
  outlineOffset: '-1px',
  border: 'none',
};

export default function Login() {
  const navigate = useNavigate();
  const login = useAuthStore((s) => s.login);

  useTitle('Sign In');

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const { mfaRequired } = await login(username, password);
      if (mfaRequired) {
        navigate('/mfa');
      } else {
        navigate('/');
      }
    } catch (err: unknown) {
      let message = 'Login failed';
      if (err && typeof err === 'object' && 'status' in err) {
        const apiErr = err as { status: number; detail: string };
        if (apiErr.status === 0) {
          message = apiErr.detail; // Network/server down — already descriptive
        } else if (apiErr.status === 401) {
          message = 'Invalid username or password';
        } else if (apiErr.status === 422) {
          message = 'Please enter both username and password';
        } else if (apiErr.status === 502 || apiErr.status === 503 || apiErr.status === 504) {
          message = 'API server is not running. Start it with: uvicorn server.main:app --port 8000';
        } else if (apiErr.status >= 500) {
          message = `Server error (${apiErr.status}). Check the server logs.`;
        } else {
          message = apiErr.detail || `Request failed (${apiErr.status})`;
        }
      } else if (err instanceof Error) {
        message = err.message;
      }
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  function handleFocus(e: React.FocusEvent<HTMLInputElement>) {
    e.target.style.outline = '2px solid #6366f1';
    e.target.style.outlineOffset = '-2px';
  }

  function handleBlur(e: React.FocusEvent<HTMLInputElement>) {
    e.target.style.outline = '1px solid rgba(255,255,255,0.1)';
    e.target.style.outlineOffset = '-1px';
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        backgroundColor: 'var(--color-surface-page)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        padding: '3rem 1.5rem',
      }}
    >
      {/* Header */}
      <div style={{ width: '100%', maxWidth: '24rem', textAlign: 'center' }}>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '2.5rem',
            height: '2.5rem',
            borderRadius: '0.5rem',
            backgroundColor: 'var(--color-accent)',
          }}
        >
          <Shield style={{ width: '1.25rem', height: '1.25rem', color: 'white' }} />
        </div>
        <h2
          style={{
            marginTop: '2.5rem',
            fontSize: '1.5rem',
            lineHeight: '2rem',
            fontWeight: 700,
            letterSpacing: '-0.025em',
            color: 'white',
          }}
        >
          Sign in to AkesoDLP
        </h2>
      </div>

      {/* Form */}
      <div style={{ marginTop: '2.5rem', width: '100%', maxWidth: '24rem' }}>
        <form
          onSubmit={handleSubmit}
          style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}
        >
          <div>
            <label
              htmlFor="username"
              style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, color: '#f3f4f6', marginBottom: '0.5rem' }}
            >
              Username
            </label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoFocus
              autoComplete="username"
              style={inputStyle}
              onFocus={handleFocus}
              onBlur={handleBlur}
            />
          </div>

          <div>
            <label
              htmlFor="password"
              style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, color: '#f3f4f6', marginBottom: '0.5rem' }}
            >
              Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
              style={inputStyle}
              onFocus={handleFocus}
              onBlur={handleBlur}
            />
          </div>

          {error && (
            <p style={{ fontSize: '0.875rem', color: '#f87171' }}>{error}</p>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              display: 'flex',
              width: '100%',
              justifyContent: 'center',
              borderRadius: '0.375rem',
              backgroundColor: '#6366f1',
              padding: '0.5rem 0.75rem',
              fontSize: '0.875rem',
              fontWeight: 600,
              color: 'white',
              border: 'none',
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.5 : 1,
            }}
            onMouseEnter={(e) => {
              if (!loading) (e.target as HTMLButtonElement).style.backgroundColor = '#818cf8';
            }}
            onMouseLeave={(e) => {
              (e.target as HTMLButtonElement).style.backgroundColor = '#6366f1';
            }}
          >
            {loading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>

        <p style={{ marginTop: '2.5rem', textAlign: 'center', fontSize: '0.875rem', color: '#9ca3af' }}>
          Akeso Security Suite &middot; v0.1.0
        </p>
      </div>
    </div>
  );
}
