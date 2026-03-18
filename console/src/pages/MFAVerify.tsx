/**
 * MFA verification page — enter TOTP code after password login.
 */

import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { KeyRound } from 'lucide-react';
import { useAuthStore } from '../stores/authStore';
import useTitle from '../hooks/useTitle';

export default function MFAVerify() {
  const navigate = useNavigate();
  const verifyMfa = useAuthStore((s) => s.verifyMfa);
  const mfaChallengeToken = useAuthStore((s) => s.mfaChallengeToken);

  useTitle('MFA Verification');

  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Redirect if no challenge is active
  if (!mfaChallengeToken) {
    navigate('/login');
    return null;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await verifyMfa(code);
      navigate('/');
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Verification failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[var(--color-surface-page)] flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Icon */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-[var(--color-surface-card)] border border-slate-700 mb-4">
            <KeyRound className="w-7 h-7 text-[var(--color-accent)]" />
          </div>
          <h1 className="text-2xl font-semibold text-slate-50">Two-Factor Auth</h1>
          <p className="text-sm text-slate-400 mt-1">
            Enter the 6-digit code from your authenticator app
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <input
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              required
              autoFocus
              maxLength={6}
              pattern="\d{6}"
              className="w-full px-3 py-3 rounded-lg bg-[var(--color-surface-card)] border border-slate-600 text-slate-50 text-center text-2xl tracking-[0.5em] font-mono placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)] focus:border-transparent"
              placeholder="000000"
            />
          </div>

          {error && (
            <div className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-3 py-2">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || code.length !== 6}
            className="w-full py-2.5 rounded-lg bg-[var(--color-accent)] text-white font-medium hover:bg-indigo-400 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Verifying...' : 'Verify'}
          </button>

          <button
            type="button"
            onClick={() => navigate('/login')}
            className="w-full py-2 text-sm text-slate-400 hover:text-slate-300 transition-colors"
          >
            Back to login
          </button>
        </form>
      </div>
    </div>
  );
}
