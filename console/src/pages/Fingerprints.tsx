/**
 * Document Fingerprints management page (P6-T2).
 *
 * Upload confidential documents for simhash fingerprinting,
 * view indexed documents, and delete fingerprints.
 */

import { useEffect, useState, useRef } from 'react';
import {
  Fingerprint,
  Upload,
  Trash2,
  FileText,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Search,
} from 'lucide-react';
import useTitle from '../hooks/useTitle';
import api, { getAccessToken } from '../api/client';

interface FingerprintRecord {
  id: string;
  name: string;
  description: string;
  text_length: number;
  shingle_count: number;
  shingle_size: number;
  content_preview: string;
}

interface FingerprintListResponse {
  fingerprints: FingerprintRecord[];
  total: number;
}

const cardStyle: React.CSSProperties = {
  backgroundColor: 'var(--color-surface-card)',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '0.75rem',
  padding: '1.5rem',
};

export default function Fingerprints() {
  useTitle('Document Fingerprints');

  const [loading, setLoading] = useState(true);
  const [records, setRecords] = useState<FingerprintRecord[]>([]);
  const [uploading, setUploading] = useState(false);
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [description, setDescription] = useState('');
  const [docName, setDocName] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    loadFingerprints();
  }, []);

  useEffect(() => {
    if (toast) {
      const t = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(t);
    }
  }, [toast]);

  async function loadFingerprints() {
    try {
      const data = await api.get<FingerprintListResponse>('/fingerprints');
      setRecords(data.fingerprints);
    } catch {
      // Silently use empty list on error
    } finally {
      setLoading(false);
    }
  }

  async function handleUpload() {
    const file = fileInputRef.current?.files?.[0];
    if (!file) {
      setToast({ type: 'error', message: 'Select a file to upload.' });
      return;
    }

    setUploading(true);
    try {
      const form = new FormData();
      form.append('file', file);
      form.append('name', docName.trim() || file.name);
      form.append('description', description.trim());

      await fetch('/api/fingerprints/upload', {
        method: 'POST',
        body: form,
        headers: {
          'Authorization': `Bearer ${getAccessToken() || ''}`,
        },
      }).then(async (resp) => {
        if (!resp.ok) {
          const err = await resp.json().catch(() => ({ detail: 'Upload failed' }));
          throw new Error(err.detail || `Upload failed (${resp.status})`);
        }
      });

      setToast({ type: 'success', message: `Document "${docName.trim() || file.name}" fingerprinted successfully.` });
      setDocName('');
      setDescription('');
      if (fileInputRef.current) fileInputRef.current.value = '';
      await loadFingerprints();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Upload failed';
      setToast({ type: 'error', message });
    } finally {
      setUploading(false);
    }
  }

  async function handleDelete(id: string, name: string) {
    try {
      await api.delete(`/fingerprints/${id}`);
      setToast({ type: 'success', message: `Removed "${name}" from index.` });
      await loadFingerprints();
    } catch {
      setToast({ type: 'error', message: `Failed to delete "${name}".` });
    }
  }

  const filtered = records.filter(
    (r) =>
      r.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.description.toLowerCase().includes(searchQuery.toLowerCase()),
  );

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
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
          Document Fingerprints
        </h1>
        <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginTop: '0.25rem' }}>
          Index confidential documents for content matching via simhash fingerprinting.
        </p>
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
        {/* Upload card */}
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
                backgroundColor: 'rgba(34,197,94,0.15)',
              }}
            >
              <Upload className="w-4 h-4" style={{ color: '#22c55e' }} />
            </div>
            <div>
              <h2 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                Upload Document
              </h2>
              <p style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                Upload a text document to compute its fingerprint
              </p>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
            <div>
              <label style={labelStyle}>Document Name</label>
              <input
                type="text"
                placeholder="e.g. M&A Strategy Q2"
                value={docName}
                onChange={(e) => setDocName(e.target.value)}
                style={inputStyle}
              />
            </div>
            <div>
              <label style={labelStyle}>Description</label>
              <input
                type="text"
                placeholder="Optional description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                style={inputStyle}
              />
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end' }}>
            <div style={{ flex: 1 }}>
              <label style={labelStyle}>File</label>
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.md,.csv,.log,.json,.xml,.html,.rtf"
                style={{
                  ...inputStyle,
                  padding: '0.375rem 0.75rem',
                  cursor: 'pointer',
                }}
              />
            </div>
            <button
              onClick={handleUpload}
              disabled={uploading}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.5rem 1.25rem',
                borderRadius: '0.5rem',
                backgroundColor: '#22c55e',
                color: 'white',
                fontWeight: 500,
                fontSize: '0.875rem',
                border: 'none',
                cursor: uploading ? 'not-allowed' : 'pointer',
                opacity: uploading ? 0.6 : 1,
                whiteSpace: 'nowrap',
              }}
            >
              {uploading ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <Fingerprint className="w-4 h-4" />
              )}
              {uploading ? 'Processing...' : 'Fingerprint'}
            </button>
          </div>
        </div>

        {/* Indexed documents */}
        <div style={cardStyle}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: '1.25rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  width: '2rem',
                  height: '2rem',
                  borderRadius: '0.5rem',
                  backgroundColor: 'rgba(99,102,241,0.15)',
                }}
              >
                <FileText className="w-4 h-4" style={{ color: '#6366f1' }} />
              </div>
              <div>
                <h2 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  Indexed Documents
                </h2>
                <p style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                  {records.length} document{records.length !== 1 ? 's' : ''} indexed
                </p>
              </div>
            </div>

            {records.length > 0 && (
              <div style={{ position: 'relative' }}>
                <Search
                  className="w-4 h-4"
                  style={{
                    position: 'absolute',
                    left: '0.625rem',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    color: 'var(--color-text-secondary)',
                  }}
                />
                <input
                  type="text"
                  placeholder="Search..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{
                    ...inputStyle,
                    paddingLeft: '2rem',
                    width: '14rem',
                  }}
                />
              </div>
            )}
          </div>

          {filtered.length === 0 ? (
            <div
              style={{
                textAlign: 'center',
                padding: '2rem',
                color: 'var(--color-text-secondary)',
                fontSize: '0.875rem',
              }}
            >
              {records.length === 0
                ? 'No documents indexed yet. Upload a document above to get started.'
                : 'No documents match your search.'}
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {filtered.map((rec) => (
                <div
                  key={rec.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '0.75rem 1rem',
                    borderRadius: '0.5rem',
                    backgroundColor: 'rgba(0,0,0,0.15)',
                    border: '1px solid rgba(255,255,255,0.05)',
                  }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span
                        style={{
                          fontSize: '0.875rem',
                          fontWeight: 600,
                          color: 'var(--color-text-primary)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {rec.name}
                      </span>
                    </div>
                    {rec.description && (
                      <p
                        style={{
                          fontSize: '0.75rem',
                          color: 'var(--color-text-secondary)',
                          marginTop: '0.125rem',
                        }}
                      >
                        {rec.description}
                      </p>
                    )}
                    <div
                      style={{
                        display: 'flex',
                        gap: '1rem',
                        marginTop: '0.25rem',
                        fontSize: '0.7rem',
                        color: 'var(--color-text-secondary)',
                      }}
                    >
                      <span>{rec.text_length.toLocaleString()} chars</span>
                      <span>{rec.shingle_count.toLocaleString()} shingles</span>
                      <span
                        style={{
                          maxWidth: '20rem',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {rec.content_preview}
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={() => handleDelete(rec.id, rec.name)}
                    title="Remove from index"
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      width: '2rem',
                      height: '2rem',
                      borderRadius: '0.375rem',
                      backgroundColor: 'transparent',
                      border: '1px solid rgba(239,68,68,0.2)',
                      color: '#ef4444',
                      cursor: 'pointer',
                      flexShrink: 0,
                      marginLeft: '0.75rem',
                    }}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Info note */}
        <div
          style={{
            ...cardStyle,
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.75rem',
            borderColor: 'rgba(99,102,241,0.2)',
            backgroundColor: 'rgba(99,102,241,0.05)',
          }}
        >
          <Fingerprint className="w-4 h-4 mt-0.5" style={{ color: '#6366f1', flexShrink: 0 }} />
          <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
            <strong style={{ color: 'var(--color-text-primary)' }}>How it works.</strong>{' '}
            Documents are chunked into character n-grams and hashed using simhash. When content
            is scanned, its fingerprint is compared against the index — a similarity score above
            the threshold (default 40%) triggers a detection match.
          </div>
        </div>
      </div>
    </div>
  );
}


const labelStyle: React.CSSProperties = {
  fontSize: '0.75rem',
  fontWeight: 500,
  color: 'var(--color-text-secondary)',
  textTransform: 'uppercase' as const,
  letterSpacing: '0.05em',
  marginBottom: '0.375rem',
  display: 'block',
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
