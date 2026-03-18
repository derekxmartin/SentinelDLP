/**
 * Global search dialog — searches across incidents, policies, users.
 * Opens with Ctrl+K or clicking the search bar.
 */

import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, ShieldAlert, FileText, Users, X } from 'lucide-react';
import api from '../api/client';

interface SearchHit {
  id: string;
  type: 'incident' | 'policy' | 'user';
  title: string;
  subtitle: string | null;
}

interface SearchResponse {
  query: string;
  total: number;
  results: SearchHit[];
}

const TYPE_ICONS = {
  incident: ShieldAlert,
  policy: FileText,
  user: Users,
};

const TYPE_COLORS = {
  incident: 'text-red-400',
  policy: 'text-indigo-400',
  user: 'text-green-400',
};

const TYPE_ROUTES = {
  incident: '/incidents',
  policy: '/policies',
  user: '/users',
};

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function GlobalSearch({ open, onClose }: Props) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchHit[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [loading, setLoading] = useState(false);

  // Keyboard shortcut: Ctrl+K
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        if (open) onClose();
        else {
          setQuery('');
          setResults([]);
        }
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, onClose]);

  // Search on query change (debounced)
  useEffect(() => {
    if (!query.trim()) {
      setResults([]);
      return;
    }

    const timeout = setTimeout(async () => {
      setLoading(true);
      try {
        const data = await api.get<SearchResponse>('/search', { q: query });
        setResults(data.results);
        setSelectedIndex(0);
      } catch {
        setResults([]);
      } finally {
        setLoading(false);
      }
    }, 200);

    return () => clearTimeout(timeout);
  }, [query]);

  const handleSelect = useCallback(
    (hit: SearchHit) => {
      onClose();
      setQuery('');
      navigate(`${TYPE_ROUTES[hit.type]}/${hit.id}`);
    },
    [navigate, onClose]
  );

  // Keyboard navigation
  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((i) => Math.min(i + 1, results.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === 'Enter' && results[selectedIndex]) {
      handleSelect(results[selectedIndex]);
    } else if (e.key === 'Escape') {
      onClose();
    }
  }

  if (!open) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 z-40"
        onClick={onClose}
      />

      {/* Dialog */}
      <div className="fixed top-[20%] left-1/2 -translate-x-1/2 w-full max-w-lg z-50">
        <div className="bg-[var(--color-surface-card)] border border-slate-700 rounded-xl shadow-2xl overflow-hidden">
          {/* Input */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-slate-700">
            <Search className="w-5 h-5 text-slate-400 shrink-0" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Search incidents, policies, users..."
              autoFocus
              className="flex-1 bg-transparent text-slate-50 placeholder-slate-500 outline-none text-sm"
            />
            <button onClick={onClose} className="text-slate-400 hover:text-slate-300">
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Results */}
          <div className="max-h-80 overflow-y-auto">
            {loading && (
              <div className="px-4 py-8 text-center text-sm text-slate-500">
                Searching...
              </div>
            )}

            {!loading && query && results.length === 0 && (
              <div className="px-4 py-8 text-center text-sm text-slate-500">
                No results for "{query}"
              </div>
            )}

            {!loading && results.map((hit, i) => {
              const Icon = TYPE_ICONS[hit.type];
              return (
                <button
                  key={`${hit.type}-${hit.id}`}
                  onClick={() => handleSelect(hit)}
                  className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                    i === selectedIndex
                      ? 'bg-[var(--color-accent)]/15'
                      : 'hover:bg-slate-700/50'
                  }`}
                >
                  <Icon className={`w-4 h-4 shrink-0 ${TYPE_COLORS[hit.type]}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-slate-200 truncate">{hit.title}</p>
                    {hit.subtitle && (
                      <p className="text-xs text-slate-500 truncate">{hit.subtitle}</p>
                    )}
                  </div>
                  <span className="text-xs text-slate-600 capitalize">{hit.type}</span>
                </button>
              );
            })}
          </div>

          {/* Footer hint */}
          <div className="px-4 py-2 border-t border-slate-700 text-xs text-slate-500 flex items-center gap-4">
            <span>↑↓ Navigate</span>
            <span>↵ Open</span>
            <span>Esc Close</span>
          </div>
        </div>
      </div>
    </>
  );
}
