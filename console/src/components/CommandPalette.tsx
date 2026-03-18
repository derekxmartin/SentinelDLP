/**
 * Command palette — Cmd+Shift+P opens a list of quick actions.
 */

import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  FileText,
  Users,
  ScanSearch,
  BookOpen,
  Moon,
  Sun,
  LogOut,
  Command,
} from 'lucide-react';
import { useAuthStore } from '../stores/authStore';
import { useThemeStore } from '../stores/themeStore';

interface CommandItem {
  id: string;
  label: string;
  icon: typeof Command;
  action: () => void;
  category: string;
}

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function CommandPalette({ open, onClose }: Props) {
  const navigate = useNavigate();
  const logout = useAuthStore((s) => s.logout);
  const setTheme = useThemeStore((s) => s.setMode);

  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);

  const commands: CommandItem[] = [
    { id: 'nav-dashboard', label: 'Go to Dashboard', icon: LayoutDashboard, action: () => navigate('/'), category: 'Navigation' },
    { id: 'nav-incidents', label: 'Go to Incidents', icon: ShieldAlert, action: () => navigate('/incidents'), category: 'Navigation' },
    { id: 'nav-policies', label: 'Go to Policies', icon: FileText, action: () => navigate('/policies'), category: 'Navigation' },
    { id: 'nav-detection', label: 'Go to Detection', icon: ScanSearch, action: () => navigate('/detection'), category: 'Navigation' },
    { id: 'nav-identifiers', label: 'Go to Identifiers', icon: BookOpen, action: () => navigate('/identifiers'), category: 'Navigation' },
    { id: 'nav-users', label: 'Go to Users', icon: Users, action: () => navigate('/users'), category: 'Navigation' },
    { id: 'theme-dark', label: 'Switch to Dark Mode', icon: Moon, action: () => setTheme('dark'), category: 'Theme' },
    { id: 'theme-light', label: 'Switch to Light Mode', icon: Sun, action: () => setTheme('light'), category: 'Theme' },
    { id: 'auth-logout', label: 'Sign Out', icon: LogOut, action: () => { logout(); navigate('/login'); }, category: 'Account' },
  ];

  const filtered = query
    ? commands.filter((c) => c.label.toLowerCase().includes(query.toLowerCase()))
    : commands;

  const handleSelect = useCallback(
    (cmd: CommandItem) => {
      onClose();
      setQuery('');
      cmd.action();
    },
    [onClose]
  );

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((i) => Math.min(i + 1, filtered.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === 'Enter' && filtered[selectedIndex]) {
      handleSelect(filtered[selectedIndex]);
    } else if (e.key === 'Escape') {
      onClose();
    }
  }

  // Reset selection on query change
  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  if (!open) return null;

  // Group by category
  const categories = [...new Set(filtered.map((c) => c.category))];

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/60 z-50" onClick={onClose} />

      {/* Dialog */}
      <div className="fixed top-[20%] left-1/2 -translate-x-1/2 w-full max-w-md z-50">
        <div className="bg-[var(--color-surface-card)] border border-slate-700 rounded-xl shadow-2xl overflow-hidden">
          {/* Input */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-slate-700">
            <Command className="w-5 h-5 text-slate-400 shrink-0" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Type a command..."
              autoFocus
              className="flex-1 bg-transparent text-slate-50 placeholder-slate-500 outline-none text-sm"
            />
          </div>

          {/* Commands */}
          <div className="max-h-80 overflow-y-auto py-1">
            {categories.map((cat) => (
              <div key={cat}>
                <p className="px-4 py-1.5 text-xs font-medium text-slate-500 uppercase tracking-wider">
                  {cat}
                </p>
                {filtered
                  .filter((c) => c.category === cat)
                  .map((cmd) => {
                    const globalIdx = filtered.indexOf(cmd);
                    const Icon = cmd.icon;
                    return (
                      <button
                        key={cmd.id}
                        onClick={() => handleSelect(cmd)}
                        className={`w-full flex items-center gap-3 px-4 py-2 text-left transition-colors ${
                          globalIdx === selectedIndex
                            ? 'bg-[var(--color-accent)]/15 text-[var(--color-accent)]'
                            : 'text-slate-300 hover:bg-slate-700/50'
                        }`}
                      >
                        <Icon className="w-4 h-4 shrink-0" />
                        <span className="text-sm">{cmd.label}</span>
                      </button>
                    );
                  })}
              </div>
            ))}

            {filtered.length === 0 && (
              <div className="px-4 py-6 text-center text-sm text-slate-500">
                No commands match "{query}"
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="px-4 py-2 border-t border-slate-700 text-xs text-slate-500 flex items-center gap-4">
            <span>↑↓ Navigate</span>
            <span>↵ Run</span>
            <span>Esc Close</span>
          </div>
        </div>
      </div>
    </>
  );
}
