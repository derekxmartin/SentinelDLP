/**
 * Main application layout with sidebar navigation.
 * Includes dark mode toggle, user menu, and global search.
 */

import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  FileText,
  Search,
  Users,
  LogOut,
  Sun,
  Moon,
  Monitor,
  Shield,
  ScanSearch,
  BookOpen,
  Bell,
} from 'lucide-react';
import { useAuthStore } from '../stores/authStore';
import { useThemeStore } from '../stores/themeStore';
import GlobalSearch from './GlobalSearch';
import { useState } from 'react';

const NAV_ITEMS = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/incidents', icon: ShieldAlert, label: 'Incidents' },
  { to: '/policies', icon: FileText, label: 'Policies' },
  { to: '/detection', icon: ScanSearch, label: 'Detection' },
  { to: '/identifiers', icon: BookOpen, label: 'Identifiers' },
  { to: '/users', icon: Users, label: 'Users' },
];

function ThemeToggle() {
  const { mode, setMode } = useThemeStore();

  const modes: Array<{ value: typeof mode; icon: typeof Sun; label: string }> = [
    { value: 'dark', icon: Moon, label: 'Dark' },
    { value: 'light', icon: Sun, label: 'Light' },
    { value: 'system', icon: Monitor, label: 'System' },
  ];

  return (
    <div className="flex items-center gap-1 p-1 rounded-lg bg-slate-800/50">
      {modes.map(({ value, icon: Icon, label }) => (
        <button
          key={value}
          onClick={() => setMode(value)}
          title={label}
          className={`p-1.5 rounded-md transition-colors ${
            mode === value
              ? 'bg-[var(--color-accent)] text-white'
              : 'text-slate-400 hover:text-slate-300'
          }`}
        >
          <Icon className="w-3.5 h-3.5" />
        </button>
      ))}
    </div>
  );
}

export default function Layout() {
  const navigate = useNavigate();
  const { user, logout } = useAuthStore();
  const [searchOpen, setSearchOpen] = useState(false);

  async function handleLogout() {
    await logout();
    navigate('/login');
  }

  return (
    <div className="flex h-screen bg-[var(--color-surface-page)]">
      {/* Sidebar */}
      <aside className="w-60 bg-[var(--color-surface-sidebar)] border-r border-slate-800 flex flex-col">
        {/* Logo */}
        <NavLink to="/" className="flex items-center gap-3 px-5 py-5 border-b border-slate-800 hover:bg-slate-800/50 transition-colors">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-[var(--color-accent)]">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <span className="text-lg font-semibold text-slate-50">SentinelDLP</span>
        </NavLink>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-[var(--color-accent)]/15 text-[var(--color-accent)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`
              }
            >
              <Icon className="w-4 h-4" />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="px-3 py-4 border-t border-slate-800 space-y-3">
          <ThemeToggle />

          {/* User info */}
          <div className="flex items-center gap-3 px-2">
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-slate-200 truncate">
                {user?.username}
              </p>
              <p className="text-xs text-slate-500 truncate">
                {user?.role.name}
              </p>
            </div>
            <button
              onClick={handleLogout}
              title="Sign out"
              className="p-1.5 rounded-md text-slate-400 hover:text-red-400 hover:bg-slate-800 transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <header className="flex items-center justify-between px-6 py-3 border-b border-slate-800 bg-[var(--color-surface-sidebar)]">
          {/* Search */}
          <button
            onClick={() => setSearchOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/50 border border-slate-700 text-slate-400 text-sm hover:text-slate-300 hover:border-slate-600 transition-colors w-72"
          >
            <Search className="w-4 h-4" />
            <span className="flex-1 text-left">Search...</span>
            <kbd className="text-xs bg-slate-700 px-1.5 py-0.5 rounded">
              Ctrl+K
            </kbd>
          </button>

          {/* Right side */}
          <div className="flex items-center gap-3">
            <button className="p-2 rounded-lg text-slate-400 hover:text-slate-300 hover:bg-slate-800 transition-colors relative">
              <Bell className="w-4 h-4" />
            </button>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>

      {/* Global search dialog */}
      <GlobalSearch open={searchOpen} onClose={() => setSearchOpen(false)} />
    </div>
  );
}
