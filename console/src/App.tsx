/**
 * AkesoDLP Console — root application component.
 *
 * Routes:
 *   /login  — Login page (public)
 *   /mfa    — MFA verification (public, requires challenge token)
 *   /       — Dashboard (protected)
 *   /incidents — Incidents list (protected)
 *   /policies  — Policy list (protected)
 *   /detection — Detection test (protected)
 *   /identifiers — Data identifiers (protected)
 *   /users  — User management (protected)
 *   /settings/network — Network monitor settings (protected)
 *   /reports — Report generation and export (protected)
 *   /risk — User risk scores (protected)
 *   /fingerprints — Document fingerprint management (protected)
 */

import { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';

import AuthGuard from './components/AuthGuard';
import CommandPalette from './components/CommandPalette';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Fingerprints from './pages/Fingerprints';
import Incidents from './pages/Incidents';
import IncidentSnapshot from './pages/IncidentSnapshot';
import Login from './pages/Login';
import MFAVerify from './pages/MFAVerify';
import NetworkSettings from './pages/NetworkSettings';
import Placeholder from './pages/Placeholder';
import Reports from './pages/Reports';
import UserRisk from './pages/UserRisk';
import Policies from './pages/Policies';
import PolicyEditor from './pages/PolicyEditor';

function ProtectedLayout() {
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);

  // Cmd+Shift+P / Ctrl+Shift+P
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'P') {
        e.preventDefault();
        setCommandPaletteOpen((prev) => !prev);
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <AuthGuard>
      <Layout />
      <CommandPalette
        open={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
      />
    </AuthGuard>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public routes */}
        <Route path="/login" element={<Login />} />
        <Route path="/mfa" element={<MFAVerify />} />

        {/* Protected routes — Layout renders <Outlet> for child pages */}
        <Route element={<ProtectedLayout />}>
          <Route index element={<Dashboard />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="incidents/:id" element={<IncidentSnapshot />} />
          <Route path="policies" element={<Policies />} />
          <Route path="policies/:id" element={<PolicyEditor />} />
          <Route path="detection" element={<Placeholder title="Detection" task="a future sprint" />} />
          <Route path="identifiers" element={<Placeholder title="Data Identifiers" task="a future sprint" />} />
          <Route path="users" element={<Placeholder title="Users" task="a future sprint" />} />
          <Route path="reports" element={<Reports />} />
          <Route path="risk" element={<UserRisk />} />
          <Route path="fingerprints" element={<Fingerprints />} />
          <Route path="settings/network" element={<NetworkSettings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
