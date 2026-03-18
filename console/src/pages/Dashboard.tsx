/**
 * Dashboard page — placeholder until P2-T8.
 */

import { ShieldAlert, FileText, Monitor, Activity } from 'lucide-react';
import useTitle from '../hooks/useTitle';

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: typeof ShieldAlert;
  label: string;
  value: string;
  color: string;
}) {
  return (
    <div className="bg-[var(--color-surface-card)] border border-slate-700 rounded-xl p-5">
      <div className="flex items-center gap-3 mb-3">
        <div className={`p-2 rounded-lg ${color}`}>
          <Icon className="w-4 h-4" />
        </div>
        <span className="text-sm text-slate-400">{label}</span>
      </div>
      <p className="text-2xl font-semibold text-slate-50">{value}</p>
    </div>
  );
}

export default function Dashboard() {
  useTitle('Dashboard');
  return (
    <div>
      <h1 className="text-xl font-semibold text-slate-50 mb-6">Dashboard</h1>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={ShieldAlert}
          label="Open Incidents"
          value="—"
          color="bg-red-500/10 text-red-400"
        />
        <StatCard
          icon={FileText}
          label="Active Policies"
          value="—"
          color="bg-indigo-500/10 text-indigo-400"
        />
        <StatCard
          icon={Monitor}
          label="Agents Online"
          value="—"
          color="bg-green-500/10 text-green-400"
        />
        <StatCard
          icon={Activity}
          label="Scans Today"
          value="—"
          color="bg-yellow-500/10 text-yellow-400"
        />
      </div>

      <div className="mt-8 bg-[var(--color-surface-card)] border border-slate-700 rounded-xl p-6">
        <p className="text-sm text-slate-400">
          Dashboard metrics and charts will be implemented in P2-T8.
        </p>
      </div>
    </div>
  );
}
