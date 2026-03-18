/**
 * Generic placeholder page for routes not yet implemented.
 */

import { Construction } from 'lucide-react';

export default function Placeholder({ title, task }: { title: string; task: string }) {
  return (
    <div>
      <h1 className="text-xl font-semibold text-slate-50 mb-6">{title}</h1>
      <div className="bg-[var(--color-surface-card)] border border-slate-700 rounded-xl p-8 text-center">
        <Construction className="w-10 h-10 text-slate-500 mx-auto mb-3" />
        <p className="text-slate-400">This page will be implemented in {task}.</p>
      </div>
    </div>
  );
}
