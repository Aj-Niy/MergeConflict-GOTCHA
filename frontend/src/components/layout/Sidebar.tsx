import { Link, useRouterState } from "@tanstack/react-router";
import {
  ShieldCheck,
  LayoutDashboard,
  Search,
  FileText,
  Clock,
  Settings,
  ChevronRight,
  Lock,
  Layers,
  FileCheck2,
} from "lucide-react";
import { cn } from "../../lib/utils";

const NAV_ITEMS = [
  { label: "Overview", icon: LayoutDashboard, to: "/overview" },
  { label: "Verify Scan", icon: Search, to: "/verify" },
  { label: "Trust Reports", icon: FileText, to: "/reports" },
  { label: "Batch Scanning", icon: Layers, to: "/batches" },
  { label: "Policy Builder", icon: Lock, to: "/policies" },
  { label: "Attestations", icon: FileCheck2, to: "/attestations" },
  { label: "History", icon: Clock, to: "/history" },
  { label: "Settings", icon: Settings, to: "/settings" },
];

export function Sidebar() {
  const router = useRouterState();
  const pathname = router.location.pathname;

  return (
    <aside className="flex h-screen w-60 flex-col border-r border-zinc-200 bg-white select-none">
      <div className="flex h-14 items-center gap-2.5 border-b border-zinc-200 px-4">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-indigo-600">
          <ShieldCheck className="h-4 w-4 text-white" strokeWidth={2.5} />
        </div>
        <span className="text-sm font-bold tracking-tight text-zinc-900">GOTCHA</span>
        <span className="ml-auto rounded bg-indigo-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-indigo-600">
          v2.0
        </span>
      </div>

      <nav className="flex-1 overflow-y-auto py-3 px-2">
        <ul className="flex flex-col gap-0.5">
          {NAV_ITEMS.map(({ label, icon: Icon, to }) => {
            const active = pathname === to || (to !== "/" && pathname.startsWith(to));
            return (
              <li key={to}>
                <Link
                  to={to}
                  className={cn(
                    "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors",
                    active
                      ? "bg-indigo-50 text-indigo-700 font-medium"
                      : "text-zinc-600 hover:bg-zinc-50 hover:text-zinc-900"
                  )}
                >
                  <Icon className={cn("h-4 w-4 shrink-0", active ? "text-indigo-600" : "text-zinc-400")} />
                  {label}
                  {active && <ChevronRight className="ml-auto h-3.5 w-3.5 text-indigo-400" />}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="border-t border-zinc-200 p-3">
        <div className="flex items-center gap-2.5 rounded-md px-2 py-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-full bg-zinc-900 text-[11px] font-semibold text-white">
            G
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-xs font-medium text-zinc-900">admin@gotcha.ai</p>
            <p className="text-[10px] text-zinc-400">Zero-Trust Active</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
