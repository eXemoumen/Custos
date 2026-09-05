"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Bot,
  Sliders,
  CheckSquare,
  ShieldAlert,
  FileText,
  SearchCode,
  Settings,
  Shield,
  Radio,
} from "lucide-react";

interface SidebarProps {
  pendingCount?: number;
  isWsConnected?: boolean;
}

export function Sidebar({ pendingCount = 0, isWsConnected = true }: SidebarProps) {
  const pathname = usePathname();

  const navItems = [
    { name: "Overview", href: "/", icon: LayoutDashboard },
    { name: "Agents", href: "/agents", icon: Bot },
    { name: "Policies", href: "/policies", icon: Sliders },
    { name: "Decisions", href: "/decisions", icon: CheckSquare },
    { name: "Approvals", href: "/approvals", icon: ShieldAlert, badge: pendingCount },
    { name: "Audit", href: "/audit", icon: FileText },
    { name: "Inspectors", href: "/knowledge", icon: SearchCode },
    { name: "Settings", href: "/settings", icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[var(--bg-base)] border-r border-[var(--border-color)] flex flex-col h-screen sticky top-0 flex-shrink-0 z-20 transition-colors duration-250">
      {/* Brand Header */}
      <div className="p-5 border-b border-[var(--border-color)] flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-b from-[#4f46e5] to-[#4338ca] border border-white/[0.15] flex items-center justify-center shadow-[0_2px_10px_rgba(79,70,229,0.3)]">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-extrabold text-sm text-[var(--text-primary)] tracking-wider font-mono">
                CUSTOS
              </span>
            </div>
            <p className="text-[10px] font-medium text-[var(--text-secondary)] tracking-wider uppercase mt-0.5">
              Agent Security Gate
            </p>
          </div>
        </div>

        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#4f46e5]/10 text-[#4f46e5] dark:text-[#facc15] dark:bg-[#facc15]/10 border border-[#4f46e5]/30 dark:border-[#facc15]/30 font-semibold">
          v1.1
        </span>
      </div>

      {/* Navigation */}
      <nav className="p-3 flex-1 flex flex-col gap-1 overflow-y-auto">
        <div className="px-3 pt-2 pb-1 text-[10px] font-semibold text-[var(--text-muted)] uppercase tracking-widest font-mono">
          Security Platform
        </div>
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-medium transition-all duration-200 group btn-tactile ${
                isActive
                  ? "bg-[#4f46e5] text-white shadow-[0_2px_12px_rgba(79,70,229,0.35)] font-semibold"
                  : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-surface)] border border-transparent hover:border-[var(--border-color)]"
              }`}
            >
              <div
                className={`w-7 h-7 rounded-lg flex items-center justify-center transition-colors ${
                  isActive
                    ? "bg-white/15 text-white"
                    : "text-[var(--text-secondary)] group-hover:text-[var(--text-primary)]"
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
              </div>
              <span>{item.name}</span>

              {Boolean(item.badge && item.badge > 0) && (
                <span className="ml-auto bg-[#f59e0b] text-[#020617] text-[10px] font-mono font-bold px-2 py-0.5 rounded-full shadow-sm animate-pulse">
                  {item.badge}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Footer Status Panel */}
      <div className="p-3 m-3 rounded-xl bg-[var(--bg-surface)] border border-[var(--border-color)] flex items-center justify-between text-xs transition-colors">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            {isWsConnected && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#10b981] opacity-75" />
            )}
            <span
              className={`relative inline-flex rounded-full h-2 w-2 ${
                isWsConnected ? "bg-[#10b981]" : "bg-[#ef4444]"
              }`}
            />
          </span>
          <span className="text-[11px] font-mono text-[var(--text-secondary)]">
            {isWsConnected ? "System Protected" : "Gateway Offline"}
          </span>
        </div>
        <Radio className={`w-3.5 h-3.5 ${isWsConnected ? "text-[#10b981]" : "text-[#ef4444]"}`} />
      </div>
    </aside>
  );
}
