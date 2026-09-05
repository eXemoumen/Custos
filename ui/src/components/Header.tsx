"use client";

import Link from "next/link";
import { RefreshCw, Play, Settings } from "lucide-react";

interface HeaderProps {
  title: string;
  subtitle: string;
  category?: string;
  onRecompile?: () => void;
  onOpenTestModal?: () => void;
  isRecompiling?: boolean;
}

export function Header({
  title,
  subtitle,
  category = "Security Operations",
  onRecompile,
  onOpenTestModal,
  isRecompiling = false,
}: HeaderProps) {
  return (
    <header className="px-8 py-4 border-b border-[var(--border-color)] bg-[var(--bg-base)]/85 backdrop-blur-xl sticky top-0 z-10 flex items-center justify-between">
      <div>
        <div className="flex items-center gap-2 mb-0.5">
          <span className="text-[10px] uppercase font-mono font-semibold tracking-wider text-[#facc15] bg-[#facc15]/10 px-2 py-0.5 rounded border border-[#facc15]/30">
            {category}
          </span>
        </div>
        <h2 className="text-lg font-bold text-[var(--text-primary)] tracking-tight">{title}</h2>
        <p className="text-xs text-[var(--text-secondary)]">{subtitle}</p>
      </div>

      <div className="flex items-center gap-3">
        {/* System Protected Pill from ASCII Diagram */}
        <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#10b981]/10 border border-[#10b981]/30 text-[#10b981] text-xs font-mono font-semibold">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#10b981] opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-[#10b981]" />
          </span>
          <span>System Protected</span>
        </div>

        {onRecompile && (
          <button
            onClick={onRecompile}
            disabled={isRecompiling}
            className="btn-tactile inline-flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-[var(--bg-surface)] hover:bg-[var(--bg-surface-elevated)] text-[var(--text-primary)] border border-[var(--border-color)] cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRecompiling ? "animate-spin text-[#facc15]" : "text-[var(--text-secondary)]"}`} />
            <span>{isRecompiling ? "Recompiling..." : "Recompile"}</span>
          </button>
        )}

        {onOpenTestModal && (
          <button
            onClick={onOpenTestModal}
            className="btn-tactile group inline-flex items-center gap-2 pl-3.5 pr-1.5 py-1.5 rounded-full text-xs font-semibold bg-[#4f46e5] hover:bg-[#4338ca] text-white shadow-[0_2px_12px_rgba(79,70,229,0.3)] cursor-pointer transition-all"
          >
            <span className="font-bold">Test Guardrail</span>
            <div className="w-5 h-5 rounded-full bg-white/20 text-white flex items-center justify-center group-hover:scale-105 transition-transform">
              <Play className="w-2.5 h-2.5 fill-white ml-0.5" />
            </div>
          </button>
        )}

        {/* Settings Gear from ASCII Diagram */}
        <Link
          href="/settings"
          className="btn-tactile p-2 rounded-xl bg-[var(--bg-surface)] hover:bg-[var(--bg-surface-elevated)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-[var(--border-color)] cursor-pointer transition-colors"
          title="Gateway Settings"
        >
          <Settings className="w-4 h-4" />
        </Link>
      </div>
    </header>
  );
}
