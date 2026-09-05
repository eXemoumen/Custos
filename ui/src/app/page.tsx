"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { Header } from "@/components/Header";
import { TestGuardrailModal } from "@/components/TestGuardrailModal";
import { api } from "@/lib/api";
import { HealthStatus, AuditEventItem, Decision } from "@/lib/types";
import {
  ShieldAlert,
  Sliders,
  CheckCircle2,
  ArrowUpRight,
  Cpu,
  Lock,
  Terminal,
  Activity,
  ChevronRight,
} from "lucide-react";

export default function OverviewPage() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEventItem[]>([]);
  const [isTestModalOpen, setIsTestModalOpen] = useState(false);
  const [isRecompiling, setIsRecompiling] = useState(false);
  const [recompileMsg, setRecompileMsg] = useState<string | null>(null);
  const [greeting, setGreeting] = useState("Good evening");

  useEffect(() => {
    const hour = new Date().getHours();
    if (hour < 12) setGreeting("Good morning");
    else if (hour < 17) setGreeting("Good afternoon");
    else setGreeting("Good evening");
  }, []);

  const fetchData = async () => {
    try {
      const [h, a] = await Promise.all([
        api.getHealth().catch(() => null),
        api.getAuditEvents(10).catch(() => ({ events: [] })),
      ]);
      if (h) setHealth(h);
      if (a && a.events) setAuditEvents(a.events);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleRecompile = async () => {
    setIsRecompiling(true);
    try {
      const res = await api.recompileKB();
      setRecompileMsg(res.message);
      fetchData();
      setTimeout(() => setRecompileMsg(null), 4000);
    } catch (err) {
      console.error(err);
    } finally {
      setIsRecompiling(false);
    }
  };

  const formatTimeAgo = (ts?: number, ts_unix_ms?: number) => {
    const timeMs = ts_unix_ms || (ts ? ts * 1000 : null);
    if (!timeMs) return "just now";
    const diffSec = Math.max(1, Math.floor((Date.now() - timeMs) / 1000));
    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    return `${Math.floor(diffSec / 3600)}h ago`;
  };

  const totalCalls = health?.metrics?.total_calls ?? auditEvents.length;
  const totalAllowed = health?.metrics?.total_allowed ?? auditEvents.filter((e) => e.decision === "allow" || e.decision === "allow_once").length;
  const totalBlocked = health?.metrics?.total_blocked ?? auditEvents.filter((e) => e.decision === "deny" || e.decision === "quarantine").length;

  const displayDecisions = auditEvents;

  const getDecisionIconAndStyle = (decision: string) => {
    switch (decision) {
      case "allow":
      case "allow_once":
        return {
          symbol: "●",
          label: "ALLOW",
          color: "text-[#059669] dark:text-[#10b981]",
          bg: "bg-[#10b981]/15 border-[#10b981]/30",
        };
      case "deny":
        return {
          symbol: "●",
          label: "DENY",
          color: "text-[#dc2626] dark:text-[#ef4444]",
          bg: "bg-[#ef4444]/15 border-[#ef4444]/30",
        };
      case "prompt":
        return {
          symbol: "●",
          label: "PROMPT",
          color: "text-[#d97706] dark:text-[#f59e0b]",
          bg: "bg-[#f59e0b]/15 border-[#f59e0b]/30",
        };
      case "quarantine":
        return {
          symbol: "◆",
          label: "QUARANTINE",
          color: "text-[#7c3aed] dark:text-[#8b5cf6]",
          bg: "bg-[#8b5cf6]/15 border-[#8b5cf6]/30",
        };
      case "defer":
        return {
          symbol: "⚪",
          label: "DEFERRED",
          color: "text-[#71717a]",
          bg: "bg-[#71717a]/15 border-[#71717a]/30",
        };
      default:
        return {
          symbol: "🔵",
          label: "INFO",
          color: "text-[#0891b2] dark:text-[#06b6d4]",
          bg: "bg-[#06b6d4]/15 border-[#06b6d4]/30",
        };
    }
  };

  return (
    <div className="pb-16">
      <Header
        category="Control Plane"
        title="Overview"
        subtitle="Real-time agent permission gate & decision monitoring"
        onRecompile={handleRecompile}
        onOpenTestModal={() => setIsTestModalOpen(true)}
        isRecompiling={isRecompiling}
      />

      <div className="p-8 max-w-[1400px] mx-auto flex flex-col gap-8">
        {recompileMsg && (
          <div className="bg-[#10b981]/10 border border-[#10b981]/30 text-[#059669] dark:text-[#10b981] px-4 py-3 rounded-xl text-xs flex items-center gap-2 animate-in fade-in">
            <CheckCircle2 className="w-4 h-4 text-[#10b981]" />
            <span>{recompileMsg}</span>
          </div>
        )}

        {/* ASCII Section 1: Greeting */}
        <div>
          <h1 className="text-3xl font-extrabold text-[var(--text-primary)] tracking-tight">
            {greeting}
          </h1>
          <p className="text-sm font-medium text-[var(--text-secondary)] mt-1">
            Your agents are protected.
          </p>
        </div>

        {/* ASCII Section 2: Three Stat Boxes */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-5">
          {/* Card 1: Calls */}
          <div className="doppel-shell">
            <div className="doppel-core p-6 flex flex-col justify-between">
              <div className="text-3xl sm:text-4xl font-extrabold font-mono text-[var(--text-primary)] tracking-tight">
                {totalCalls.toLocaleString()}
              </div>
              <div className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)] mt-2 font-mono">
                Calls
              </div>
            </div>
          </div>

          {/* Card 2: Allowed */}
          <div className="doppel-shell border-[#10b981]/30">
            <div className="doppel-core p-6 flex flex-col justify-between">
              <div className="text-3xl sm:text-4xl font-extrabold font-mono text-[#059669] dark:text-[#10b981] tracking-tight">
                {totalAllowed.toLocaleString()}
              </div>
              <div className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)] mt-2 font-mono flex items-center justify-between">
                <span>Allowed</span>
                <span className="w-2.5 h-2.5 rounded-full bg-[#10b981]" />
              </div>
            </div>
          </div>

          {/* Card 3: Blocked */}
          <div className="doppel-shell border-[#ef4444]/30">
            <div className="doppel-core p-6 flex flex-col justify-between">
              <div className="text-3xl sm:text-4xl font-extrabold font-mono text-[#dc2626] dark:text-[#ef4444] tracking-tight">
                {totalBlocked.toLocaleString()}
              </div>
              <div className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)] mt-2 font-mono flex items-center justify-between">
                <span>Blocked</span>
                <span className="w-2.5 h-2.5 rounded-full bg-[#ef4444]" />
              </div>
            </div>
          </div>
        </div>

        {/* Pending Approvals Warning Banner if any held */}
        {Boolean(health?.gateway.pending_prompts && health.gateway.pending_prompts > 0) && (
          <Link
            href="/approvals"
            className="p-4 rounded-xl bg-[#f59e0b]/10 border border-[#f59e0b]/30 flex items-center justify-between btn-tactile group"
          >
            <div className="flex items-center gap-3">
              <ShieldAlert className="w-5 h-5 text-[#f59e0b] animate-bounce" />
              <div>
                <div className="text-xs font-bold text-[var(--text-primary)]">
                  {health?.gateway.pending_prompts} Tool Invocations Suspended
                </div>
                <div className="text-[11px] text-[var(--text-secondary)]">
                  Autonomous agents require human authorization before proceeding.
                </div>
              </div>
            </div>
            <div className="flex items-center gap-1.5 text-xs font-bold text-[#d97706] dark:text-[#f59e0b] font-mono">
              <span>Open Inbox</span>
              <ChevronRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
            </div>
          </Link>
        )}

        {/* ASCII Section 3: Recent Decisions Box */}
        <div className="doppel-shell">
          <div className="doppel-core p-6 flex flex-col gap-4">
            <div className="flex items-center justify-between pb-3 border-b border-[var(--border-color)]">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#4f46e5] dark:text-[#facc15]" />
                <h3 className="text-sm font-bold text-[var(--text-primary)] tracking-tight">
                  Recent decisions
                </h3>
              </div>
              <Link
                href="/decisions"
                className="text-xs font-mono font-semibold text-[#4f46e5] hover:text-[#4338ca] dark:text-[#facc15] dark:hover:text-yellow-300 inline-flex items-center gap-1 transition-colors"
              >
                <span>View all</span>
                <ArrowUpRight className="w-3 h-3" />
              </Link>
            </div>

            {/* Decision rows */}
            <div className="flex flex-col divide-y divide-[var(--border-color)]">
              {displayDecisions.length === 0 ? (
                <div className="py-10 text-center flex flex-col items-center justify-center gap-2">
                  <Activity className="w-6 h-6 text-[#71717a]" />
                  <span className="text-xs font-mono text-[var(--text-secondary)]">
                    No decisions recorded yet. Real-time agent tool invocations will stream here.
                  </span>
                  <button
                    onClick={() => setIsTestModalOpen(true)}
                    className="btn-tactile mt-1 text-xs font-mono font-semibold text-[#facc15] hover:underline cursor-pointer"
                  >
                    Simulate first tool invocation →
                  </button>
                </div>
              ) : (
                displayDecisions.map((item, idx) => {
                  const style = getDecisionIconAndStyle(item.decision);
                  return (
                    <div
                      key={idx}
                      className="py-3.5 px-2 flex items-center justify-between hover:bg-[var(--bg-surface-elevated)] rounded-lg transition-colors group"
                    >
                      <div className="flex items-center gap-4">
                        {/* Status indicator */}
                        <span className={`text-base font-bold ${style.color}`}>
                          {style.symbol}
                        </span>
                        <span
                          className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded border ${style.bg} ${style.color}`}
                        >
                          {style.label}
                        </span>

                        {/* Tool name */}
                        <span className="font-mono text-xs font-bold text-[var(--text-primary)] group-hover:text-[#4f46e5] dark:group-hover:text-[#facc15] transition-colors">
                          {item.tool}
                        </span>

                        {/* Context / Reason */}
                        {item.reasoning && (
                          <span className="text-xs text-[var(--text-secondary)] hidden md:inline truncate max-w-md">
                            — {item.reasoning}
                          </span>
                        )}
                      </div>

                      {/* Elapsed timestamp */}
                      <div className="text-[11px] font-mono text-[var(--text-muted)] group-hover:text-[var(--text-secondary)] transition-colors flex-shrink-0">
                        {formatTimeAgo(item.ts, item.ts_unix_ms)}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* Pipeline Architecture Stage Map */}
        <div className="p-5 rounded-2xl bg-[var(--bg-surface)] border border-[var(--border-color)] flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#10b981]" />
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)]">
                Gateway Security Architecture
              </span>
            </div>
            <span className="text-[11px] font-mono text-[var(--text-secondary)]">
              Floor: Zero-Trust Strict
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {[
              { num: "01", name: "Ingress", sub: "JSON-RPC / REST", icon: Terminal },
              { num: "02", name: "ABAC Policy", sub: "Deterministic", icon: Sliders },
              { num: "03", name: "Inspectors", sub: "A12 Signatures", icon: ShieldAlert },
              { num: "04", name: "Assistant", sub: "Local LLM Guard", icon: Cpu },
              { num: "05", name: "Human Gate", sub: "Live Approval", icon: CheckCircle2 },
              { num: "06", name: "Audit Trail", sub: "SHA-256 HMAC", icon: Lock },
            ].map((st, i) => {
              const Icon = st.icon;
              return (
                <div
                  key={i}
                  className="p-3.5 rounded-xl bg-[var(--bg-base)] border border-[var(--border-color)] flex flex-col justify-between gap-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono text-[var(--text-muted)] font-bold">
                      {st.num}
                    </span>
                    <Icon className="w-3.5 h-3.5 text-[#4f46e5] dark:text-[#facc15]" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-[var(--text-primary)]">{st.name}</div>
                    <div className="text-[10px] font-mono text-[var(--text-secondary)]">{st.sub}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <TestGuardrailModal
        isOpen={isTestModalOpen}
        onClose={() => setIsTestModalOpen(false)}
      />
    </div>
  );
}
