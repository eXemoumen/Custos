"use client";

import { useState } from "react";
import { PromptItem } from "@/lib/types";
import {
  Wrench,
  AlertTriangle,
  ShieldCheck,
  X,
  Ban,
  Clock,
  Copy,
  Check,
  Terminal,
} from "lucide-react";

interface ApprovalCardProps {
  prompt: PromptItem;
  onRespond: (requestId: string, choice: string) => void;
  isProcessing?: boolean;
}

export function ApprovalCard({ prompt, onRespond, isProcessing = false }: ApprovalCardProps) {
  const [copied, setCopied] = useState(false);
  const riskScore = Math.round(prompt.risk * 100);

  const copyArgs = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(prompt.args, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy arguments to clipboard:", err);
    }
  };

  const getRiskConfig = () => {
    if (prompt.risk >= 0.8) {
      return {
        level: "CRITICAL ESCALATION",
        badge: "bg-[#ef4444]/15 text-[#dc2626] dark:text-[#ef4444] border-[#ef4444]/30",
        glow: "border-[#ef4444]/40 shadow-[0_8px_32px_-4px_rgba(239,68,68,0.2)]",
        meter: "bg-[#ef4444]",
      };
    }
    if (prompt.risk >= 0.5) {
      return {
        level: "HIGH RISK INTERCEPTION",
        badge: "bg-[#f59e0b]/15 text-[#d97706] dark:text-[#f59e0b] border-[#f59e0b]/30",
        glow: "border-[#f59e0b]/40 shadow-[0_8px_32px_-4px_rgba(245,158,11,0.2)]",
        meter: "bg-[#f59e0b]",
      };
    }
    return {
      level: "EVALUATION HOLD",
      badge: "bg-[#4f46e5]/15 text-[#4f46e5] dark:text-[#facc15] border-[#4f46e5]/30 dark:border-[#facc15]/30",
      glow: "border-[#4f46e5]/40 shadow-[0_8px_32px_-4px_rgba(79,70,229,0.2)]",
      meter: "bg-[#4f46e5] dark:bg-[#facc15]",
    };
  };

  const risk = getRiskConfig();

  return (
    <div className={`doppel-shell transition-all duration-300 ${risk.glow}`}>
      <div className="doppel-core p-6 flex flex-col gap-5">
        {/* Header Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[var(--border-color)]">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-[var(--bg-surface-elevated)] border border-[var(--border-color)] flex items-center justify-center text-[#4f46e5] dark:text-[#facc15]">
              <Terminal className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-bold text-[var(--text-primary)]">{prompt.tool}</span>
                <span className="text-[10px] font-mono text-[var(--text-muted)] bg-[var(--bg-surface-elevated)] px-2 py-0.5 rounded border border-[var(--border-color)]">
                  ID: {prompt.request_id.slice(0, 8)}
                </span>
              </div>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="text-[10px] uppercase font-mono tracking-widest text-[var(--text-secondary)]">
                  Target Operation
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3 self-end sm:self-center">
            {prompt.deadline_ms && (
              <div className="flex items-center gap-1.5 text-[11px] font-mono text-[var(--text-secondary)] bg-[var(--bg-surface-elevated)] px-2.5 py-1 rounded-lg border border-[var(--border-color)]">
                <Clock className="w-3.5 h-3.5 text-[#f59e0b] animate-pulse" />
                <span>Pending Hold</span>
              </div>
            )}
            <div className="flex items-center gap-2">
              <div className="w-16 h-1.5 rounded-full bg-[var(--border-color)] overflow-hidden hidden sm:block">
                <div
                  className={`h-full rounded-full ${risk.meter}`}
                  style={{ width: `${riskScore}%` }}
                />
              </div>
              <span
                className={`text-[11px] font-mono font-bold px-2.5 py-1 rounded-full border ${risk.badge}`}
              >
                {riskScore}% RISK
              </span>
            </div>
          </div>
        </div>

        {/* Security Reasoning Section */}
        <div className="p-4 rounded-xl bg-[var(--bg-surface-elevated)] border border-[var(--border-color)] flex items-start gap-3">
          <div className="w-6 h-6 rounded-lg bg-[#f59e0b]/15 border border-[#f59e0b]/30 flex items-center justify-center text-[#d97706] dark:text-[#f59e0b] flex-shrink-0 mt-0.5">
            <AlertTriangle className="w-3.5 h-3.5" />
          </div>
          <div className="flex-1">
            <div className="text-[10px] font-mono font-semibold uppercase tracking-wider text-[#d97706] dark:text-[#f59e0b] mb-1">
              Security Rationale // Gateway Escalation
            </div>
            <p className="text-xs text-[var(--text-primary)] leading-relaxed">
              {prompt.reasoning || "Evaluation escalated this sensitive operation for human authorization."}
            </p>
          </div>
        </div>

        {/* Intercepted Arguments Terminal Box */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500/40 border border-rose-500/60" />
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500/40 border border-amber-500/60" />
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/40 border border-emerald-500/60" />
              </div>
              <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-secondary)] font-semibold ml-2">
                Intercepted Arguments Payload
              </span>
            </div>
            <button
              onClick={copyArgs}
              className="btn-tactile inline-flex items-center gap-1 text-[10px] font-mono text-[var(--text-secondary)] hover:text-[var(--text-primary)] bg-[var(--bg-surface-elevated)] px-2 py-1 rounded border border-[var(--border-color)] cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="w-3 h-3 text-[#10b981]" />
                  <span className="text-[#10b981]">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" />
                  <span>Copy JSON</span>
                </>
              )}
            </button>
          </div>

          <pre className="bg-[var(--bg-base)] border border-[var(--border-color)] rounded-xl p-4 text-xs font-mono text-[#0891b2] dark:text-[#06b6d4] overflow-x-auto max-h-48 leading-relaxed shadow-inner">
            {JSON.stringify(prompt.args, null, 2)}
          </pre>
        </div>

        {/* Action Decision Control Bar */}
        <div className="flex flex-wrap items-center gap-3 pt-3 border-t border-[var(--border-color)]">
          {/* Authorize (Allow) */}
          <button
            onClick={() => onRespond(prompt.request_id, "allow")}
            disabled={isProcessing}
            className="btn-tactile group inline-flex items-center gap-2 pl-4 pr-1.5 py-1.5 rounded-full text-xs font-semibold bg-[#10b981] hover:bg-[#059669] text-white shadow-[0_2px_12px_rgba(16,185,129,0.3)] cursor-pointer disabled:opacity-50 transition-all"
          >
            <span className="font-bold tracking-tight">Authorize Call</span>
            <div className="w-6 h-6 rounded-full bg-white/20 text-white flex items-center justify-center group-hover:scale-105 transition-transform">
              <ShieldCheck className="w-3.5 h-3.5" />
            </div>
          </button>

          {/* Authorize Once */}
          <button
            onClick={() => onRespond(prompt.request_id, "allow_once")}
            disabled={isProcessing}
            className="btn-tactile group inline-flex items-center gap-2 pl-4 pr-1.5 py-1.5 rounded-full text-xs font-semibold bg-[var(--bg-surface-elevated)] hover:bg-[var(--border-color)] text-[var(--text-primary)] border border-[var(--border-color)] cursor-pointer disabled:opacity-50 transition-all"
          >
            <span>Allow Once</span>
            <div className="w-6 h-6 rounded-full bg-white/10 text-[var(--text-primary)] flex items-center justify-center group-hover:scale-105 transition-transform">
              <Clock className="w-3 h-3" />
            </div>
          </button>

          {/* Deny Call */}
          <button
            onClick={() => onRespond(prompt.request_id, "deny")}
            disabled={isProcessing}
            className="btn-tactile group inline-flex items-center gap-2 pl-4 pr-1.5 py-1.5 rounded-full text-xs font-semibold bg-[#ef4444]/15 hover:bg-[#ef4444]/25 text-[#dc2626] dark:text-[#ef4444] border border-[#ef4444]/30 cursor-pointer disabled:opacity-50 transition-all"
          >
            <span className="font-semibold">Deny Execution</span>
            <div className="w-6 h-6 rounded-full bg-[#ef4444]/20 text-[#dc2626] dark:text-[#ef4444] flex items-center justify-center group-hover:scale-105 transition-transform">
              <X className="w-3.5 h-3.5" />
            </div>
          </button>

          {/* Quarantine Agent */}
          <button
            onClick={() => onRespond(prompt.request_id, "quarantine")}
            disabled={isProcessing}
            className="btn-tactile group ml-auto inline-flex items-center gap-2 pl-4 pr-1.5 py-1.5 rounded-full text-xs font-semibold bg-[#8b5cf6]/15 hover:bg-[#8b5cf6]/25 text-[#7c3aed] dark:text-[#8b5cf6] border border-[#8b5cf6]/30 cursor-pointer disabled:opacity-50 transition-all"
          >
            <span className="font-semibold">Quarantine Agent</span>
            <div className="w-6 h-6 rounded-full bg-[#8b5cf6]/20 text-[#7c3aed] dark:text-[#8b5cf6] flex items-center justify-center group-hover:scale-105 transition-transform">
              <Ban className="w-3 h-3" />
            </div>
          </button>
        </div>
      </div>
    </div>
  );
}
