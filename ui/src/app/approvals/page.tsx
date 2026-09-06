"use client";

import { useState, useEffect } from "react";
import { Header } from "@/components/Header";
import { ApprovalCard } from "@/components/ApprovalCard";
import { TestGuardrailModal } from "@/components/TestGuardrailModal";
import { api } from "@/lib/api";
import { PromptItem } from "@/lib/types";
import {
  ShieldCheck,
  CheckCircle2,
  Radio,
  Clock,
  Terminal,
  Play,
  Activity,
} from "lucide-react";

export default function ApprovalsPage() {
  const [prompts, setPrompts] = useState<PromptItem[]>([]);
  const [isTestModalOpen, setIsTestModalOpen] = useState(false);
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  const fetchPrompts = async () => {
    try {
      const list = await api.getPrompts();
      setPrompts(list);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchPrompts();
    const interval = setInterval(fetchPrompts, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleRespond = async (requestId: string, choice: string) => {
    try {
      await api.respondPrompt(requestId, choice);
      setPrompts((prev) => prev.filter((p) => p.request_id !== requestId));
      setToastMsg(`Action '${choice.toUpperCase()}' dispatched successfully.`);
      setTimeout(() => setToastMsg(null), 3500);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : "Failed to resolve prompt");
    }
  };

  return (
    <div className="pb-16">
      <Header
        category="Human-in-the-Loop"
        title="Live Authorization Inbox"
        subtitle="Real-time intercept stream for high-risk autonomous agent tool executions"
        onOpenTestModal={() => setIsTestModalOpen(true)}
      />

      <div className="p-8 max-w-5xl mx-auto flex flex-col gap-6">
        {/* Status Strip */}
        <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-white/[0.02] border border-white/[0.06] text-xs">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400" />
              </span>
              <span className="font-mono text-slate-300 font-semibold">
                Intercept Listener // Active
              </span>
            </div>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400 font-mono text-[11px]">
              Protocol: WebSocket + SSE Fallback
            </span>
          </div>

          <div className="flex items-center gap-4 text-[11px] font-mono">
            <span className="text-slate-400">
              Held Calls:{" "}
              <strong className={prompts.length > 0 ? "text-amber-400 font-bold" : "text-emerald-400 font-bold"}>
                {prompts.length}
              </strong>
            </span>
            <span className="text-slate-400">
              Default Timeout: <strong className="text-slate-200">60s</strong>
            </span>
          </div>
        </div>

        {toastMsg && (
          <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 px-4 py-3 rounded-xl text-xs flex items-center gap-2 animate-in fade-in">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>{toastMsg}</span>
          </div>
        )}

        {prompts.length === 0 ? (
          /* High-End Zen / Radar Scanner Empty State */
          <div className="doppel-shell">
            <div className="doppel-core p-16 flex flex-col items-center justify-center text-center relative overflow-hidden">
              {/* Subtle background radar ring decor */}
              <div className="absolute w-72 h-72 rounded-full border border-cyan-500/10 pointer-events-none animate-pulse" />
              <div className="absolute w-96 h-96 rounded-full border border-cyan-500/5 pointer-events-none" />

              <div className="w-16 h-16 rounded-2xl bg-gradient-to-b from-emerald-500/15 to-emerald-500/5 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mb-5 shadow-[0_0_32px_rgba(16,185,129,0.1)]">
                <ShieldCheck className="w-8 h-8" />
              </div>

              <div className="flex items-center gap-2 mb-2">
                <span className="text-[10px] uppercase font-mono tracking-widest text-emerald-400 bg-emerald-500/10 px-2.5 py-0.5 rounded-full border border-emerald-500/20">
                  Perimeter Secure // Zero Invocations Held
                </span>
              </div>

              <h3 className="text-lg font-bold text-slate-100 tracking-tight">
                All Autonomous Tool Calls Clear
              </h3>
              <p className="text-xs text-slate-400 max-w-md mt-1.5 leading-relaxed">
                When an agent attempts a high-risk tool execution (e.g. destructive shell command,
                database drops, private network egress), the gateway immediately freezes execution
                and streams it here for your explicit authorization.
              </p>

              <div className="mt-6 flex items-center gap-3">
                <button
                  onClick={() => setIsTestModalOpen(true)}
                  className="btn-tactile group inline-flex items-center gap-2 pl-4 pr-1.5 py-1.5 rounded-full text-xs font-semibold bg-white/[0.04] hover:bg-white/[0.08] text-slate-200 border border-white/[0.08] cursor-pointer"
                >
                  <span>Simulate Tool Interception</span>
                  <div className="w-6 h-6 rounded-full bg-white/[0.08] text-slate-300 flex items-center justify-center group-hover:scale-105 transition-transform">
                    <Play className="w-2.5 h-2.5 fill-white ml-0.5" />
                  </div>
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            {prompts.map((prompt) => (
              <ApprovalCard
                key={prompt.request_id}
                prompt={prompt}
                onRespond={handleRespond}
              />
            ))}
          </div>
        )}
      </div>

      <TestGuardrailModal
        isOpen={isTestModalOpen}
        onClose={() => setIsTestModalOpen(false)}
      />
    </div>
  );
}
