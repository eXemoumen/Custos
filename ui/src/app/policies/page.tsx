"use client";

import { useState, useEffect } from "react";
import { Header } from "@/components/Header";
import { TestGuardrailModal } from "@/components/TestGuardrailModal";
import { api } from "@/lib/api";
import { PolicyRuleItem } from "@/lib/types";
import {
  Sliders,
  Layers,
  Search,
  Lock,
  ArrowDown,
  ShieldAlert,
  ShieldCheck,
  Clock,
  Sparkles,
  Terminal,
} from "lucide-react";

export default function PoliciesPage() {
  const [rules, setRules] = useState<PolicyRuleItem[]>([]);
  const [defaultAction, setDefaultAction] = useState("deny");
  const [searchTerm, setSearchTerm] = useState("");
  const [actionFilter, setActionFilter] = useState<string>("all");
  const [isTestModalOpen, setIsTestModalOpen] = useState(false);

  useEffect(() => {
    api.getPolicies().then((res) => {
      setRules(res.rules || []);
      setDefaultAction(res.default || "deny");
    });
  }, []);

  const filteredRules = rules.filter((rule) => {
    const matchesSearch =
      searchTerm === "" ||
      JSON.stringify(rule.match).toLowerCase().includes(searchTerm.toLowerCase()) ||
      (rule.description && rule.description.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (rule.overlay_id && rule.overlay_id.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesAction = actionFilter === "all" || rule.action === actionFilter;

    return matchesSearch && matchesAction;
  });

  const getActionBadge = (action: string) => {
    if (action === "deny") {
      return {
        cls: "bg-rose-500/15 text-rose-300 border-rose-500/30",
        icon: <ShieldAlert className="w-3 h-3 text-rose-400" />,
      };
    }
    if (action === "allow") {
      return {
        cls: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
        icon: <ShieldCheck className="w-3 h-3 text-emerald-400" />,
      };
    }
    return {
      cls: "bg-amber-500/15 text-amber-300 border-amber-500/30",
      icon: <Clock className="w-3 h-3 text-amber-400" />,
    };
  };

  return (
    <div className="pb-16">
      <Header
        category="Access Control Engine"
        title="Policy Rule Matrix"
        subtitle="Compiled deterministic ABAC rules, overlay hierarchy, and first-match-wins pipeline"
        onOpenTestModal={() => setIsTestModalOpen(true)}
      />

      <div className="p-8 max-w-[1400px] mx-auto flex flex-col gap-6">
        {/* Policy Summary Architecture Banner */}
        <div className="doppel-shell">
          <div className="doppel-core p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shadow-[0_0_24px_rgba(59,130,246,0.1)]">
                <Sliders className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="font-bold text-base text-slate-100 tracking-tight">
                    Compiled Rule Sequence
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                    FIRST-MATCH-WINS
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1 max-w-xl leading-relaxed">
                  Every tool call is evaluated top-down against this deterministic rule list.
                  Knowledge Base overlays take precedence over base policy templates.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-4 self-end md:self-center">
              <div className="flex flex-col items-end">
                <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400">
                  Default Fallback Floor
                </span>
                <span className="mt-1 px-3 py-1 rounded-full text-xs font-mono font-bold bg-rose-500/15 text-rose-300 border border-rose-500/30">
                  {defaultAction.toUpperCase()} (Zero Trust)
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Filter & Search Controls */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="relative w-full sm:w-80">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search tool, glob pattern, or overlay ID..."
              className="w-full bg-white/[0.03] border border-white/[0.06] rounded-xl pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>

          <div className="inline-flex p-1 rounded-xl bg-white/[0.03] border border-white/[0.06] self-start sm:self-auto">
            {["all", "deny", "prompt", "allow"].map((act) => (
              <button
                key={act}
                onClick={() => setActionFilter(act)}
                className={`btn-tactile px-3 py-1 rounded-lg text-xs font-mono capitalize transition-all cursor-pointer ${
                  actionFilter === act
                    ? "bg-white/[0.08] text-white font-bold border border-white/[0.1]"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {act}
              </button>
            ))}
          </div>
        </div>

        {/* Visual Policy Pipeline Waterfall */}
        <div className="flex flex-col gap-3">
          {filteredRules.map((rule, idx) => {
            const badge = getActionBadge(rule.action);
            const isOverlay = Boolean(rule.overlay_id);

            return (
              <div key={idx} className="doppel-shell">
                <div className="doppel-core p-4.5 flex flex-col md:flex-row md:items-center justify-between gap-4">
                  {/* Left: Priority + Match */}
                  <div className="flex items-start md:items-center gap-3.5">
                    <span className="text-xs font-mono font-bold text-slate-500 bg-white/[0.03] px-2.5 py-1.5 rounded-lg border border-white/[0.06] flex-shrink-0">
                      #{String(idx + 1).padStart(2, "0")}
                    </span>

                    <span
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono font-bold uppercase tracking-wider border ${badge.cls}`}
                    >
                      {badge.icon}
                      <span>{rule.action}</span>
                    </span>

                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-xs text-cyan-300 font-semibold bg-cyan-950/30 px-2 py-0.5 rounded border border-cyan-500/20">
                          {JSON.stringify(rule.match)}
                        </span>
                      </div>
                      {rule.description && (
                        <span className="text-xs text-slate-400 leading-normal">
                          {rule.description}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Right: Layer Origin Source */}
                  <div className="flex items-center gap-2 self-end md:self-center">
                    <span
                      className={`text-[10px] font-mono px-2.5 py-1 rounded-md border ${
                        isOverlay
                          ? "bg-cyan-500/10 text-cyan-300 border-cyan-500/20"
                          : "bg-slate-800 text-slate-400 border-slate-700"
                      }`}
                    >
                      {isOverlay ? `overlay: ${rule.overlay_id}` : "base-policy"}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}

          {/* Terminal Fallback Floor Card */}
          <div className="doppel-shell border-rose-500/20 shadow-[0_8px_32px_-4px_rgba(244,63,94,0.1)]">
            <div className="doppel-core p-5 bg-rose-950/10 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400">
                  <Lock className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-rose-300">
                      STAGE 06: IMPENETRABLE DEFAULT FALLBACK FLOOR
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Any tool execution not explicitly matched by preceding rules hits this zero-trust terminal gate.
                  </p>
                </div>
              </div>

              <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                HARD DENY
              </span>
            </div>
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
