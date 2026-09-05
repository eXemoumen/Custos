"use client";

import { useState, useEffect } from "react";
import { Header } from "@/components/Header";
import { TestGuardrailModal } from "@/components/TestGuardrailModal";
import { api } from "@/lib/api";
import { AuditEventItem } from "@/lib/types";
import {
  CheckSquare,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Ban,
  Clock,
  Terminal,
  ChevronDown,
  ChevronRight,
} from "lucide-react";

export default function DecisionsPage() {
  const [events, setEvents] = useState<AuditEventItem[]>([]);
  const [filter, setFilter] = useState<string>("all");
  const [search, setSearch] = useState<string>("");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [isTestModalOpen, setIsTestModalOpen] = useState(false);

  const loadDecisions = () => {
    api.getAuditEvents(50).then((res) => {
      setEvents(res.events || []);
    }).catch(console.error);
  };

  useEffect(() => {
    loadDecisions();
    const interval = setInterval(loadDecisions, 3000);
    return () => clearInterval(interval);
  }, []);

  const filtered = events.filter((e) => {
    const matchFilter = filter === "all" || e.decision === filter;
    const matchSearch =
      search === "" ||
      (e.tool && e.tool.toLowerCase().includes(search.toLowerCase())) ||
      (e.reasoning && e.reasoning.toLowerCase().includes(search.toLowerCase()));
    return matchFilter && matchSearch;
  });

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case "allow":
      case "allow_once":
        return {
          label: "ALLOWED",
          color: "text-[#10b981] bg-[#10b981]/10 border-[#10b981]/30",
          icon: <CheckCircle2 className="w-3.5 h-3.5 text-[#10b981]" />,
        };
      case "deny":
        return {
          label: "DENIED",
          color: "text-[#ef4444] bg-[#ef4444]/10 border-[#ef4444]/30",
          icon: <XCircle className="w-3.5 h-3.5 text-[#ef4444]" />,
        };
      case "prompt":
        return {
          label: "PROMPT",
          color: "text-[#f59e0b] bg-[#f59e0b]/10 border-[#f59e0b]/30",
          icon: <AlertTriangle className="w-3.5 h-3.5 text-[#f59e0b]" />,
        };
      case "quarantine":
        return {
          label: "QUARANTINE",
          color: "text-[#8b5cf6] bg-[#8b5cf6]/10 border-[#8b5cf6]/30",
          icon: <Ban className="w-3.5 h-3.5 text-[#8b5cf6]" />,
        };
      default:
        return {
          label: decision.toUpperCase(),
          color: "text-[#64748b] bg-[#64748b]/10 border-[#64748b]/30",
          icon: <Clock className="w-3.5 h-3.5 text-[#64748b]" />,
        };
    }
  };

  return (
    <div className="pb-16">
      <Header
        category="Decision Log"
        title="Decisions"
        subtitle="Full stream of gateway permission evaluations and actions"
        onOpenTestModal={() => setIsTestModalOpen(true)}
      />

      <div className="p-8 max-w-[1400px] mx-auto flex flex-col gap-6">
        {/* Search & Filter bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="relative w-full sm:w-80">
            <Search className="w-3.5 h-3.5 text-[#94a3b8] absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search tool or rationale..."
              className="w-full bg-[#0f172a] border border-[#334155] rounded-xl pl-9 pr-3 py-2 text-xs text-[#f8fafc] placeholder-[#64748b] focus:outline-none focus:border-[#4f46e5]"
            />
          </div>

          <div className="flex items-center gap-1.5 p-1 rounded-xl bg-[#0f172a] border border-[#334155] self-start sm:self-auto overflow-x-auto">
            {["all", "allow", "deny", "prompt", "quarantine"].map((act) => (
              <button
                key={act}
                onClick={() => setFilter(act)}
                className={`btn-tactile px-3 py-1.5 rounded-lg text-xs font-mono font-medium capitalize cursor-pointer transition-all ${
                  filter === act
                    ? "bg-[#4f46e5] text-white font-bold"
                    : "text-[#94a3b8] hover:text-[#f8fafc]"
                }`}
              >
                {act}
              </button>
            ))}
          </div>
        </div>

        {/* Decision rows list */}
        <div className="doppel-shell">
          <div className="doppel-core p-6 flex flex-col gap-2">
            <div className="flex items-center justify-between pb-3 border-b border-[#334155]">
              <span className="text-xs font-mono font-semibold uppercase text-[#94a3b8]">
                Evaluated Actions ({filtered.length})
              </span>
              <span className="text-[11px] font-mono text-[#64748b]">
                Real-Time Enforced
              </span>
            </div>

            {filtered.length === 0 ? (
              <div className="py-12 text-center text-[#64748b] font-mono text-xs">
                No decisions recorded matching the current filter.
              </div>
            ) : (
              filtered.map((item, idx) => {
                const badge = getDecisionBadge(item.decision);
                const isExpanded = expandedId === idx;
                const ts = item.ts_unix_ms || (item.ts ? item.ts * 1000 : Date.now());

                return (
                  <div
                    key={idx}
                    className="border-b border-[#334155]/50 last:border-0 py-3.5 flex flex-col gap-2"
                  >
                    <div
                      onClick={() => setExpandedId(isExpanded ? null : idx)}
                      className="flex items-center justify-between cursor-pointer group"
                    >
                      <div className="flex items-center gap-3">
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4 text-[#94a3b8]" />
                        ) : (
                          <ChevronRight className="w-4 h-4 text-[#64748b] group-hover:text-[#94a3b8]" />
                        )}
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold border ${badge.color}`}
                        >
                          {badge.icon}
                          <span>{badge.label}</span>
                        </span>
                        <span className="font-mono text-xs font-bold text-[#f8fafc]">
                          {item.tool}
                        </span>
                        <span className="text-xs text-[#94a3b8] hidden md:inline truncate max-w-md">
                          {item.reasoning || item.assistant_reasoning || "-"}
                        </span>
                      </div>

                      <div className="text-[11px] font-mono text-[#64748b]">
                        {new Date(ts).toLocaleTimeString()}
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="ml-7 p-4 rounded-xl bg-[#020617] border border-[#334155] text-xs font-mono flex flex-col gap-2 animate-in fade-in">
                        <div className="text-[#94a3b8]">
                          <strong className="text-[#f8fafc]">Security Rationale: </strong>
                          <span>{item.reasoning || "Evaluation matched standard policy sequence."}</span>
                        </div>
                        {item.risk_score !== undefined && (
                          <div className="text-[#94a3b8]">
                            <strong className="text-[#f8fafc]">Assessed Risk: </strong>
                            <span>{Math.round(item.risk_score * 100)}%</span>
                          </div>
                        )}
                        <pre className="bg-[#0f172a] border border-[#334155] p-3 rounded-lg text-[11px] text-[#f8fafc] overflow-x-auto">
                          {JSON.stringify(item, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                );
              })
            )}
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
