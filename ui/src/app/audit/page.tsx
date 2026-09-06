"use client";

import React, { useState, useEffect } from "react";
import { Header } from "@/components/Header";
import { TestGuardrailModal } from "@/components/TestGuardrailModal";
import { api } from "@/lib/api";
import { AuditEventItem } from "@/lib/types";
import {
  ShieldCheck,
  ShieldAlert,
  FileText,
  Search,
  Hash,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  Terminal,
  Lock,
  Radio,
} from "lucide-react";

export default function AuditPage() {
  const [events, setEvents] = useState<AuditEventItem[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("all");
  const [isTestModalOpen, setIsTestModalOpen] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const [verifyStatus, setVerifyStatus] = useState<{
    verified: boolean;
    message: string;
  } | null>(null);

  const loadAudit = async () => {
    try {
      const res = await api.getAuditEvents(100);
      setEvents(res.events || []);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    loadAudit();
  }, []);

  const handleVerify = async () => {
    setIsVerifying(true);
    try {
      const res = await api.verifyAudit();
      setVerifyStatus({
        verified: res.verified,
        message: res.message,
      });
      setTimeout(() => setVerifyStatus(null), 6000);
    } catch (err: unknown) {
      setVerifyStatus({
        verified: false,
        message: err instanceof Error ? err.message : "Verification failed",
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const filteredEvents = events.filter((e) => {
    const matchesSearch =
      searchTerm === "" ||
      (e.tool && e.tool.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (e.reasoning && e.reasoning.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (e.decision && e.decision.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesDecision =
      decisionFilter === "all" || e.decision === decisionFilter;

    return matchesSearch && matchesDecision;
  });

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case "deny":
        return "bg-rose-500/15 text-rose-300 border-rose-500/30";
      case "allow":
      case "allow_once":
        return "bg-emerald-500/15 text-emerald-300 border-emerald-500/30";
      case "quarantine":
        return "bg-purple-500/15 text-purple-300 border-purple-500/30";
      default:
        return "bg-amber-500/15 text-amber-300 border-amber-500/30";
    }
  };

  return (
    <div className="pb-16">
      <Header
        category="Cryptographic Provenance"
        title="Tamper-Evident Audit Ledger"
        subtitle="Hash-chained SHA-256 ledger recording every autonomous tool authorization"
        onOpenTestModal={() => setIsTestModalOpen(true)}
      />

      <div className="p-8 max-w-[1400px] mx-auto flex flex-col gap-6">
        {/* Verification Status Banner */}
        <div className="doppel-shell">
          <div className="doppel-core p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 shadow-[0_0_24px_rgba(16,185,129,0.1)]">
                <Lock className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="font-bold text-base text-slate-100 tracking-tight">
                    Cryptographic Hash-Chain Integrity
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                    SHA-256 HMAC
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1 max-w-xl leading-relaxed">
                  Every logged invocation contains the hash of its predecessor. Any manual
                  modification or truncation of the ledger breaks the cryptographic signature chain.
                </p>
              </div>
            </div>

            <button
              onClick={handleVerify}
              disabled={isVerifying}
              className="btn-tactile group inline-flex items-center gap-2.5 pl-4 pr-1.5 py-1.5 rounded-full text-xs font-semibold bg-white text-slate-950 hover:bg-slate-100 shadow-[0_4px_16px_rgba(255,255,255,0.12)] cursor-pointer disabled:opacity-50 self-start md:self-center"
            >
              <span className="font-bold">
                {isVerifying ? "Verifying Blocks..." : "Verify Hash Chain"}
              </span>
              <div className="w-6 h-6 rounded-full bg-slate-900 text-white flex items-center justify-center group-hover:scale-105 transition-transform">
                <ShieldCheck className="w-3 h-3 text-emerald-400" />
              </div>
            </button>
          </div>
        </div>

        {verifyStatus && (
          <div
            className={`px-4 py-3 rounded-xl text-xs flex items-center gap-2.5 animate-in fade-in border ${
              verifyStatus.verified
                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                : "bg-rose-500/10 border-rose-500/30 text-rose-300"
            }`}
          >
            {verifyStatus.verified ? (
              <ShieldCheck className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-rose-400 flex-shrink-0" />
            )}
            <span className="font-mono">{verifyStatus.message}</span>
          </div>
        )}

        {/* Filter and Search Bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="relative w-full sm:w-80">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search tool, decision, reasoning..."
              className="w-full bg-white/[0.03] border border-white/[0.06] rounded-xl pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>

          <div className="inline-flex p-1 rounded-xl bg-white/[0.03] border border-white/[0.06] self-start sm:self-auto">
            {["all", "deny", "allow", "prompt", "quarantine"].map((dec) => (
              <button
                key={dec}
                onClick={() => setDecisionFilter(dec)}
                className={`btn-tactile px-3 py-1 rounded-lg text-xs font-mono capitalize transition-all cursor-pointer ${
                  decisionFilter === dec
                    ? "bg-white/[0.08] text-white font-bold border border-white/[0.1]"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {dec}
              </button>
            ))}
          </div>
        </div>

        {/* Ledger Table Container */}
        <div className="doppel-shell">
          <div className="doppel-core p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-slate-100">
                  Immutable Audit Records ({filteredEvents.length} entries)
                </h3>
              </div>
              <span className="text-[11px] font-mono text-slate-400">
                Sorted by latest sequence
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-white/[0.06] text-slate-400 uppercase font-mono text-[10px] tracking-wider">
                    <th className="pb-3 px-3 w-8"></th>
                    <th className="pb-3 px-3">Timestamp</th>
                    <th className="pb-3 px-3">Tool Designation</th>
                    <th className="pb-3 px-3">Decision</th>
                    <th className="pb-3 px-3">Risk</th>
                    <th className="pb-3 px-3">Security Rationale</th>
                    <th className="pb-3 px-3 text-right">Hash Footprint</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.04]">
                  {filteredEvents.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-slate-500 font-mono text-xs">
                        No audit events match current criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredEvents.map((e, idx) => {
                      const ts = e.ts_unix_ms || (e.ts ? e.ts * 1000 : null);
                      const riskVal = e.risk_score ?? e.risk ?? 0;
                      const eventKey = e.hash || `${ts || idx}-${e.tool || "event"}-${idx}`;
                      const isExpanded = expandedId === eventKey;
                      const shortHash = e.hash ? e.hash.slice(0, 10) + "..." : "genesis";

                      return (
                        <React.Fragment key={eventKey}>
                          <tr
                            onClick={() => setExpandedId(isExpanded ? null : eventKey)}
                            className="hover:bg-white/[0.02] transition-colors cursor-pointer"
                          >
                            <td className="py-3 px-2 text-slate-500">
                              {isExpanded ? (
                                <ChevronDown className="w-3.5 h-3.5" />
                              ) : (
                                <ChevronRight className="w-3.5 h-3.5" />
                              )}
                            </td>
                            <td className="py-3 px-3 font-mono text-slate-400 text-[11px]">
                              {ts ? new Date(ts).toLocaleTimeString() : "N/A"}
                            </td>
                            <td className="py-3 px-3 font-mono text-cyan-300 font-semibold">
                              {e.tool || "N/A"}
                            </td>
                            <td className="py-3 px-3">
                              <span
                                className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider border ${getDecisionBadge(
                                  e.decision
                                )}`}
                              >
                                {e.decision}
                              </span>
                            </td>
                            <td className="py-3 px-3 font-mono text-slate-300">
                              {Math.round(riskVal * 100)}%
                            </td>
                            <td className="py-3 px-3 text-slate-300 max-w-sm truncate text-xs">
                              {e.reasoning || e.assistant_reasoning || e.policy_match || "-"}
                            </td>
                            <td className="py-3 px-3 text-right font-mono text-[10px] text-slate-500">
                              <span className="bg-black/30 px-2 py-0.5 rounded border border-white/[0.05]">
                                {shortHash}
                              </span>
                            </td>
                          </tr>

                          {/* Expanded Detail View */}
                          {isExpanded && (
                            <tr className="bg-black/40">
                              <td colSpan={7} className="p-4 border-b border-white/[0.06]">
                                <div className="flex flex-col gap-3 font-mono text-xs">
                                  <div className="flex items-center justify-between text-slate-400 pb-2 border-b border-white/[0.04]">
                                    <span>
                                      FULL AUDIT EVENT PAYLOAD // CRYPTOGRAPHIC BLOCK #
                                      {idx + 1}
                                    </span>
                                    <button
                                      onClick={(ev) => {
                                        ev.stopPropagation();
                                        copyToClipboard(JSON.stringify(e, null, 2), `event-${idx}`);
                                      }}
                                      className="btn-tactile inline-flex items-center gap-1.5 text-[10px] bg-white/[0.04] px-2.5 py-1 rounded border border-white/[0.06] text-slate-300 cursor-pointer"
                                    >
                                      {copiedHash === `event-${idx}` ? (
                                        <>
                                          <Check className="w-3 h-3 text-emerald-400" />
                                          <span className="text-emerald-400">Copied</span>
                                        </>
                                      ) : (
                                        <>
                                          <Copy className="w-3 h-3" />
                                          <span>Copy Record JSON</span>
                                        </>
                                      )}
                                    </button>
                                  </div>

                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-[11px]">
                                    <div>
                                      <span className="text-slate-500 block">Hash:</span>
                                      <span className="text-cyan-300 break-all">
                                        {e.hash || "Genesis Block"}
                                      </span>
                                    </div>
                                    <div>
                                      <span className="text-slate-500 block">Previous Hash:</span>
                                      <span className="text-slate-400 break-all">
                                        {e.prev_hash || "00000000000000000000"}
                                      </span>
                                    </div>
                                  </div>

                                  <pre className="bg-[#04060a] border border-white/[0.06] rounded-xl p-3.5 text-slate-300 text-xs overflow-x-auto max-h-56">
                                    {JSON.stringify(e, null, 2)}
                                  </pre>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })
                  )}
                </tbody>
              </table>
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
