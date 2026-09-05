"use client";

import { useState, useEffect } from "react";
import { Header } from "@/components/Header";
import { TestGuardrailModal } from "@/components/TestGuardrailModal";
import { api } from "@/lib/api";
import { AgentRecord } from "@/lib/types";
import {
  Bot,
  ShieldCheck,
  Ban,
  Activity,
  Play,
  CheckCircle2,
} from "lucide-react";

export default function AgentsPage() {
  const [isTestModalOpen, setIsTestModalOpen] = useState(false);
  const [agents, setAgents] = useState<AgentRecord[]>([]);
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  const loadAgents = async () => {
    try {
      const data = await api.getAgents();
      setAgents(data || []);
    } catch (err) {
      console.error("Failed to load agents:", err);
    }
  };

  useEffect(() => {
    loadAgents();
    const interval = setInterval(loadAgents, 4000);
    return () => clearInterval(interval);
  }, []);

  const toggleQuarantine = async (agentId: string, currentStatus: string) => {
    try {
      if (currentStatus === "quarantined") {
        await api.releaseAgent(agentId);
        setToastMsg(`Agent '${agentId}' released from quarantine.`);
      } else {
        await api.quarantineAgent(agentId);
        setToastMsg(`Agent '${agentId}' quarantined. All subsequent invocations will be blocked.`);
      }
      loadAgents();
      setTimeout(() => setToastMsg(null), 3500);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : "Failed to change quarantine status");
    }
  };

  const quarantinedCount = agents.filter((a) => a.status === "quarantined").length;

  return (
    <div className="pb-16">
      <Header
        category="Identity & Access"
        title="Agents"
        subtitle="Connected autonomous agents, permission profiles, and containment state"
        onOpenTestModal={() => setIsTestModalOpen(true)}
      />

      <div className="p-8 max-w-[1400px] mx-auto flex flex-col gap-6">
        {toastMsg && (
          <div className="bg-[#10b981]/10 border border-[#10b981]/30 text-[#10b981] px-4 py-3 rounded-xl text-xs flex items-center gap-2 animate-in fade-in">
            <CheckCircle2 className="w-4 h-4 text-[#10b981] flex-shrink-0" />
            <span>{toastMsg}</span>
          </div>
        )}

        {/* Top summary row */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-5">
          <div className="doppel-shell">
            <div className="doppel-core p-5 flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono font-semibold uppercase text-[var(--text-secondary)]">
                  Total Active Agents
                </span>
                <div className="text-3xl font-extrabold font-mono text-[var(--text-primary)] mt-1">
                  {agents.length}
                </div>
              </div>
              <div className="w-10 h-10 rounded-xl bg-[#4f46e5]/10 border border-[#4f46e5]/30 flex items-center justify-center text-[#4f46e5]">
                <Bot className="w-5 h-5" />
              </div>
            </div>
          </div>

          <div className="doppel-shell border-[#10b981]/30">
            <div className="doppel-core p-5 flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono font-semibold uppercase text-[var(--text-secondary)]">
                  Protected Perimeter
                </span>
                <div className="text-3xl font-extrabold font-mono text-[#10b981] mt-1">
                  {agents.length > 0 ? "100%" : "Armed"}
                </div>
              </div>
              <div className="w-10 h-10 rounded-xl bg-[#10b981]/10 border border-[#10b981]/30 flex items-center justify-center text-[#10b981]">
                <ShieldCheck className="w-5 h-5" />
              </div>
            </div>
          </div>

          <div className="doppel-shell border-[#8b5cf6]/30">
            <div className="doppel-core p-5 flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono font-semibold uppercase text-[var(--text-secondary)]">
                  Quarantined
                </span>
                <div className="text-3xl font-extrabold font-mono text-[#8b5cf6] mt-1">
                  {quarantinedCount}
                </div>
              </div>
              <div className="w-10 h-10 rounded-xl bg-[#8b5cf6]/10 border border-[#8b5cf6]/30 flex items-center justify-center text-[#8b5cf6]">
                <Ban className="w-5 h-5" />
              </div>
            </div>
          </div>
        </div>

        {/* Agents table card */}
        <div className="doppel-shell">
          <div className="doppel-core p-6">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-bold text-[var(--text-primary)]">
                  Registered Autonomous Agents
                </h3>
                <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                  Live agents communicating through the Custos gateway middleware
                </p>
              </div>
            </div>

            {agents.length === 0 ? (
              <div className="py-16 text-center flex flex-col items-center justify-center gap-3">
                <div className="w-12 h-12 rounded-xl bg-[#4f46e5]/10 border border-[#4f46e5]/20 flex items-center justify-center text-[#4f46e5]">
                  <Bot className="w-6 h-6" />
                </div>
                <div className="text-sm font-bold text-[var(--text-primary)]">
                  No Autonomous Agents Connected Yet
                </div>
                <p className="text-xs text-[var(--text-secondary)] max-w-md">
                  As agents execute tool calls through Custos (via REST, Python SDK, or LangChain/OpenAI integrations),
                  their identity, activity metrics, and containment status will be listed here.
                </p>
                <button
                  onClick={() => setIsTestModalOpen(true)}
                  className="btn-tactile mt-2 inline-flex items-center gap-2 px-4 py-2 rounded-full text-xs font-semibold bg-[#4f46e5] hover:bg-[#4338ca] text-white shadow-[0_2px_12px_rgba(79,70,229,0.3)] cursor-pointer"
                >
                  <Play className="w-3 h-3 fill-white" />
                  <span>Simulate Tool Invocation</span>
                </button>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-[var(--border-color)] text-[var(--text-secondary)] uppercase font-mono text-[10px] tracking-wider">
                      <th className="pb-3 px-3">Agent Name & ID</th>
                      <th className="pb-3 px-3">Framework</th>
                      <th className="pb-3 px-3">Status</th>
                      <th className="pb-3 px-3">Active Policy Profile</th>
                      <th className="pb-3 px-3">Calls</th>
                      <th className="pb-3 px-3">Last Active</th>
                      <th className="pb-3 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--border-color)]">
                    {agents.map((agent) => (
                      <tr key={agent.id} className="hover:bg-[var(--bg-surface-elevated)] transition-colors">
                        <td className="py-3.5 px-3">
                          <div className="font-semibold text-[var(--text-primary)]">{agent.name}</div>
                          <div className="font-mono text-[10px] text-[var(--text-muted)]">{agent.id}</div>
                        </td>
                        <td className="py-3.5 px-3 font-mono text-[var(--text-secondary)]">
                          {agent.framework}
                        </td>
                        <td className="py-3.5 px-3">
                          <span
                            className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider ${
                              agent.status === "quarantined"
                                ? "bg-[#8b5cf6]/15 text-[#8b5cf6] border border-[#8b5cf6]/30"
                                : "bg-[#10b981]/15 text-[#10b981] border border-[#10b981]/30"
                            }`}
                          >
                            {agent.status}
                          </span>
                        </td>
                        <td className="py-3.5 px-3 font-mono text-[#4f46e5] dark:text-[#facc15]">
                          {agent.policy_profile}
                        </td>
                        <td className="py-3.5 px-3 font-mono text-[var(--text-primary)]">
                          {agent.calls.toLocaleString()}
                        </td>
                        <td className="py-3.5 px-3 font-mono text-[var(--text-muted)]">
                          {agent.last_seen_ts ? new Date(agent.last_seen_ts * 1000).toLocaleTimeString() : "Just now"}
                        </td>
                        <td className="py-3.5 px-3 text-right">
                          <button
                            onClick={() => toggleQuarantine(agent.id, agent.status)}
                            className={`btn-tactile text-[11px] font-mono px-3 py-1 rounded-lg border cursor-pointer ${
                              agent.status === "quarantined"
                                ? "bg-[#10b981]/10 text-[#10b981] border-[#10b981]/30 hover:bg-[#10b981]/20"
                                : "bg-[#8b5cf6]/10 text-[#8b5cf6] border-[#8b5cf6]/30 hover:bg-[#8b5cf6]/20"
                            }`}
                          >
                            {agent.status === "quarantined" ? "Release" : "Quarantine"}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>

      <TestGuardrailModal
        isOpen={isTestModalOpen}
        onClose={() => {
          setIsTestModalOpen(false);
          loadAgents();
        }}
      />
    </div>
  );
}
