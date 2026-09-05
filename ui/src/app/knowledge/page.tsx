"use client";

import { useState, useEffect } from "react";
import { Header } from "@/components/Header";
import { TestGuardrailModal } from "@/components/TestGuardrailModal";
import { api } from "@/lib/api";
import {
  SensitiveAsset,
  GuardrailRule,
  ThreatPattern,
  AssetType,
  Decision,
} from "@/lib/types";
import {
  Plus,
  Trash2,
  CheckCircle2,
  Shield,
  FileCode,
  AlertOctagon,
  X,
  FileText,
  Globe,
  Radio,
  Database,
  KeyRound,
  Sparkles,
  ArrowUpRight,
  RefreshCw,
} from "lucide-react";

export default function KnowledgePage() {
  const [activeTab, setActiveTab] = useState<"assets" | "rules" | "threats">("assets");
  const [assets, setAssets] = useState<SensitiveAsset[]>([]);
  const [rules, setRules] = useState<GuardrailRule[]>([]);
  const [threats, setThreats] = useState<ThreatPattern[]>([]);
  const [isTestModalOpen, setIsTestModalOpen] = useState(false);
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const [isRecompiling, setIsRecompiling] = useState(false);

  // Modals
  const [isAddAssetOpen, setIsAddAssetOpen] = useState(false);
  const [isAddRuleOpen, setIsAddRuleOpen] = useState(false);
  const [isAddThreatOpen, setIsAddThreatOpen] = useState(false);

  // Form states
  const [assetName, setAssetName] = useState("");
  const [assetType, setAssetType] = useState<AssetType>("file_path");
  const [assetPattern, setAssetPattern] = useState("");
  const [assetAction, setAssetAction] = useState<Decision>("deny");

  const [ruleName, setRuleName] = useState("");
  const [ruleText, setRuleText] = useState("");
  const [ruleKeywords, setRuleKeywords] = useState("");
  const [ruleAction, setRuleAction] = useState<Decision>("prompt");

  const [threatName, setThreatName] = useState("");
  const [threatPattern, setThreatPattern] = useState("");
  const [threatDesc, setThreatDesc] = useState("");

  const loadData = async () => {
    try {
      const [a, r, t] = await Promise.all([
        api.getAssets(),
        api.getRules(),
        api.getThreats(),
      ]);
      setAssets(a);
      setRules(r);
      setThreats(t);
    } catch (err) {
      console.error("Failed to load KB data:", err);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRecompile = async () => {
    setIsRecompiling(true);
    try {
      const res = await api.recompileKB();
      setToastMsg(res.message);
      loadData();
      setTimeout(() => setToastMsg(null), 3500);
    } catch (err) {
      console.error(err);
    } finally {
      setIsRecompiling(false);
    }
  };

  // Quick Preset Handlers
  const applyAssetPreset = (name: string, type: AssetType, pattern: string, action: Decision) => {
    setAssetName(name);
    setAssetType(type);
    setAssetPattern(pattern);
    setAssetAction(action);
    setIsAddAssetOpen(true);
  };

  const applyRulePreset = (name: string, text: string, keywords: string, action: Decision) => {
    setRuleName(name);
    setRuleText(text);
    setRuleKeywords(keywords);
    setRuleAction(action);
    setIsAddRuleOpen(true);
  };

  const applyThreatPreset = (name: string, pattern: string, desc: string) => {
    setThreatName(name);
    setThreatPattern(pattern);
    setThreatDesc(desc);
    setIsAddThreatOpen(true);
  };

  const handleAddAsset = async () => {
    if (!assetName || !assetPattern) return;
    try {
      await api.createAsset({
        name: assetName,
        asset_type: assetType,
        pattern: assetPattern,
        action: assetAction,
        severity: "high",
        enabled: true,
      });
      setIsAddAssetOpen(false);
      setAssetName("");
      setAssetPattern("");
      loadData();
      setToastMsg("Protected asset registered and compiled to policy.");
      setTimeout(() => setToastMsg(null), 3000);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : "Failed to add asset");
    }
  };

  const handleDeleteAsset = async (id: string) => {
    if (!confirm("Are you sure you want to delete this protected asset?")) return;
    try {
      await api.deleteAsset(id);
      loadData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleAddRule = async () => {
    if (!ruleName || !ruleText) return;
    const kws = ruleKeywords.split(",").map((k) => k.trim()).filter(Boolean);
    try {
      await api.createRule({
        name: ruleName,
        natural_language_rule: ruleText,
        category: "general",
        action: ruleAction,
        severity: "high",
        target_tools: ["*"],
        keywords: kws,
        enabled: true,
      });
      setIsAddRuleOpen(false);
      setRuleName("");
      setRuleText("");
      setRuleKeywords("");
      loadData();
      setToastMsg("Natural language rule registered and compiled to policy.");
      setTimeout(() => setToastMsg(null), 3000);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : "Failed to add rule");
    }
  };

  const handleDeleteRule = async (id: string) => {
    if (!confirm("Delete this guardrail rule?")) return;
    try {
      await api.deleteRule(id);
      loadData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleAddThreat = async () => {
    if (!threatName || !threatPattern) return;
    try {
      await api.createThreat({
        name: threatName,
        pattern: threatPattern,
        is_regex: true,
        severity: "critical",
        description: threatDesc,
        action: "quarantine",
        enabled: true,
      });
      setIsAddThreatOpen(false);
      setThreatName("");
      setThreatPattern("");
      setThreatDesc("");
      loadData();
      setToastMsg("Threat pattern registered.");
      setTimeout(() => setToastMsg(null), 3000);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : "Failed to add threat");
    }
  };

  const handleDeleteThreat = async (id: string) => {
    if (!confirm("Delete this threat signature?")) return;
    try {
      await api.deleteThreat(id);
      loadData();
    } catch (err) {
      console.error(err);
    }
  };

  const getAssetTypeIcon = (type: AssetType) => {
    switch (type) {
      case "file_path":
        return <FileText className="w-3.5 h-3.5 text-cyan-400" />;
      case "domain":
        return <Globe className="w-3.5 h-3.5 text-blue-400" />;
      case "ip_network":
        return <Radio className="w-3.5 h-3.5 text-emerald-400" />;
      case "db_table":
        return <Database className="w-3.5 h-3.5 text-amber-400" />;
      case "regex":
        return <KeyRound className="w-3.5 h-3.5 text-rose-400" />;
    }
  };

  return (
    <div className="pb-16">
      <Header
        category="Knowledge Architecture"
        title="Knowledge Base Guardrails"
        subtitle="Manage sensitive assets, organizational safety rules, and threat signatures"
        onRecompile={handleRecompile}
        onOpenTestModal={() => setIsTestModalOpen(true)}
        isRecompiling={isRecompiling}
      />

      <div className="p-8 max-w-[1400px] mx-auto flex flex-col gap-6">
        {toastMsg && (
          <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 px-4 py-3 rounded-xl text-xs flex items-center gap-2 animate-in fade-in">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>{toastMsg}</span>
          </div>
        )}

        {/* Quick Preset Launchpad */}
        <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06] flex flex-col gap-2.5">
          <div className="flex items-center gap-2">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-300">
              Quick Guardrail Presets // One-Click Security Hardening
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() =>
                applyAssetPreset("Cloud Credentials Vault", "file_path", ".aws/credentials|.env*|.kube/config", "deny")
              }
              className="btn-tactile text-[11px] font-mono px-3 py-1.5 rounded-lg bg-white/[0.03] hover:bg-white/[0.07] border border-white/[0.06] text-slate-300 hover:text-white cursor-pointer"
            >
              + Cloud & Env Keys (.env*, .aws)
            </button>
            <button
              onClick={() =>
                applyAssetPreset("Private Infrastructure Subnets", "ip_network", "10.0.0.0/8|192.168.0.0/16|172.16.0.0/12", "deny")
              }
              className="btn-tactile text-[11px] font-mono px-3 py-1.5 rounded-lg bg-white/[0.03] hover:bg-white/[0.07] border border-white/[0.06] text-slate-300 hover:text-white cursor-pointer"
            >
              + RFC1918 Private Subnets
            </button>
            <button
              onClick={() =>
                applyRulePreset(
                  "Financial Transfer Ceiling",
                  "The agent must never initiate wire transfers, payment gateway refunds, or invoice disbursements above $500 without explicit human authorization.",
                  "transfer, refund, invoice, payout, payment, stripe",
                  "prompt"
                )
              }
              className="btn-tactile text-[11px] font-mono px-3 py-1.5 rounded-lg bg-white/[0.03] hover:bg-white/[0.07] border border-white/[0.06] text-slate-300 hover:text-white cursor-pointer"
            >
              + Financial Transaction Cap ($500+)
            </button>
            <button
              onClick={() =>
                applyThreatPreset(
                  "Prompt Injection Override",
                  "(?i)(ignore previous instructions|disregard all previous system rules|you are now DAN)",
                  "Detects jailbreak and direct system prompt override attempts"
                )
              }
              className="btn-tactile text-[11px] font-mono px-3 py-1.5 rounded-lg bg-white/[0.03] hover:bg-white/[0.07] border border-white/[0.06] text-slate-300 hover:text-white cursor-pointer"
            >
              + Prompt Injection Jailbreak Neutralizer
            </button>
          </div>
        </div>

        {/* Segmented Island Control for Tabs */}
        <div className="flex items-center justify-between">
          <div className="inline-flex p-1.5 rounded-2xl bg-white/[0.03] border border-white/[0.06] backdrop-blur-xl">
            <button
              onClick={() => setActiveTab("assets")}
              className={`btn-tactile inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold cursor-pointer transition-all ${
                activeTab === "assets"
                  ? "bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-[0_2px_12px_rgba(6,182,212,0.15)]"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Shield className="w-3.5 h-3.5" />
              <span>Sensitive Assets</span>
              <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-black/40 border border-white/[0.08]">
                {assets.length}
              </span>
            </button>

            <button
              onClick={() => setActiveTab("rules")}
              className={`btn-tactile inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold cursor-pointer transition-all ${
                activeTab === "rules"
                  ? "bg-blue-500/15 text-blue-300 border border-blue-500/30 shadow-[0_2px_12px_rgba(59,130,246,0.15)]"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Natural Language Rules</span>
              <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-black/40 border border-white/[0.08]">
                {rules.length}
              </span>
            </button>

            <button
              onClick={() => setActiveTab("threats")}
              className={`btn-tactile inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold cursor-pointer transition-all ${
                activeTab === "threats"
                  ? "bg-purple-500/15 text-purple-300 border border-purple-500/30 shadow-[0_2px_12px_rgba(168,85,247,0.15)]"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <AlertOctagon className="w-3.5 h-3.5" />
              <span>Threat Signatures (A12)</span>
              <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-black/40 border border-white/[0.08]">
                {threats.length}
              </span>
            </button>
          </div>

          <div>
            {activeTab === "assets" && (
              <button
                onClick={() => setIsAddAssetOpen(true)}
                className="btn-tactile group inline-flex items-center gap-2 pl-4 pr-1.5 py-1.5 rounded-full text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-[0_4px_16px_rgba(6,182,212,0.2)] cursor-pointer transition-all"
              >
                <span className="font-bold">Add Sensitive Asset</span>
                <div className="w-6 h-6 rounded-full bg-slate-950 text-cyan-400 flex items-center justify-center group-hover:scale-105 transition-transform">
                  <Plus className="w-3.5 h-3.5" />
                </div>
              </button>
            )}
            {activeTab === "rules" && (
              <button
                onClick={() => setIsAddRuleOpen(true)}
                className="btn-tactile group inline-flex items-center gap-2 pl-4 pr-1.5 py-1.5 rounded-full text-xs font-semibold bg-blue-500 hover:bg-blue-400 text-slate-950 shadow-[0_4px_16px_rgba(59,130,246,0.2)] cursor-pointer transition-all"
              >
                <span className="font-bold">Add Natural Rule</span>
                <div className="w-6 h-6 rounded-full bg-slate-950 text-blue-400 flex items-center justify-center group-hover:scale-105 transition-transform">
                  <Plus className="w-3.5 h-3.5" />
                </div>
              </button>
            )}
            {activeTab === "threats" && (
              <button
                onClick={() => setIsAddThreatOpen(true)}
                className="btn-tactile group inline-flex items-center gap-2 pl-4 pr-1.5 py-1.5 rounded-full text-xs font-semibold bg-purple-500 hover:bg-purple-400 text-slate-950 shadow-[0_4px_16px_rgba(168,85,247,0.2)] cursor-pointer transition-all"
              >
                <span className="font-bold">Add Threat Pattern</span>
                <div className="w-6 h-6 rounded-full bg-slate-950 text-purple-400 flex items-center justify-center group-hover:scale-105 transition-transform">
                  <Plus className="w-3.5 h-3.5" />
                </div>
              </button>
            )}
          </div>
        </div>

        {/* TAB 1: SENSITIVE ASSETS */}
        {activeTab === "assets" && (
          <div className="doppel-shell">
            <div className="doppel-core p-6">
              <div className="mb-4">
                <h3 className="text-sm font-bold text-slate-100 tracking-tight">
                  Protected Perimeter Boundaries
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  File globs, IP subnets, database tables, and secrets compiled into top-priority ABAC overlay blocks.
                </p>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-white/[0.06] text-slate-400 uppercase font-mono text-[10px] tracking-wider">
                      <th className="pb-3 px-3">Type</th>
                      <th className="pb-3 px-3">Asset Designation</th>
                      <th className="pb-3 px-3">Match Pattern</th>
                      <th className="pb-3 px-3">Enforcement</th>
                      <th className="pb-3 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.04]">
                    {assets.map((asset) => (
                      <tr key={asset.id} className="hover:bg-white/[0.02] transition-colors">
                        <td className="py-3.5 px-3">
                          <div className="flex items-center gap-2 font-mono text-slate-300">
                            {getAssetTypeIcon(asset.asset_type)}
                            <span className="text-[11px]">{asset.asset_type}</span>
                          </div>
                        </td>
                        <td className="py-3.5 px-3 font-semibold text-slate-200">
                          {asset.name}
                        </td>
                        <td className="py-3.5 px-3 font-mono text-cyan-300 text-[11px]">
                          {asset.pattern}
                        </td>
                        <td className="py-3.5 px-3">
                          <span
                            className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider ${
                              asset.action === "deny"
                                ? "bg-rose-500/15 text-rose-300 border border-rose-500/30"
                                : "bg-amber-500/15 text-amber-300 border border-amber-500/30"
                            }`}
                          >
                            {asset.action}
                          </span>
                        </td>
                        <td className="py-3.5 px-3 text-right">
                          <button
                            onClick={() => handleDeleteAsset(asset.id)}
                            className="btn-tactile text-slate-500 hover:text-rose-400 p-1.5 rounded-lg hover:bg-rose-500/10 cursor-pointer"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: NATURAL LANGUAGE RULES */}
        {activeTab === "rules" && (
          <div className="doppel-shell">
            <div className="doppel-core p-6">
              <div className="mb-4">
                <h3 className="text-sm font-bold text-slate-100 tracking-tight">
                  Organizational Safety Guidelines
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Natural language constitutional directives evaluated by the local Ollama LLM / Constitution Assistant.
                </p>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-white/[0.06] text-slate-400 uppercase font-mono text-[10px] tracking-wider">
                      <th className="pb-3 px-3">Rule Name</th>
                      <th className="pb-3 px-3">Plain English Directive</th>
                      <th className="pb-3 px-3">Fast Filter Keywords</th>
                      <th className="pb-3 px-3">Action</th>
                      <th className="pb-3 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.04]">
                    {rules.map((rule) => (
                      <tr key={rule.id} className="hover:bg-white/[0.02] transition-colors">
                        <td className="py-3.5 px-3 font-semibold text-slate-200">
                          {rule.name}
                        </td>
                        <td className="py-3.5 px-3 text-slate-300 max-w-md leading-relaxed">
                          {rule.natural_language_rule}
                        </td>
                        <td className="py-3.5 px-3 font-mono text-slate-400">
                          <div className="flex flex-wrap gap-1">
                            {rule.keywords.map((kw, i) => (
                              <span
                                key={i}
                                className="bg-white/[0.03] border border-white/[0.06] text-[10px] px-1.5 py-0.5 rounded text-slate-300"
                              >
                                {kw}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="py-3.5 px-3">
                          <span
                            className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider ${
                              rule.action === "deny"
                                ? "bg-rose-500/15 text-rose-300 border border-rose-500/30"
                                : "bg-amber-500/15 text-amber-300 border border-amber-500/30"
                            }`}
                          >
                            {rule.action}
                          </span>
                        </td>
                        <td className="py-3.5 px-3 text-right">
                          <button
                            onClick={() => handleDeleteRule(rule.id)}
                            className="btn-tactile text-slate-500 hover:text-rose-400 p-1.5 rounded-lg hover:bg-rose-500/10 cursor-pointer"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: THREAT SIGNATURES */}
        {activeTab === "threats" && (
          <div className="doppel-shell">
            <div className="doppel-core p-6">
              <div className="mb-4">
                <h3 className="text-sm font-bold text-slate-100 tracking-tight">
                  Indirect Prompt Injection & Attack Signatures (A12)
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Zero-latency regex inspection. Matches trigger instant agent quarantine and context scrub.
                </p>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-white/[0.06] text-slate-400 uppercase font-mono text-[10px] tracking-wider">
                      <th className="pb-3 px-3">Signature Name</th>
                      <th className="pb-3 px-3">Regex Pattern</th>
                      <th className="pb-3 px-3">Threat Description</th>
                      <th className="pb-3 px-3">Action</th>
                      <th className="pb-3 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.04]">
                    {threats.map((threat) => (
                      <tr key={threat.id} className="hover:bg-white/[0.02] transition-colors">
                        <td className="py-3.5 px-3 font-semibold text-slate-200">
                          {threat.name}
                        </td>
                        <td className="py-3.5 px-3 font-mono text-purple-300 text-[11px]">
                          {threat.pattern}
                        </td>
                        <td className="py-3.5 px-3 text-slate-400 max-w-sm">
                          {threat.description || "Active jailbreak signature"}
                        </td>
                        <td className="py-3.5 px-3">
                          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider bg-purple-500/15 text-purple-300 border border-purple-500/30">
                            {threat.action}
                          </span>
                        </td>
                        <td className="py-3.5 px-3 text-right">
                          <button
                            onClick={() => handleDeleteThreat(threat.id)}
                            className="btn-tactile text-slate-500 hover:text-rose-400 p-1.5 rounded-lg hover:bg-rose-500/10 cursor-pointer"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Add Asset Modal */}
      {isAddAssetOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="doppel-shell max-w-md w-full animate-in zoom-in-95 duration-150">
            <div className="doppel-core p-6">
              <div className="flex items-center justify-between pb-4 border-b border-white/[0.06]">
                <h3 className="font-bold text-sm text-slate-100">Register Protected Asset</h3>
                <button
                  onClick={() => setIsAddAssetOpen(false)}
                  className="btn-tactile text-slate-400 hover:text-white p-1 rounded-lg hover:bg-white/[0.05]"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="flex flex-col gap-3.5 my-5">
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">Asset Name</label>
                  <input
                    value={assetName}
                    onChange={(e) => setAssetName(e.target.value)}
                    placeholder="e.g. AWS Production Keys"
                    className="w-full bg-[#04060a] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">Asset Type</label>
                  <select
                    value={assetType}
                    onChange={(e) => setAssetType(e.target.value as AssetType)}
                    className="w-full bg-[#04060a] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="file_path">File Path / Glob</option>
                    <option value="ip_network">IP / Subnet</option>
                    <option value="domain">Domain</option>
                    <option value="db_table">Database Table</option>
                    <option value="regex">Regex Pattern</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">
                    Pattern (pipe-separated for multiples: a|b)
                  </label>
                  <input
                    value={assetPattern}
                    onChange={(e) => setAssetPattern(e.target.value)}
                    placeholder="e.g. .env|.aws/credentials"
                    className="w-full bg-[#04060a] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">Enforcement Action</label>
                  <select
                    value={assetAction}
                    onChange={(e) => setAssetAction(e.target.value as Decision)}
                    className="w-full bg-[#04060a] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="deny">Deny (Hard Intercept)</option>
                    <option value="prompt">Prompt (Require Human Approval)</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-2.5 pt-4 border-t border-white/[0.06]">
                <button
                  onClick={() => setIsAddAssetOpen(false)}
                  className="btn-tactile px-4 py-2 rounded-xl text-xs bg-white/[0.04] hover:bg-white/[0.08] text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  onClick={handleAddAsset}
                  className="btn-tactile px-5 py-2 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-[0_2px_12px_rgba(6,182,212,0.2)] cursor-pointer"
                >
                  Save Asset
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add Rule Modal */}
      {isAddRuleOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="doppel-shell max-w-md w-full animate-in zoom-in-95 duration-150">
            <div className="doppel-core p-6">
              <div className="flex items-center justify-between pb-4 border-b border-white/[0.06]">
                <h3 className="font-bold text-sm text-slate-100">Add Natural Language Rule</h3>
                <button
                  onClick={() => setIsAddRuleOpen(false)}
                  className="btn-tactile text-slate-400 hover:text-white p-1 rounded-lg hover:bg-white/[0.05]"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="flex flex-col gap-3.5 my-5">
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">Rule Name</label>
                  <input
                    value={ruleName}
                    onChange={(e) => setRuleName(e.target.value)}
                    placeholder="e.g. Financial Transfer Cap"
                    className="w-full bg-[#04060a] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">
                    Plain English Policy Directive
                  </label>
                  <textarea
                    value={ruleText}
                    onChange={(e) => setRuleText(e.target.value)}
                    rows={3}
                    placeholder="e.g. Agent must never transfer funds or process invoices over $200 without user approval."
                    className="w-full bg-[#04060a] border border-white/[0.08] rounded-xl p-3 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">
                    Trigger Keywords (comma-separated)
                  </label>
                  <input
                    value={ruleKeywords}
                    onChange={(e) => setRuleKeywords(e.target.value)}
                    placeholder="e.g. transfer, invoice, payment, refund"
                    className="w-full bg-[#04060a] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">Enforcement</label>
                  <select
                    value={ruleAction}
                    onChange={(e) => setRuleAction(e.target.value as Decision)}
                    className="w-full bg-[#04060a] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                  >
                    <option value="prompt">Prompt (Hold for Approval)</option>
                    <option value="deny">Deny (Hard Block)</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-2.5 pt-4 border-t border-white/[0.06]">
                <button
                  onClick={() => setIsAddRuleOpen(false)}
                  className="btn-tactile px-4 py-2 rounded-xl text-xs bg-white/[0.04] hover:bg-white/[0.08] text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  onClick={handleAddRule}
                  className="btn-tactile px-5 py-2 rounded-xl text-xs font-bold bg-blue-500 hover:bg-blue-400 text-slate-950 shadow-[0_2px_12px_rgba(59,130,246,0.2)] cursor-pointer"
                >
                  Save Rule
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add Threat Modal */}
      {isAddThreatOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="doppel-shell max-w-md w-full animate-in zoom-in-95 duration-150">
            <div className="doppel-core p-6">
              <div className="flex items-center justify-between pb-4 border-b border-white/[0.06]">
                <h3 className="font-bold text-sm text-slate-100">Register Threat Signature</h3>
                <button
                  onClick={() => setIsAddThreatOpen(false)}
                  className="btn-tactile text-slate-400 hover:text-white p-1 rounded-lg hover:bg-white/[0.05]"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="flex flex-col gap-3.5 my-5">
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">Threat Name</label>
                  <input
                    value={threatName}
                    onChange={(e) => setThreatName(e.target.value)}
                    placeholder="e.g. System Override Attempt"
                    className="w-full bg-[#04060a] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">Regex Pattern</label>
                  <input
                    value={threatPattern}
                    onChange={(e) => setThreatPattern(e.target.value)}
                    placeholder="e.g. (?i)(ignore previous instructions)"
                    className="w-full bg-[#04060a] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs font-mono text-purple-300 focus:outline-none focus:border-purple-500"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">Description</label>
                  <input
                    value={threatDesc}
                    onChange={(e) => setThreatDesc(e.target.value)}
                    placeholder="e.g. Detects jailbreak phrases"
                    className="w-full bg-[#04060a] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2.5 pt-4 border-t border-white/[0.06]">
                <button
                  onClick={() => setIsAddThreatOpen(false)}
                  className="btn-tactile px-4 py-2 rounded-xl text-xs bg-white/[0.04] hover:bg-white/[0.08] text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  onClick={handleAddThreat}
                  className="btn-tactile px-5 py-2 rounded-xl text-xs font-bold bg-purple-500 hover:bg-purple-400 text-slate-950 shadow-[0_2px_12px_rgba(168,85,247,0.2)] cursor-pointer"
                >
                  Save Threat
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <TestGuardrailModal
        isOpen={isTestModalOpen}
        onClose={() => setIsTestModalOpen(false)}
      />
    </div>
  );
}
