"use client";

import { useState, useEffect } from "react";
import { Header } from "@/components/Header";
import { TestGuardrailModal } from "@/components/TestGuardrailModal";
import { api } from "@/lib/api";
import {
  Settings,
  Shield,
  Key,
  Cpu,
  Server,
  Save,
  AlertOctagon,
  CheckCircle2,
} from "lucide-react";

export default function SettingsPage() {
  const [isTestModalOpen, setIsTestModalOpen] = useState(false);
  const [ollamaUrl, setOllamaUrl] = useState("http://localhost:11434");
  const [ollamaModel, setOllamaModel] = useState("llama3.2");
  const [defaultAction, setDefaultAction] = useState("deny");
  const [hmacKey, setHmacKey] = useState("");
  const [hmacMasked, setHmacMasked] = useState("");
  const [savedMsg, setSavedMsg] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    api.getSettings()
      .then((res) => {
        if (res.default_action) setDefaultAction(res.default_action);
        if (res.ollama_url) setOllamaUrl(res.ollama_url);
        if (res.ollama_model) setOllamaModel(res.ollama_model);
        if (res.hmac_key_masked) setHmacMasked(res.hmac_key_masked);
      })
      .catch(() => {
        api.getPolicies().then((res) => {
          if (res.default) setDefaultAction(res.default);
        }).catch(() => {});
      });
  }, []);

  const handleSave = async () => {
    setIsSaving(true);
    setSaveError(null);
    try {
      await api.updateSettings({
        default_action: defaultAction,
        ollama_url: ollamaUrl,
        ollama_model: ollamaModel,
        hmac_key: hmacKey.trim() ? hmacKey.trim() : undefined,
      });
      setSavedMsg(true);
      if (hmacKey.trim()) {
        setHmacMasked("••••••••");
        setHmacKey("");
      }
      setTimeout(() => setSavedMsg(false), 3500);
    } catch (err: unknown) {
      console.error("Failed to save settings:", err);
      const msg = err instanceof Error ? err.message : "Failed to save configuration";
      setSaveError(msg);
      setTimeout(() => setSaveError(null), 4500);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="pb-16">
      <Header
        category="Configuration"
        title="Settings"
        subtitle="Gateway runtime parameters, LLM assistants, and cryptographic keys"
        onOpenTestModal={() => setIsTestModalOpen(true)}
      />

      <div className="p-8 max-w-4xl mx-auto flex flex-col gap-6">
        {savedMsg && (
          <div className="bg-[#10b981]/10 border border-[#10b981]/30 text-[#10b981] px-4 py-3 rounded-xl text-xs flex items-center gap-2 animate-in fade-in">
            <CheckCircle2 className="w-4 h-4 text-[#10b981]" />
            <span>Gateway settings saved successfully.</span>
          </div>
        )}
        {saveError && (
          <div className="bg-rose-500/10 border border-rose-500/30 text-rose-300 px-4 py-3 rounded-xl text-xs flex items-center gap-2 animate-in fade-in">
            <AlertOctagon className="w-4 h-4 text-rose-400 flex-shrink-0" />
            <span>{saveError}</span>
          </div>
        )}

        {/* Setting Card: Zero-Trust Policy Default */}
        <div className="doppel-shell">
          <div className="doppel-core p-6 flex flex-col gap-4">
            <div className="flex items-center gap-3 pb-3 border-b border-[#334155]">
              <div className="w-8 h-8 rounded-lg bg-[#4f46e5]/10 border border-[#4f46e5]/30 flex items-center justify-center text-[#4f46e5]">
                <Shield className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-[#f8fafc]">
                  Default Permission Policy Floor
                </h3>
                <p className="text-xs text-[#94a3b8]">
                  Fallback decision when a tool invocation is not explicitly matched by any rule
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3" role="radiogroup" aria-label="Default Permission Policy Floor">
              <label
                htmlFor="policy-floor-deny"
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setDefaultAction("deny");
                  }
                }}
                className={`p-4 rounded-xl border cursor-pointer flex flex-col gap-1 transition-all ${
                  defaultAction === "deny"
                    ? "bg-[#ef4444]/10 border-[#ef4444]/40 text-[#f8fafc]"
                    : "bg-[#020617] border-[#334155] text-[#94a3b8]"
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <input
                      id="policy-floor-deny"
                      type="radio"
                      name="defaultAction"
                      value="deny"
                      checked={defaultAction === "deny"}
                      onChange={() => setDefaultAction("deny")}
                      className="accent-[#ef4444] cursor-pointer"
                    />
                    <span className="font-bold text-xs">HARD DENY (Recommended)</span>
                  </div>
                  <span className="w-2 h-2 rounded-full bg-[#ef4444]" />
                </div>
                <span className="text-[11px] text-[#94a3b8] pl-5.5">
                  Zero-trust security floor: blocks all unconfigured tool actions.
                </span>
              </label>

              <label
                htmlFor="policy-floor-prompt"
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setDefaultAction("prompt");
                  }
                }}
                className={`p-4 rounded-xl border cursor-pointer flex flex-col gap-1 transition-all ${
                  defaultAction === "prompt"
                    ? "bg-[#f59e0b]/10 border-[#f59e0b]/40 text-[#f8fafc]"
                    : "bg-[#020617] border-[#334155] text-[#94a3b8]"
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <input
                      id="policy-floor-prompt"
                      type="radio"
                      name="defaultAction"
                      value="prompt"
                      checked={defaultAction === "prompt"}
                      onChange={() => setDefaultAction("prompt")}
                      className="accent-[#f59e0b] cursor-pointer"
                    />
                    <span className="font-bold text-xs">HOLD FOR HUMAN APPROVAL</span>
                  </div>
                  <span className="w-2 h-2 rounded-full bg-[#f59e0b]" />
                </div>
                <span className="text-[11px] text-[#94a3b8] pl-5.5">
                  Escalates unconfigured tool calls to the Live Approvals inbox.
                </span>
              </label>
            </div>
          </div>
        </div>

        {/* Setting Card: Local Ollama / LLM Constitution Assistant */}
        <div className="doppel-shell">
          <div className="doppel-core p-6 flex flex-col gap-4">
            <div className="flex items-center gap-3 pb-3 border-b border-[#334155]">
              <div className="w-8 h-8 rounded-lg bg-[#7c3aed]/10 border border-[#7c3aed]/30 flex items-center justify-center text-[#7c3aed]">
                <Cpu className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-100">
                  Local Constitution Assistant (Ollama)
                </h3>
                <p className="text-xs text-slate-400">
                  Evaluates natural language rules against agent user messages & tools
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Ollama Base URL
                </label>
                <input
                  value={ollamaUrl}
                  onChange={(e) => setOllamaUrl(e.target.value)}
                  className="w-full bg-[#020617] border border-[#334155] rounded-xl px-3.5 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-[#4f46e5]"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Model Identifier
                </label>
                <input
                  value={ollamaModel}
                  onChange={(e) => setOllamaModel(e.target.value)}
                  className="w-full bg-[#020617] border border-[#334155] rounded-xl px-3.5 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-[#4f46e5]"
                />
              </div>
            </div>
          </div>
        </div>

        {/* Setting Card: Cryptographic Audit Signing Key */}
        <div className="doppel-shell">
          <div className="doppel-core p-6 flex flex-col gap-4">
            <div className="flex items-center gap-3 pb-3 border-b border-[#334155]">
              <div className="w-8 h-8 rounded-lg bg-[#10b981]/10 border border-[#10b981]/30 flex items-center justify-center text-[#10b981]">
                <Key className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-100">
                  Cryptographic Audit Ledger Signing Key
                </h3>
                <p className="text-xs text-slate-400">
                  Secret key used to compute SHA-256 HMAC signatures on every log line
                </p>
              </div>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                HMAC Key (UTF-8)
              </label>
              <input
                type="password"
                value={hmacKey}
                onChange={(e) => setHmacKey(e.target.value)}
                placeholder={hmacMasked ? `Configured on server: ${hmacMasked} (enter new key to update)` : "Enter HMAC secret signing key..."}
                className="w-full bg-[#020617] border border-[#334155] rounded-xl px-3.5 py-2 text-xs font-mono text-[#10b981] placeholder:text-[#64748b] focus:outline-none focus:border-[#4f46e5]"
              />
            </div>
          </div>
        </div>

        {/* Save CTA */}
        <div className="flex justify-end">
          <button
            onClick={handleSave}
            disabled={isSaving}
            className="btn-tactile group inline-flex items-center gap-2 pl-5 pr-2 py-2 rounded-full text-xs font-semibold bg-[#4f46e5] hover:bg-[#4338ca] disabled:opacity-50 text-white shadow-[0_2px_12px_rgba(79,70,229,0.3)] cursor-pointer transition-all"
          >
            <span className="font-bold">{isSaving ? "Saving..." : "Save Configuration"}</span>
            <div className="w-6 h-6 rounded-full bg-white/20 text-white flex items-center justify-center group-hover:scale-105 transition-transform">
              <Save className="w-3 h-3" />
            </div>
          </button>
        </div>
      </div>

      <TestGuardrailModal
        isOpen={isTestModalOpen}
        onClose={() => setIsTestModalOpen(false)}
      />
    </div>
  );
}
