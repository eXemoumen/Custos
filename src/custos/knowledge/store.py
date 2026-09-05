"""Knowledge Base persistence store.

Stores sensitive assets, natural language guardrails, and threat patterns.
Persists to a JSON file (or SQLite) and provides out-of-the-box security defaults.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from custos.knowledge.schema import (
    AssetType,
    GuardrailAction,
    GuardrailCategory,
    GuardrailRule,
    SensitiveAsset,
    Severity,
    ThreatPattern,
)

logger = logging.getLogger(__name__)

DEFAULT_KB_PATH = Path.home() / ".custos" / "knowledge_base.json"

DEFAULT_ASSETS: list[dict[str, Any]] = [
    {
        "id": "asset-env-files",
        "name": "Environment & Secret Files",
        "asset_type": "file_path",
        "pattern": ".env|id_rsa|.aws|.kube",
        "action": "deny",
        "severity": "critical",
        "description": "Protects private keys, cloud credentials, and .env files.",
    },
    {
        "id": "asset-system-creds",
        "name": "System Authentication Files",
        "asset_type": "file_path",
        "pattern": "/etc/shadow|/etc/master.passwd|SAM|SYSTEM",
        "action": "deny",
        "severity": "critical",
        "description": "Prevents reading system password and shadow credential files.",
    },
    {
        "id": "asset-destructive-shell",
        "name": "Destructive Shell Operations",
        "asset_type": "regex",
        "pattern": "(rm\\s+-rf\\s+[/~])|(mkfs\\.)|(dd\\s+if=.*of=/dev/)|(format\\s+[a-zA-Z]:)",
        "action": "deny",
        "severity": "critical",
        "description": "Blocks destructive filesystem erasure commands.",
    },
    {
        "id": "asset-metadata-service",
        "name": "Cloud Metadata Service (SSRF)",
        "asset_type": "ip_network",
        "pattern": "169.254.169.254",
        "action": "deny",
        "severity": "critical",
        "description": "Blocks attempts to reach AWS/GCP/Azure instance metadata endpoints.",
    },
    {
        "id": "asset-private-subnets",
        "name": "Internal Private Subnets",
        "asset_type": "ip_network",
        "pattern": "10.*|192.168.*|172.16.*",
        "action": "prompt",
        "severity": "high",
        "description": "Requires human review when calling internal corporate IP ranges.",
    },
]

DEFAULT_RULES: list[dict[str, Any]] = [
    {
        "id": "rule-no-mass-deletion",
        "name": "No Destructive Bulk Operations",
        "natural_language_rule": "Agent must never bulk delete records, wipe databases, or drop tables without explicit human approval.",
        "category": "destructive_operations",
        "action": "prompt",
        "severity": "critical",
        "target_tools": ["db.*", "sql.*", "fs.delete*"],
        "keywords": ["drop", "truncate", "delete from", "remove", "wipe"],
    },
    {
        "id": "rule-financial-limits",
        "name": "Financial Transaction Guard",
        "natural_language_rule": "Financial transfers, purchases, or payments must be held for explicit user confirmation.",
        "category": "financial",
        "action": "prompt",
        "severity": "critical",
        "target_tools": ["payment.*", "bank.*", "transfer.*", "stripe.*"],
        "keywords": ["transfer", "pay", "charge", "refund", "balance"],
    },
    {
        "id": "rule-no-external-exfiltration",
        "name": "Prevent Sensitive Data Exfiltration",
        "natural_language_rule": "Do not send customer emails, credentials, or private keys to unknown external third-party endpoints or webhooks.",
        "category": "data_exfiltration",
        "action": "prompt",
        "severity": "high",
        "target_tools": ["http.*", "curl", "webhook.*", "email.send*"],
        "keywords": ["post", "upload", "send", "webhook", "export"],
    },
]

DEFAULT_THREATS: list[dict[str, Any]] = [
    {
        "id": "threat-ignore-instructions",
        "name": "Instruction Override Attempt",
        "pattern": "(?i)(ignore\\s+(all\\s+)?previous\\s+instructions|disregard\\s+prior\\s+rules|system\\s+prompt\\s+override)",
        "is_regex": True,
        "severity": "critical",
        "description": "Detects classic jailbreak and instruction-override markers.",
        "action": "quarantine",
    },
    {
        "id": "threat-jailbreak-persona",
        "name": "DAN / Jailbreak Persona",
        "pattern": "(?i)(you\\s+are\\s+now\\s+in\\s+(developer|dan|unfiltered|jailbreak)\\s+mode)",
        "is_regex": True,
        "severity": "critical",
        "description": "Detects jailbreak persona adoption patterns.",
        "action": "quarantine",
    },
]


class KnowledgeBaseStore:
    """Manages the persistence and retrieval of Knowledge Base guardrails."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_KB_PATH
        self._assets: dict[str, SensitiveAsset] = {}
        self._rules: dict[str, GuardrailRule] = {}
        self._threats: dict[str, ThreatPattern] = {}
        self._load()

    def _load(self) -> None:
        """Load from file or initialize with security defaults."""
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self._assets = {
                    a["id"]: SensitiveAsset.from_dict(a) for a in data.get("assets", [])
                }
                self._rules = {
                    r["id"]: GuardrailRule.from_dict(r) for r in data.get("rules", [])
                }
                self._threats = {
                    t["id"]: ThreatPattern.from_dict(t) for t in data.get("threats", [])
                }
                logger.info("Loaded Knowledge Base from %s", self.path)
                return
            except Exception as e:
                logger.warning("Failed to load KB from %s: %s; using defaults", self.path, e)

        # Initialize defaults
        self._assets = {
            a["id"]: SensitiveAsset.from_dict(a) for a in DEFAULT_ASSETS
        }
        self._rules = {
            r["id"]: GuardrailRule.from_dict(r) for r in DEFAULT_RULES
        }
        self._threats = {
            t["id"]: ThreatPattern.from_dict(t) for t in DEFAULT_THREATS
        }
        self.save()

    def save(self) -> None:
        """Persist to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "assets": [a.to_dict() for a in self._assets.values()],
            "rules": [r.to_dict() for r in self._rules.values()],
            "threats": [t.to_dict() for t in self._threats.values()],
        }
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # Assets
    def list_assets(self, enabled_only: bool = False) -> list[SensitiveAsset]:
        assets = list(self._assets.values())
        if enabled_only:
            assets = [a for a in assets if a.enabled]
        return assets

    def get_asset(self, asset_id: str) -> SensitiveAsset | None:
        return self._assets.get(asset_id)

    def add_asset(self, asset: SensitiveAsset) -> SensitiveAsset:
        self._assets[asset.id] = asset
        self.save()
        return asset

    def update_asset(self, asset_id: str, updates: dict[str, Any]) -> SensitiveAsset | None:
        if asset_id not in self._assets:
            return None
        current = self._assets[asset_id].to_dict()
        current.update(updates)
        updated = SensitiveAsset.from_dict(current)
        self._assets[asset_id] = updated
        self.save()
        return updated

    def delete_asset(self, asset_id: str) -> bool:
        if asset_id in self._assets:
            del self._assets[asset_id]
            self.save()
            return True
        return False

    # Rules
    def list_rules(self, enabled_only: bool = False) -> list[GuardrailRule]:
        rules = list(self._rules.values())
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        return rules

    def get_rule(self, rule_id: str) -> GuardrailRule | None:
        return self._rules.get(rule_id)

    def add_rule(self, rule: GuardrailRule) -> GuardrailRule:
        self._rules[rule.id] = rule
        self.save()
        return rule

    def update_rule(self, rule_id: str, updates: dict[str, Any]) -> GuardrailRule | None:
        if rule_id not in self._rules:
            return None
        current = self._rules[rule_id].to_dict()
        current.update(updates)
        updated = GuardrailRule.from_dict(current)
        self._rules[rule_id] = updated
        self.save()
        return updated

    def delete_rule(self, rule_id: str) -> bool:
        if rule_id in self._rules:
            del self._rules[rule_id]
            self.save()
            return True
        return False

    # Threats
    def list_threats(self, enabled_only: bool = False) -> list[ThreatPattern]:
        threats = list(self._threats.values())
        if enabled_only:
            threats = [t for t in threats if t.enabled]
        return threats

    def get_threat(self, threat_id: str) -> ThreatPattern | None:
        return self._threats.get(threat_id)

    def add_threat(self, threat: ThreatPattern) -> ThreatPattern:
        self._threats[threat.id] = threat
        self.save()
        return threat

    def update_threat(self, threat_id: str, updates: dict[str, Any]) -> ThreatPattern | None:
        if threat_id not in self._threats:
            return None
        current = self._threats[threat_id].to_dict()
        current.update(updates)
        updated = ThreatPattern.from_dict(current)
        self._threats[threat_id] = updated
        self.save()
        return updated

    def delete_threat(self, threat_id: str) -> bool:
        if threat_id in self._threats:
            del self._threats[threat_id]
            self.save()
            return True
        return False

    def export_data(self) -> dict[str, Any]:
        return {
            "version": 1,
            "assets": [a.to_dict() for a in self._assets.values()],
            "rules": [r.to_dict() for r in self._rules.values()],
            "threats": [t.to_dict() for t in self._threats.values()],
        }

    def import_data(self, data: dict[str, Any], overwrite: bool = False) -> None:
        if overwrite:
            self._assets.clear()
            self._rules.clear()
            self._threats.clear()

        for a in data.get("assets", []):
            asset = SensitiveAsset.from_dict(a)
            self._assets[asset.id] = asset

        for r in data.get("rules", []):
            rule = GuardrailRule.from_dict(r)
            self._rules[rule.id] = rule

        for t in data.get("threats", []):
            threat = ThreatPattern.from_dict(t)
            self._threats[threat.id] = threat

        self.save()
