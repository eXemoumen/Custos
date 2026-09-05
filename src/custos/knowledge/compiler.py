"""Compiles Knowledge Base assets and rules into deterministic Custos policy overlays.

Converts:
- File paths / patterns -> match: { tool: "fs.*" } with args predicate on path/filepath
- IPs / Networks -> match: { tool: "http.*" | "curl*" } with args predicate on url/host
- Shell commands / regex -> match: { tool: "shell.*" | "bash*" } with regex predicate on command
- Threat patterns -> compiled into deterministic regex inspection rules
"""

from __future__ import annotations

import logging
from typing import Any

from custos.knowledge.schema import (
    AssetType,
    GuardrailAction,
    GuardrailRule,
    SensitiveAsset,
    ThreatPattern,
)
from custos.knowledge.store import KnowledgeBaseStore

logger = logging.getLogger(__name__)


class KnowledgeBaseCompiler:
    """Compiles high-level Knowledge Base assets & rules into native Custos policy overlay specs."""

    @staticmethod
    def compile_asset(asset: SensitiveAsset) -> list[dict[str, Any]]:
        """Compile a single SensitiveAsset into one or more Custos policy rule specs."""
        if not asset.enabled:
            return []

        action_str = asset.action.value  # "deny" or "prompt"
        rules: list[dict[str, Any]] = []

        # Split multiple patterns separated by |
        subpatterns = [p.strip() for p in asset.pattern.split("|") if p.strip()]

        if asset.asset_type == AssetType.FILE_PATH:
            for pat in subpatterns:
                clean_pat = pat.strip("*")
                for tool_glob in ["fs.*", "file.*", "filesystem.*", "read_file", "write_file"]:
                    rules.append({
                        "match": {
                            "tool": tool_glob,
                            "args": {"path": {"contains": clean_pat}}
                        },
                        "action": action_str,
                        "description": f"KB Asset: {asset.name} ({clean_pat})",
                    })

        elif asset.asset_type == AssetType.IP_NETWORK or asset.asset_type == AssetType.DOMAIN:
            for pat in subpatterns:
                for tool_glob in ["http.*", "net.*", "curl*", "request*", "fetch*"]:
                    rules.append({
                        "match": {
                            "tool": tool_glob,
                            "args": {"url": {"contains": pat}}
                        },
                        "action": action_str,
                        "description": f"KB Asset: {asset.name} ({pat})",
                    })

        elif asset.asset_type == AssetType.REGEX:
            for pat in subpatterns:
                for tool_glob in ["shell.*", "bash*", "exec*", "terminal.*", "cmd*"]:
                    rules.append({
                        "match": {
                            "tool": tool_glob,
                            "args": {"command": {"matches": pat}}
                        },
                        "action": action_str,
                        "description": f"KB Asset: {asset.name} ({pat})",
                    })

        elif asset.asset_type == AssetType.KEYWORD:
            for pat in subpatterns:
                for tool_glob in ["shell.*", "bash*", "exec*", "terminal.*", "cmd*"]:
                    rules.append({
                        "match": {
                            "tool": tool_glob,
                            "args": {"command": {"contains": pat}}
                        },
                        "action": action_str,
                        "description": f"KB Asset: {asset.name} ({pat})",
                    })

        elif asset.asset_type == AssetType.DB_TABLE:
            for pat in subpatterns:
                for tool_glob in ["db.*", "sql.*", "query*", "database.*"]:
                    rules.append({
                        "match": {
                            "tool": tool_glob,
                            "args": {"query": {"contains": pat}}
                        },
                        "action": action_str,
                        "description": f"KB Asset: {asset.name} ({pat})",
                    })

        return rules

    @classmethod
    def compile_store_to_overlay(
        cls,
        store: KnowledgeBaseStore,
        overlay_id: str = "knowledge_base_overlay",
    ) -> dict[str, Any]:
        """Compile all active assets in the store into a policy overlay mapping."""
        compiled_rules: list[dict[str, Any]] = []

        # 1. Compile assets
        for asset in store.list_assets(enabled_only=True):
            rules = cls.compile_asset(asset)
            compiled_rules.extend(rules)

        # 2. Compile strict natural language rules that target specific tools
        for rule in store.list_rules(enabled_only=True):
            action_str = rule.action.value
            for tool_pattern in rule.target_tools:
                for kw in rule.keywords:
                    compiled_rules.append({
                        "match": {
                            "tool": tool_pattern,
                            "args": {"command": {"contains": kw}} if "shell" in tool_pattern else {"query": {"contains": kw}} if "db" in tool_pattern else {"any": True},
                        },
                        "action": action_str,
                        "description": f"KB Rule: {rule.name} (keyword: {kw})",
                    })

        return {
            "id": overlay_id,
            "rules": compiled_rules,
        }
