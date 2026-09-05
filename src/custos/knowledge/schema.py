"""Data schemas for Custos Knowledge Base and Guardrails.

Provides structured definitions for:
- Sensitive assets (paths, IPs, domains, secrets, tables, regexes)
- Natural-language behavioral guardrails (policies, company rules)
- Threat and injection patterns (IPI, jailbreak patterns)
- Evaluation results
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from enum import Enum
from typing import Any


class AssetType(str, Enum):
    FILE_PATH = "file_path"
    IP_NETWORK = "ip_network"
    DOMAIN = "domain"
    DB_TABLE = "db_table"
    ENV_VAR = "env_var"
    REGEX = "regex"
    KEYWORD = "keyword"


class GuardrailAction(str, Enum):
    DENY = "deny"
    PROMPT = "prompt"
    QUARANTINE = "quarantine"


class GuardrailCategory(str, Enum):
    DATA_EXFILTRATION = "data_exfiltration"
    DESTRUCTIVE_OPERATIONS = "destructive_operations"
    FINANCIAL = "financial"
    COMPLIANCE_PRIVACY = "compliance_privacy"
    NETWORK_SECURITY = "network_security"
    GENERAL = "general"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SensitiveAsset:
    """An individual protected asset or boundary definition."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    asset_type: AssetType = AssetType.FILE_PATH
    pattern: str = ""  # e.g., "*/.env*", "10.0.0.0/8", "users_credentials", "id_rsa*"
    action: GuardrailAction = GuardrailAction.DENY
    severity: Severity = Severity.HIGH
    description: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SensitiveAsset:
        data = dict(data)
        if "asset_type" in data and isinstance(data["asset_type"], str):
            data["asset_type"] = AssetType(data["asset_type"])
        if "action" in data and isinstance(data["action"], str):
            data["action"] = GuardrailAction(data["action"])
        if "severity" in data and isinstance(data["severity"], str):
            data["severity"] = Severity(data["severity"])
        allowed = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in allowed})


@dataclass
class GuardrailRule:
    """A natural language policy rule for agent behavior."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    natural_language_rule: str = ""  # e.g. "Do not allow deleting production tables without approval"
    category: GuardrailCategory = GuardrailCategory.GENERAL
    action: GuardrailAction = GuardrailAction.PROMPT
    severity: Severity = Severity.HIGH
    target_tools: list[str] = field(default_factory=lambda: ["*"])  # e.g. ["db.*", "shell.*"]
    keywords: list[str] = field(default_factory=list)  # for fast heuristic pre-filtering
    enabled: bool = True
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardrailRule:
        data = dict(data)
        if "category" in data and isinstance(data["category"], str):
            data["category"] = GuardrailCategory(data["category"])
        if "action" in data and isinstance(data["action"], str):
            data["action"] = GuardrailAction(data["action"])
        if "severity" in data and isinstance(data["severity"], str):
            data["severity"] = Severity(data["severity"])
        allowed = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in allowed})


@dataclass
class ThreatPattern:
    """A known threat or injection signature pattern."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    pattern: str = ""  # regex or string trigger
    is_regex: bool = True
    severity: Severity = Severity.CRITICAL
    description: str = ""
    action: GuardrailAction = GuardrailAction.QUARANTINE
    enabled: bool = True
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ThreatPattern:
        data = dict(data)
        if "action" in data and isinstance(data["action"], str):
            data["action"] = GuardrailAction(data["action"])
        if "severity" in data and isinstance(data["severity"], str):
            data["severity"] = Severity(data["severity"])
        allowed = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in allowed})


@dataclass
class GuardrailEvaluationResult:
    """The result of checking an invocation against the Knowledge Base."""

    allowed: bool
    action: GuardrailAction | None = None
    violated_rule: GuardrailRule | None = None
    violated_asset: SensitiveAsset | None = None
    violated_threat: ThreatPattern | None = None
    risk_score: float = 0.0  # 0.0 to 1.0
    reasoning: str = ""
