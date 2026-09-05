"""Configuration for Custos Server."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ServerConfig:
    """Settings for the Custos Control Plane server."""

    host: str = "0.0.0.0"
    port: int = 8000
    auth_token: str | None = None  # If set, requires Bearer token on requests
    policy_path: Path | None = None
    audit_log_path: Path = field(default_factory=lambda: Path.home() / ".custos" / "audit.jsonl")
    kb_path: Path = field(default_factory=lambda: Path.home() / ".custos" / "knowledge_base.json")
    ollama_url: str | None = None
    ollama_model: str = "llama3.2"
    hmac_key: str | None = None
    ui_dist_path: Path | None = None
    cors_origins: list[str] = field(default_factory=lambda: ["*"])

    @classmethod
    def from_env(cls) -> ServerConfig:
        return cls(
            host=os.getenv("CUSTOS_HOST", "0.0.0.0"),
            port=int(os.getenv("CUSTOS_PORT", "8000")),
            auth_token=os.getenv("CUSTOS_AUTH_TOKEN"),
            policy_path=Path(os.environ["CUSTOS_POLICY_PATH"]) if "CUSTOS_POLICY_PATH" in os.environ else None,
            audit_log_path=Path(os.getenv("CUSTOS_AUDIT_PATH", str(Path.home() / ".custos" / "audit.jsonl"))),
            kb_path=Path(os.getenv("CUSTOS_KB_PATH", str(Path.home() / ".custos" / "knowledge_base.json"))),
            ollama_url=os.getenv("CUSTOS_OLLAMA_URL"),
            ollama_model=os.getenv("CUSTOS_OLLAMA_MODEL", "llama3.2"),
            hmac_key=os.getenv("CUSTOS_HMAC_KEY"),
            ui_dist_path=Path(os.environ["CUSTOS_UI_PATH"]) if "CUSTOS_UI_PATH" in os.environ else None,
        )
