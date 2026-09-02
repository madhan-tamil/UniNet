"""Runtime configuration.

Precedence (highest first):  UNINET_* environment variables  ->  config/config.yaml
->  built-in defaults. Kept dependency-light on purpose (plain dataclass + yaml).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "config.yaml"
DEFAULT_RULES_PATH = REPO_ROOT / "config" / "threat_rules.yaml"

_ENV_PREFIX = "UNINET_"


@dataclass
class Settings:
    bus: str = "inproc"
    kafka_brokers: str = "localhost:9092"
    kafka_topic: str = "uninet.flows.oneway"

    window_seconds: int = 60
    burst_gap_seconds: float = 2.0
    min_bursts_for_periodicity: int = 3
    min_flows_per_window: int = 4   # skip assessment for near-idle host windows

    alert_threshold: float = 0.5
    fusion_weights: dict[str, float] = field(
        default_factory=lambda: {"rule": 0.5, "anomaly": 0.2, "graph": 0.3}
    )

    model_dir: str = "models"
    anomaly_model: str = "anomaly_isoforest.joblib"
    rgat_model: str = "rgat.pt"
    sequence_model: str = "sequence_gru.pt"

    api_host: str = "127.0.0.1"
    api_port: int = 8000

    # ---- dashboard auth (single operator account; prototype-grade) ------
    auth_disabled: bool = False
    auth_user: str = "admin"
    auth_password: str = "uninet"
    secret_key: str = "uninet-dev-secret-change-me"

    # ---- derived helpers -------------------------------------------------
    @property
    def model_path_anomaly(self) -> Path:
        return REPO_ROOT / self.model_dir / self.anomaly_model

    @property
    def model_path_rgat(self) -> Path:
        return REPO_ROOT / self.model_dir / self.rgat_model

    @property
    def model_path_sequence(self) -> Path:
        return REPO_ROOT / self.model_dir / self.sequence_model

    def normalized_fusion_weights(self) -> dict[str, float]:
        total = sum(self.fusion_weights.values()) or 1.0
        return {k: v / total for k, v in self.fusion_weights.items()}


def _coerce(name: str, raw: str, current: Any) -> Any:
    if isinstance(current, bool):
        return raw.lower() in {"1", "true", "yes", "on"}
    if isinstance(current, int) and not isinstance(current, bool):
        return int(raw)
    if isinstance(current, float):
        return float(raw)
    return raw


def load_settings(path: str | Path | None = None) -> Settings:
    """Load :class:`Settings` from yaml + environment overrides."""
    settings = Settings()

    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if cfg_path.is_file():
        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        for f in fields(Settings):
            if f.name in data and data[f.name] is not None:
                setattr(settings, f.name, data[f.name])

    for f in fields(Settings):
        env_key = _ENV_PREFIX + f.name.upper()
        if env_key in os.environ:
            cur = getattr(settings, f.name)
            setattr(settings, f.name, _coerce(f.name, os.environ[env_key], cur))

    return settings


def load_threat_rules(path: str | Path | None = None) -> dict[str, dict[str, float]]:
    rules_path = Path(path) if path else DEFAULT_RULES_PATH
    if not rules_path.is_file():
        return {}
    return yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}
