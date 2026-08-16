#!/usr/bin/env python3
"""
Configuration for the Security Engineer orchestrator.

Settings are loaded from a YAML config file. The path is read from the
SECURITY_ENGINEER_CONFIG environment variable; if unset, built-in defaults apply.

Secrets (ORCA_API_TOKEN, NOTIFY_WEBHOOK_URL) stay as env vars — they are
not part of this config.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class OrcaCheckConfig:
    """Controls the post-PR Orca GitHub App check gate."""
    enabled: bool = True
    check_name: str = "orca-security-us"
    timeout_sec: int = 600
    poll_interval_sec: int = 15
    max_retries: int = 1
    on_failure: str = "retry"     # "retry" | "fail" | "skip"
    on_not_found: str = "skip"    # "skip" | "fail"


@dataclass
class VersionDataConfig:
    """Controls the OSV/deps.dev lookup behind CVE version decisions.

    cache_dir empty means the module default (~/.cache/security-engineer). The
    cache is what keeps a 12-way concurrent run from hammering two public APIs.
    """
    enabled: bool = True
    cache_dir: str = ""
    cache_ttl_sec: int = 6 * 3600
    timeout_sec: int = 20
    offline: bool = False           # serve from cache only, never call out
    osv_url: str = ""               # empty means the module default
    deps_dev_url: str = ""


@dataclass
class Config:
    orca_check: OrcaCheckConfig = field(default_factory=OrcaCheckConfig)
    version_data: VersionDataConfig = field(default_factory=VersionDataConfig)
    max_parallel_fixes: int = 4
    max_parallel_repos: int = 3


# Nested sections, mapped to the dataclass that parses each. Adding a section
# means adding one entry here — the previous shape hardcoded `!= "orca_check"` in
# the top-level filter, so a second section silently landed in the wrong place.
_SECTIONS = {
    "orca_check": OrcaCheckConfig,
    "version_data": VersionDataConfig,
}


def _parse_section(raw: dict, cls):
    """Build a section dataclass, dropping keys it does not declare."""
    return cls(**{k: v for k, v in (raw or {}).items()
                  if k in cls.__dataclass_fields__})


def load_config() -> Config:
    """Load config from YAML file (if set) with defaults."""
    config_path = os.environ.get("SECURITY_ENGINEER_CONFIG")
    if not config_path or not Path(config_path).exists():
        return Config()

    try:
        import yaml
    except ImportError:
        print("[WARN] PyYAML not installed — using default config", flush=True)
        return Config()

    try:
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[WARN] failed to read config {config_path}: {e}", flush=True)
        return Config()

    sections = {name: _parse_section(raw.get(name, {}), cls)
                for name, cls in _SECTIONS.items()}
    top = {
        k: v for k, v in raw.items()
        if k in Config.__dataclass_fields__ and k not in _SECTIONS
    }
    return Config(**sections, **top)
