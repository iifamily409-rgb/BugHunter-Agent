"""Configuration, scope enforcement, and the authorization gate.

The agent refuses to run unless the operator explicitly attests that every
target is authorized for security testing (e.g. a bug-bounty program or an
asset they own). Scope rules are enforced on every request the agent makes.
"""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import yaml


class ScopeError(RuntimeError):
    pass


class AuthorizationError(RuntimeError):
    pass


@dataclass
class Config:
    targets: list = field(default_factory=list)
    scope_allow: list = field(default_factory=list)      # wildcard hostnames
    scope_deny: list = field(default_factory=list)       # wildcard hostnames
    allow_private_hosts: bool = False                    # lab-only escape hatch
    max_pages: int = 150
    max_depth: int = 4
    concurrency: int = 8
    request_timeout: int = 12
    rate_limit_delay: float = 0.15
    max_retries: int = 2
    user_agent: str = "BugHunterAgent/1.0 (+authorized security testing)"
    active_scans: bool = True            # injection probes etc.
    aggressive: bool = False             # time-based / heavier probes
    daemon: bool = False
    interval_seconds: int = 86400
    output_dir: str = "reports"
    state_file: str = "state/findings.json"
    wordlist_size: int = 120
    respect_robots: bool = False         # hunters usually probe disallowed paths

    # ------------------------------------------------------------------ scope
    def in_scope(self, url: str) -> bool:
        host = urlparse(url).netloc.split(":")[0].lower()
        if not host:
            return False
        for pattern in self.scope_deny:
            if fnmatch.fnmatch(host, pattern):
                return False
        for pattern in self.scope_allow:
            if fnmatch.fnmatch(host, pattern):
                return True
        return False

    def validate(self):
        if not self.targets:
            raise ScopeError("no targets configured")
        for t in self.targets:
            if not self.in_scope(t):
                raise ScopeError(f"target {t!r} is not covered by scope_allow rules")


def load_config(path: Optional[str], overrides: dict) -> Config:
    cfg = Config()
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        for key, value in data.items():
            if hasattr(cfg, key) and value is not None:
                setattr(cfg, key, value)
    for key, value in overrides.items():
        if value is not None:
            setattr(cfg, key, value)
    return cfg


AUTH_ATTESTATION = (
    "I confirm I am authorized to perform security testing against every target in scope"
)


def verify_authorization(phrase: str | None, targets: list, scope_allow: list):
    """Require explicit, exact operator attestation before any network activity."""
    if not phrase or phrase.strip() != AUTH_ATTESTATION:
        raise AuthorizationError(
            "\n"
            "  AUTHORIZATION REQUIRED\n"
            "  This agent performs active security testing. It will only run against\n"
            "  targets you are legally authorized to test (your own assets, or targets\n"
            "  covered by a bug-bounty program whose policy you have read).\n"
            "  Re-run with:\n"
            f'    --authorized "{AUTH_ATTESTATION}"\n'
        )
    if not targets:
        raise AuthorizationError("no targets supplied (use --target or a config file)")
    if not scope_allow:
        raise AuthorizationError(
            "no scope_allow rules supplied; add explicit hostname wildcards "
            "(e.g. scope_allow: ['*.example.com']) so the agent never strays off-target"
        )
