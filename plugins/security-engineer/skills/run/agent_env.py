#!/usr/bin/env python3
"""The environment a model subprocess is allowed to see.

There was no `env=` anywhere in this plugin, so every `claude -p` call inherited
the orchestrator's environment: ORCA_API_TOKEN, NOTIFY_WEBHOOK_URL and whatever
credentials `gh` was authenticated with. A process whose whole job is reading
repository content — content an attacker can write — has no use for any of them,
and all four call sites are covered here rather than one.

The orchestrator's own `gh` and `git` subprocesses are deliberately untouched.
They need those credentials, and they are not the untrusted party.
"""
import os
import re

from config import load_config

# An allowlist of names, never a pattern: NPM_TOKEN would sail through any
# prefix rule written for npm. Values are read from the real environment at call
# time, so nothing in this file holds a secret.
_ALLOW = frozenset({
    # process and shell basics
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL",
    "LC_CTYPE", "TERM", "TZ",
    # TLS trust and proxies — without these a corporate network breaks the call
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "no_proxy",
    # Claude's own auth and routing. ANTHROPIC_API_KEY is a credential and is
    # here on purpose: it is the one the subprocess is entitled to.
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
    "ANTHROPIC_MODEL", "ANTHROPIC_SMALL_FAST_MODEL",
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
    # Toolchain caches, so the lockfile regens do not redownload the world.
    # Caches only — GOPROXY, GOPRIVATE, NPM_CONFIG_REGISTRY and PIP_INDEX_URL
    # are excluded because each can carry credentials inside a URL. A private
    # registry adds them through fix_agent.extra_env, deliberately.
    "GOPATH", "GOMODCACHE", "GOCACHE", "GOFLAGS",
    "CARGO_HOME", "RUSTUP_HOME",
    "npm_config_cache", "NPM_CONFIG_CACHE",
    "BUNDLE_PATH", "GEM_HOME", "GEM_PATH",
    "DOTNET_CLI_HOME", "NUGET_PACKAGES",
    "JAVA_HOME", "M2_HOME", "PIP_CACHE_DIR",
})

# Names fix_agent.extra_env may never add back. The literal four are the ones
# this change exists to withhold; the pattern catches the shape of the rest, so
# an operator adding AWS_REGION for Bedrock cannot also add AWS_SECRET_ACCESS_KEY
# without noticing. It does not apply to _ALLOW above, which is
# reviewed here rather than configured.
_NEVER = {"ORCA_API_TOKEN", "ORCA_AUTH_TOKEN", "NOTIFY_WEBHOOK_URL",
              "GH_TOKEN", "GITHUB_TOKEN"}
_NEVER_SHAPE = re.compile(r"TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|COOKIE|SESSION",
                              re.IGNORECASE)


def agent_env(extra: list | None = None) -> dict:
    """The environment for a model subprocess: allowlisted names only.

    extra defaults to fix_agent.extra_env from config; tests pass it directly.
    """
    if extra is None:
        extra = load_config().fix_agent.extra_env
    allowed = set(_ALLOW)
    for name in (extra or []):
        name = str(name).strip()
        if not name:
            continue
        if name in _NEVER or _NEVER_SHAPE.search(name):
            print(f"[WARN] ignoring fix_agent.extra_env entry {name!r}: "
                  f"credential-shaped names cannot be added to the agent "
                  f"environment", flush=True)
            continue
        allowed.add(name)
    return {k: v for k, v in os.environ.items() if k in allowed}
