from __future__ import annotations

import os

from connector.runtime_protocol import RuntimeProvider
from connector.runtimes.claude.provider import ClaudeProvider
from connector.runtimes.codex.provider import CodexProvider
from connector.runtimes.dsh.provider import DshProvider


def default_runtime_providers() -> tuple[RuntimeProvider, ...]:
    # Product bootstrap fixes this after inherited environment merging. There
    # is no remote runtime configuration that can select the unbound provider.
    policy = os.environ.get("OSIR_CLIENT_MODEL_BINDING")
    if policy:
        from connector.runtimes.codex.osir_bound_provider import BoundCodexProvider
        return (BoundCodexProvider(policy_valid=policy == "required-v1"), ClaudeProvider(), DshProvider())
    return (CodexProvider(), ClaudeProvider(), DshProvider())
