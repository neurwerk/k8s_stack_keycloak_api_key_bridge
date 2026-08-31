"""Validation for the stable AgentGateway permission namespace."""

from __future__ import annotations

import re

_RESOURCE_ID = r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}"
_PERMISSION_PATTERN = re.compile(
    rf"^(?:llm:invoke|model:{_RESOURCE_ID}:invoke|mcp:{_RESOURCE_ID}:invoke)$"
)


def is_valid_permission(value: str) -> bool:
    """Return whether *value* belongs to the AgentGateway permission namespace."""
    return _PERMISSION_PATTERN.fullmatch(value) is not None
