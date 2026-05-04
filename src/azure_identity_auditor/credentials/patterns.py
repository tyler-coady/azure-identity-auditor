"""Compiled regex patterns for detecting hardcoded credentials in IaC and app settings."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Severity


@dataclass(frozen=True)
class CredentialPattern:
    pattern_id: str
    description: str
    regex: re.Pattern[str]
    severity: Severity


# Patterns applied to full file content / individual lines
CREDENTIAL_PATTERNS: list[CredentialPattern] = [
    CredentialPattern(
        pattern_id="CP-001",
        description="Azure Storage connection string with embedded account key",
        regex=re.compile(
            r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{86}==",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
    ),
    CredentialPattern(
        pattern_id="CP-002",
        description="Azure Service Bus / Event Hub connection string with embedded key",
        regex=re.compile(
            r"Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[A-Za-z0-9+/=]{40,}",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
    ),
    CredentialPattern(
        pattern_id="CP-003",
        description="Azure SAS token with signature",
        regex=re.compile(
            r"\bsv=\d{4}-\d{2}-\d{2}&[^&\s\"']*&sig=[A-Za-z0-9%+/=]{40,}",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
    ),
    CredentialPattern(
        pattern_id="CP-004",
        description="Generic API key / secret assignment with non-trivial value",
        regex=re.compile(
            r"""(?i)(?:api[_-]?key|subscription[_-]?key|access[_-]?key|secret|password|token|api[_-]?secret)\s*[=:]\s*["']([A-Za-z0-9+/\-_\.]{20,})["']""",
        ),
        severity=Severity.HIGH,
    ),
    CredentialPattern(
        pattern_id="CP-005",
        description="Azure Cognitive Services / OpenAI 32-char hex key in key context",
        regex=re.compile(
            r"""(?i)(?:api[_-]?key|subscription[_-]?key|ocp-apim-subscription-key|cognitive[_-]?key)\s*[=:]\s*["']([0-9a-f]{32})["']""",
        ),
        severity=Severity.CRITICAL,
    ),
    CredentialPattern(
        pattern_id="CP-006",
        description="OpenAI-style bearer key",
        regex=re.compile(r"""["'](sk-[A-Za-z0-9]{20,})["']"""),
        severity=Severity.CRITICAL,
    ),
    CredentialPattern(
        pattern_id="CP-007",
        description="Azure connection string with password field",
        regex=re.compile(
            r"(?i)(?:server|data\s+source)=[^;]+;[^;]*(?:password|pwd)=[^;\"']{6,}",
        ),
        severity=Severity.HIGH,
    ),
]

# Regex patterns matched against app setting KEYS (not values) to flag suspicious names
APP_SETTING_KEY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(api[_-]?key|apikey)$"),
    re.compile(r"(?i)(subscription[_-]?key)$"),
    re.compile(r"(?i)(access[_-]?key|accesskey)$"),
    re.compile(r"(?i)(connection[_-]?string|connstr|connectionstring)$"),
    re.compile(r"(?i)(secret|password|passwd|api[_-]?secret)$"),
    re.compile(r"(?i)AZURE_[A-Z_]+(KEY|SECRET|PASSWORD|TOKEN)$"),
    re.compile(r"(?i)(OPENAI|COGNITIVE|AZURE_AI)[_-]?(API[_-]?)?KEY$"),
]

# Values that are safe — Key Vault references, template expressions, env var lookups
_SAFE_VALUE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^@Microsoft\.KeyVault\("),
    re.compile(r"^\[parameters\("),
    re.compile(r"^\[variables\("),
    re.compile(r"^\[listKeys\("),
    re.compile(r"^\[concat\("),
    re.compile(r"^\$\{"),          # shell/Terraform variable interpolation
    re.compile(r"^\$\("),          # Azure Pipelines variable
    re.compile(r"^\{\{"),          # GitHub Actions / Helm expression
    re.compile(r"^var\."),         # Terraform variable reference
    re.compile(r"^data\."),        # Terraform data source
    re.compile(r"^azurerm_"),      # Terraform resource reference
    re.compile(r"(?i)^(your[-_]?|<|PLACEHOLDER|REPLACE|TODO|CHANGEME|EXAMPLE)"),
]

# Placeholder / obviously fake values to skip
_PLACEHOLDER_VALUES = frozenset(
    [
        "",
        "null",
        "none",
        "placeholder",
        "changeme",
        "todo",
        "example",
        "replace",
        "your-api-key",
        "your-key-here",
        "<key>",
        "<secret>",
        "xxxxxxxx",
    ]
)


def is_safe_value(value: str) -> bool:
    """Return True if the value is a template expression, variable reference, or placeholder."""
    if not value or value.lower() in _PLACEHOLDER_VALUES:
        return True
    return any(p.search(value) for p in _SAFE_VALUE_PATTERNS)


def match_app_settings(
    settings: dict[str, str],
) -> list[tuple[str, str, CredentialPattern | None]]:
    """
    Check app settings dict for suspicious keys and credential values.

    Returns a list of (key, redacted_value, pattern_or_None) tuples for flagged settings.
    pattern is None when the key name alone triggered the finding (APP-001).
    """
    flagged: list[tuple[str, str, CredentialPattern | None]] = []

    for key, raw_value in settings.items():
        value = raw_value or ""

        # Skip Key Vault references — those are the correct pattern
        if value.startswith("@Microsoft.KeyVault("):
            continue

        redacted = _redact(value)

        # Check if the value itself matches a credential pattern
        value_matched = False
        for pattern in CREDENTIAL_PATTERNS:
            if pattern.regex.search(value) and not is_safe_value(value):
                flagged.append((key, redacted, pattern))
                value_matched = True
                break

        # If not caught by value pattern, check if the key name is suspicious
        if not value_matched and value and not is_safe_value(value):
            if any(p.search(key) for p in APP_SETTING_KEY_PATTERNS):
                flagged.append((key, redacted, None))

    return flagged


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"
