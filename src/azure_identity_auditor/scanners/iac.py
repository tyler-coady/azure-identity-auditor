"""IAC-001, IAC-002: Static analysis of IaC files for hardcoded credentials."""

from __future__ import annotations

import json
from pathlib import Path

from ..credentials.patterns import CREDENTIAL_PATTERNS, is_safe_value
from ..models import Finding, FindingSource, ScanResult, Severity
from .base import BaseScanner

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB

SCAN_EXTENSIONS: frozenset[str] = frozenset(
    [".json", ".bicep", ".tf", ".tfvars", ".yml", ".yaml", ".env"]
)

SKIP_DIRS: frozenset[str] = frozenset(
    [".git", "node_modules", "__pycache__", ".venv", "venv", ".terraform", "dist", "build"]
)

# ARM template JSON keys whose values should never be raw strings
ARM_CREDENTIAL_KEYS: frozenset[str] = frozenset(
    [
        "apikey",
        "api_key",
        "primarykey",
        "primary_key",
        "secondarykey",
        "secondary_key",
        "password",
        "secret",
        "connectionstring",
        "connection_string",
        "accesskey",
        "access_key",
        "subscriptionkey",
        "subscription_key",
        "token",
        "sharedaccesskey",
        "shared_access_key",
    ]
)

_IAC_001_REMEDIATION = (
    "Replace the hardcoded value with a template parameter using type 'secureString': "
    "\"[parameters('secretParam')]\". "
    "Alternatively, reference a Key Vault secret: "
    "\"@Microsoft.KeyVault(SecretUri=https://<vault>.vault.azure.net/secrets/<name>/)\". "
    "Never commit secret values to source control."
)

_IAC_002_REMEDIATION = (
    "Use Key Vault references, environment variables, or managed identity authentication "
    "instead of hardcoded credentials. For Terraform, use sensitive input variables or "
    "a secrets management backend (e.g. Vault provider). "
    "For GitHub Actions / Azure Pipelines, use repository secrets or variable groups — "
    "never inline credentials in YAML."
)


class IaCScanner(BaseScanner):
    name = "iac"
    description = "Scans IaC files for hardcoded credentials and API keys"

    def __init__(self, paths: list[Path]) -> None:
        self.paths = paths

    def scan(self) -> ScanResult:
        result = ScanResult()
        for root_path in self.paths:
            root = Path(root_path)
            if root.is_file():
                result.findings.extend(self._scan_file(root))
            else:
                for file_path in self._iter_files(root):
                    result.findings.extend(self._scan_file(file_path))
        return result

    # ------------------------------------------------------------------
    # File iteration
    # ------------------------------------------------------------------

    def _iter_files(self, root: Path):
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in SCAN_EXTENSIONS:
                continue
            if any(skip in path.parts for skip in SKIP_DIRS):
                continue
            yield path

    # ------------------------------------------------------------------
    # Dispatch by file type
    # ------------------------------------------------------------------

    def _scan_file(self, path: Path) -> list[Finding]:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                return []
            raw = path.read_bytes()
            if b"\x00" in raw[:8192]:  # binary file
                return []
            content = raw.decode(errors="ignore")
        except (OSError, PermissionError):
            return []

        if path.suffix == ".json":
            return self._scan_json(path, content)
        return self._scan_text_lines(path, content)

    # ------------------------------------------------------------------
    # ARM template JSON — structural analysis
    # ------------------------------------------------------------------

    def _scan_json(self, path: Path, content: str) -> list[Finding]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return self._scan_text_lines(path, content)

        # Only treat as ARM template if it has the $schema marker
        schema = str(data.get("$schema", "")) if isinstance(data, dict) else ""
        if "deploymentTemplate" in schema or "subscriptionDeploymentTemplate" in schema:
            findings: list[Finding] = []
            self._walk_arm(data, path, [], findings)
            return findings

        # For other JSON files (e.g. appsettings.json), do text scan
        return self._scan_text_lines(path, content)

    def _walk_arm(
        self,
        node: object,
        path: Path,
        json_path: list[str],
        findings: list[Finding],
    ) -> None:
        if isinstance(node, dict):
            # Handle ARM name/value pair pattern: {"name": "apiKey", "value": "secret"}
            # This is used in appSettings, connectionStrings, etc.
            if (
                isinstance(node.get("name"), str)
                and "value" in node
                and node["name"].lower() in ARM_CREDENTIAL_KEYS
            ):
                value = node.get("value", "")
                if isinstance(value, str) and not is_safe_value(value) and len(value) >= 8:
                    name_key = node["name"]
                    self._append_iac001(path, json_path + [f"name={name_key}"], value, findings)

            for key, value in node.items():
                self._walk_arm(value, path, json_path + [key], findings)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                self._walk_arm(item, path, json_path + [str(i)], findings)
        elif isinstance(node, str):
            key = json_path[-1] if json_path else ""
            if key.lower() in ARM_CREDENTIAL_KEYS and not is_safe_value(node) and len(node) >= 8:
                self._append_iac001(path, json_path, node, findings)

    def _append_iac001(
        self, path: Path, json_path: list[str], value: str, findings: list[Finding]
    ) -> None:
        label = json_path[-1] if json_path else "unknown"
        findings.append(
            Finding(
                rule_id="IAC-001",
                title=f"ARM template contains hardcoded credential in '{label}'",
                severity=Severity.CRITICAL,
                source=FindingSource.IAC,
                resource_id=str(path),
                resource_type="IaC/ARM",
                description=(
                    f"The ARM template '{path.name}' contains what appears to be a hardcoded "
                    f"credential at JSON path '{' > '.join(json_path)}'. "
                    "Hardcoded secrets in templates are routinely committed to source control."
                ),
                remediation=_IAC_001_REMEDIATION,
                details={
                    "file": str(path),
                    "json_path": " > ".join(json_path),
                    "value_preview": _redact(value),
                },
            )
        )

    # ------------------------------------------------------------------
    # Line-by-line scan (Bicep, Terraform, YAML, .env, plain JSON)
    # ------------------------------------------------------------------

    def _scan_text_lines(self, path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen_lines: set[int] = set()

        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            # Skip comment lines
            if stripped.startswith(("#", "//", "--", ";")):
                continue

            for pattern in CREDENTIAL_PATTERNS:
                match = pattern.regex.search(line)
                if not match:
                    continue

                matched_text = match.group(0)
                if is_safe_value(matched_text):
                    continue

                # One finding per line maximum
                if line_num in seen_lines:
                    break
                seen_lines.add(line_num)

                file_ext = path.suffix.lstrip(".")
                findings.append(
                    Finding(
                        rule_id="IAC-002",
                        title=f"Hardcoded {pattern.description.lower()} in {file_ext} file",
                        severity=pattern.severity,
                        source=FindingSource.IAC,
                        resource_id=str(path),
                        resource_type=f"IaC/{file_ext.upper()}",
                        description=(
                            f"A potential {pattern.description.lower()} was detected in "
                            f"'{path.name}' at line {line_num}. "
                            "Hardcoded credentials in IaC files risk exposure via source control "
                            "or artifact storage."
                        ),
                        remediation=_IAC_002_REMEDIATION,
                        details={
                            "file": str(path),
                            "line": str(line_num),
                            "pattern": pattern.pattern_id,
                            "credential_type": pattern.description,
                            "line_preview": stripped[:120],
                        },
                    )
                )
                break  # one finding per pattern per line; continue to next line

        return findings


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"
