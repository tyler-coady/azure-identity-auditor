"""AI-001, AI-002: Cognitive Services / Azure OpenAI managed identity checks."""

from __future__ import annotations

from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient

from ..models import Finding, FindingSource, ScanResult, Severity
from .base import LiveScanner

_AI_001_REMEDIATION = (
    "Set 'disableLocalAuth: true' on the Cognitive Services account. "
    "Ensure all callers authenticate via managed identity (DefaultAzureCredential) before disabling keys. "
    "In Bicep: set 'disableLocalAuth: true' in the account properties. "
    "In ARM: set 'properties.disableLocalAuth' to true."
)

_AI_002_REMEDIATION = (
    "Enable a system-assigned or user-assigned managed identity on the Cognitive Services account. "
    "In Bicep: add 'identity: { type: \"SystemAssigned\" }'. "
    "Then grant calling services the 'Cognitive Services User' role on this resource via RBAC."
)


class AIServicesScanner(LiveScanner):
    name = "ai-services"
    description = "Checks Cognitive Services / Azure OpenAI accounts for managed identity configuration"

    def scan(self) -> ScanResult:
        result = ScanResult(subscription_id=self.subscription_id)
        client = CognitiveServicesManagementClient(self.credential, self.subscription_id)

        try:
            accounts = list(client.accounts.list())
        except Exception as exc:
            result.errors.append(f"[ai-services] Failed to list accounts: {exc}")
            return result

        for account in accounts:
            try:
                result.findings.extend(self._check_account(account))
            except Exception as exc:
                result.errors.append(f"[ai-services] Error checking {account.name}: {exc}")

        return result

    def _check_account(self, account: object) -> list[Finding]:
        findings: list[Finding] = []
        resource_group = account.id.split("/resourceGroups/")[1].split("/")[0]  # type: ignore[union-attr]
        resource_type = f"Microsoft.CognitiveServices/accounts ({account.kind})"  # type: ignore[union-attr]

        # AI-001: Local key authentication not disabled
        disable_local_auth = getattr(getattr(account, "properties", None), "disable_local_auth", None)
        if not disable_local_auth:
            findings.append(
                Finding(
                    rule_id="AI-001",
                    title="AI service has local key authentication enabled",
                    severity=Severity.HIGH,
                    source=FindingSource.LIVE_AZURE,
                    resource_id=account.id,  # type: ignore[union-attr]
                    resource_type=resource_type,
                    subscription_id=self.subscription_id,
                    resource_group=resource_group,
                    description=(
                        f"The Cognitive Services account '{account.name}' has local key authentication enabled "  # type: ignore[union-attr]
                        "(disableLocalAuth is false or unset). Callers can authenticate using API keys, "
                        "bypassing managed identity and increasing the risk of credential exposure."
                    ),
                    remediation=_AI_001_REMEDIATION,
                    details={
                        "kind": str(account.kind),  # type: ignore[union-attr]
                        "location": str(account.location),  # type: ignore[union-attr]
                        "disable_local_auth": str(disable_local_auth),
                    },
                )
            )

        # AI-002: No managed identity assigned
        identity = getattr(account, "identity", None)
        identity_type = getattr(identity, "type", None)
        has_identity = identity is not None and str(identity_type).lower() not in ("", "none", "null")
        if not has_identity:
            findings.append(
                Finding(
                    rule_id="AI-002",
                    title="AI service has no managed identity assigned",
                    severity=Severity.HIGH,
                    source=FindingSource.LIVE_AZURE,
                    resource_id=account.id,  # type: ignore[union-attr]
                    resource_type=resource_type,
                    subscription_id=self.subscription_id,
                    resource_group=resource_group,
                    description=(
                        f"The Cognitive Services account '{account.name}' does not have a managed identity. "  # type: ignore[union-attr]
                        "Without a managed identity, dependent services cannot use identity-based authentication "
                        "to access this resource, forcing the use of API keys."
                    ),
                    remediation=_AI_002_REMEDIATION,
                    details={
                        "kind": str(account.kind),  # type: ignore[union-attr]
                        "identity_type": str(identity_type),
                    },
                )
            )

        return findings
