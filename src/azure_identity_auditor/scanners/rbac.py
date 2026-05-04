"""RBAC-001: Managed identity role assignment checks for AI services."""

from __future__ import annotations

from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient

from ..models import Finding, FindingSource, ScanResult, Severity
from .base import LiveScanner

# Well-known role definition IDs for Cognitive Services data-plane access
COGNITIVE_SERVICES_ROLE_IDS: frozenset[str] = frozenset(
    [
        "a97b65f3-24c7-4388-baec-2e87135dc908",  # Cognitive Services User
        "25fbc0a9-bd7c-42a3-aa1a-3b75d497ee68",  # Cognitive Services Contributor
        "5e0bd9bd-7b93-4f28-af87-19fc36ad61bd",  # Cognitive Services OpenAI User
        "a001fd3d-188f-4b5d-821b-7da978bf7442",  # Cognitive Services OpenAI Contributor
        "f2dc8367-1007-4938-bd23-fe263f013447",  # Cognitive Services Speech User
        "0e75ca1e-0464-4b4d-8b93-68208522f2ff",  # Cognitive Services Speech Contributor
    ]
)

_RBAC_001_REMEDIATION = (
    "Grant the calling service's managed identity the 'Cognitive Services User' role "
    "(or 'Cognitive Services OpenAI User' for Azure OpenAI) on this resource. "
    "Example Azure CLI: az role assignment create "
    "--role 'Cognitive Services User' "
    "--assignee <managed-identity-principal-id> "
    "--scope <resource-id>"
)


class RBACScanner(LiveScanner):
    name = "rbac"
    description = "Checks whether managed identities hold appropriate roles on AI services"

    def scan(self) -> ScanResult:
        result = ScanResult(subscription_id=self.subscription_id)
        cs_client = CognitiveServicesManagementClient(self.credential, self.subscription_id)
        auth_client = AuthorizationManagementClient(self.credential, self.subscription_id)

        try:
            accounts = list(cs_client.accounts.list())
        except Exception as exc:
            result.errors.append(f"[rbac] Failed to list accounts: {exc}")
            return result

        for account in accounts:
            try:
                result.findings.extend(self._check_account_rbac(auth_client, account))
            except Exception as exc:
                result.errors.append(f"[rbac] Error checking {account.name}: {exc}")

        return result

    def _check_account_rbac(
        self, auth_client: AuthorizationManagementClient, account: object
    ) -> list[Finding]:
        resource_group = account.id.split("/resourceGroups/")[1].split("/")[0]  # type: ignore[union-attr]

        try:
            assignments = list(
                auth_client.role_assignments.list_for_resource(
                    resource_group_name=resource_group,
                    resource_provider_namespace="Microsoft.CognitiveServices",
                    parent_resource_path="",
                    resource_type="accounts",
                    resource_name=account.name,  # type: ignore[union-attr]
                )
            )
        except Exception:
            return []

        ai_role_assignments = [
            a
            for a in assignments
            if any(
                role_id in (a.role_definition_id or "")
                for role_id in COGNITIVE_SERVICES_ROLE_IDS
            )
            and getattr(a, "principal_type", "") in ("ServicePrincipal", "ManagedIdentity")
        ]

        if ai_role_assignments:
            return []

        return [
            Finding(
                rule_id="RBAC-001",
                title="No managed identity holds a Cognitive Services role on this AI service",
                severity=Severity.MEDIUM,
                source=FindingSource.RBAC,
                resource_id=account.id,  # type: ignore[union-attr]
                resource_type=f"Microsoft.CognitiveServices/accounts ({account.kind})",  # type: ignore[union-attr]
                subscription_id=self.subscription_id,
                resource_group=resource_group,
                description=(
                    f"The AI service '{account.name}' has no managed identity "  # type: ignore[union-attr]
                    "with a Cognitive Services data-plane role (User/Contributor). "
                    "This suggests all callers are using key-based authentication."
                ),
                remediation=_RBAC_001_REMEDIATION,
                details={
                    "kind": str(account.kind),  # type: ignore[union-attr]
                    "total_role_assignments": str(len(assignments)),
                    "ai_role_assignments": "0",
                },
            )
        ]
