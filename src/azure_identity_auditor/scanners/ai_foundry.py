"""FOUNDRY-001 – 004: Azure AI Foundry Hub / Project workspace checks.

Uses azure-mgmt-resource (already a core dependency) and the ARM send_request()
method for ML-specific sub-resource calls, avoiding the outdated
azure-mgmt-machinelearningservices track-1 SDK.

Covered resource types:
  Microsoft.MachineLearningServices/workspaces          (Hub, Project)
  .../workspaces/onlineEndpoints
  .../workspaces/serverlessEndpoints
  .../workspaces/connections
"""

from __future__ import annotations

from azure.core.rest import HttpRequest
from azure.mgmt.resource import ResourceManagementClient

from ..models import Finding, FindingSource, ScanResult, Severity
from .base import LiveScanner

_ARM_ENDPOINT = "https://management.azure.com"

# Stable API version for ML Services workspace resources and connections
_WS_API = "2024-04-01"
# API version that supports serverless endpoints (model-catalog deployments)
_SERVERLESS_API = "2024-04-01"
# Stable API version for online endpoints
_ONLINE_API = "2023-10-01"

_KEY_AUTH_MODES: frozenset[str] = frozenset(["Key", "key", "KEY"])
_KEY_CONN_AUTH_TYPES: frozenset[str] = frozenset(
    ["ApiKey", "SAS", "AccountKey", "PAT", "UsernamePassword"]
)

_FOUNDRY_001_REMEDIATION = (
    "Enable a system-assigned managed identity on the AI Foundry Hub or Project workspace. "
    "In Bicep: set 'identity: { type: \"SystemAssigned\" }' on the workspace resource. "
    "Then grant the workspace identity roles on its connected resources "
    "(e.g. 'Storage Blob Data Contributor', 'Cognitive Services User')."
)
_FOUNDRY_002_REMEDIATION = (
    "Change the serverless endpoint auth mode to 'AADToken'. "
    "Callers should authenticate via DefaultAzureCredential and obtain a bearer token. "
    "Grant callers the 'Azure Machine Learning Data Scientist' role on the workspace. "
    "See: https://learn.microsoft.com/azure/machine-learning/how-to-authenticate-online-endpoint"
)
_FOUNDRY_003_REMEDIATION = (
    "Change the online endpoint auth mode to 'AADToken' (preferred) or 'AMLToken'. "
    "'Key' auth requires manual rotation and risks credential exposure. "
    "Grant callers the 'Azure Machine Learning Data Scientist' role on the workspace. "
    "See: https://learn.microsoft.com/azure/machine-learning/how-to-authenticate-online-endpoint"
)
_FOUNDRY_004_REMEDIATION = (
    "Convert the workspace connection to use managed identity or AAD authentication. "
    "Delete the API-key-based connection and recreate it with authType 'ManagedIdentity' or 'AAD'. "
    "Ensure the workspace's managed identity has the required role on the target resource "
    "(e.g. 'Cognitive Services User' for OpenAI, 'Search Index Data Reader' for AI Search). "
    "See: https://learn.microsoft.com/azure/ai-studio/how-to/connections-add"
)


class AIFoundryScanner(LiveScanner):
    name = "ai-foundry"
    description = (
        "Checks Azure AI Foundry Hub/Project workspaces, serverless endpoints, "
        "online endpoints, and workspace connections for managed identity usage"
    )

    def scan(self) -> ScanResult:
        result = ScanResult(subscription_id=self.subscription_id)
        resource_client = ResourceManagementClient(self.credential, self.subscription_id)

        try:
            workspaces = list(
                resource_client.resources.list(
                    filter="resourceType eq 'Microsoft.MachineLearningServices/workspaces'",
                    expand="identity",
                )
            )
        except Exception as exc:
            result.errors.append(f"[ai-foundry] Failed to list workspaces: {exc}")
            return result

        for ws in workspaces:
            rg = _resource_group(ws.id)

            try:
                result.findings.extend(self._check_workspace(ws, rg))
            except Exception as exc:
                result.errors.append(f"[ai-foundry] Error checking workspace {ws.name}: {exc}")

            for ep_path, ep_api, rule_id, label, remediation in (
                ("serverlessEndpoints", _SERVERLESS_API, "FOUNDRY-002", "Serverless API endpoint", _FOUNDRY_002_REMEDIATION),
                ("onlineEndpoints", _ONLINE_API, "FOUNDRY-003", "Online endpoint", _FOUNDRY_003_REMEDIATION),
            ):
                try:
                    items = self._arm_list(resource_client, f"{ws.id}/{ep_path}", ep_api)
                    result.findings.extend(
                        self._check_endpoints(items, ws, rg, rule_id, label, remediation)
                    )
                except Exception as exc:
                    result.errors.append(
                        f"[ai-foundry] Error scanning {ep_path} for {ws.name}: {exc}"
                    )

            try:
                items = self._arm_list(resource_client, f"{ws.id}/connections", _WS_API)
                result.findings.extend(self._check_connections(items, ws, rg))
            except Exception as exc:
                result.errors.append(f"[ai-foundry] Error scanning connections for {ws.name}: {exc}")

        return result

    # ------------------------------------------------------------------
    # FOUNDRY-001: workspace identity
    # ------------------------------------------------------------------

    def _check_workspace(self, ws: object, rg: str) -> list[Finding]:
        identity = getattr(ws, "identity", None)
        identity_type = str(getattr(identity, "type", "") or "").lower()
        has_identity = identity is not None and identity_type not in ("", "none", "null")
        if has_identity:
            return []

        kind = str(getattr(ws, "kind", "") or "Workspace")
        return [
            Finding(
                rule_id="FOUNDRY-001",
                title=f"AI Foundry {kind} workspace has no managed identity",
                severity=Severity.HIGH,
                source=FindingSource.LIVE_AZURE,
                resource_id=ws.id,  # type: ignore[union-attr]
                resource_type=f"Microsoft.MachineLearningServices/workspaces ({kind})",
                subscription_id=self.subscription_id,
                resource_group=rg,
                description=(
                    f"The AI Foundry workspace '{ws.name}' (kind: {kind}) has no managed identity. "  # type: ignore[union-attr]
                    "Without one, the workspace cannot authenticate to connected resources "
                    "(Azure OpenAI, AI Search, Storage) without storing API keys."
                ),
                remediation=_FOUNDRY_001_REMEDIATION,
                details={
                    "kind": kind,
                    "identity_type": str(getattr(identity, "type", "None")),
                    "location": str(getattr(ws, "location", "")),
                },
            )
        ]

    # ------------------------------------------------------------------
    # FOUNDRY-002 / 003: endpoint auth mode
    # ------------------------------------------------------------------

    def _check_endpoints(
        self,
        items: list[dict],
        ws: object,
        rg: str,
        rule_id: str,
        label: str,
        remediation: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for item in items:
            props = item.get("properties", {})
            # ARM returns camelCase authMode
            auth_mode = props.get("authMode", props.get("auth_mode", ""))
            if auth_mode not in _KEY_AUTH_MODES:
                continue
            ep_name = item.get("name", "unknown")
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=f"{label} uses key authentication",
                    severity=Severity.HIGH,
                    source=FindingSource.LIVE_AZURE,
                    resource_id=item.get("id", f"{ws.id}/{ep_name}"),  # type: ignore[union-attr]
                    resource_type=item.get("type", ""),
                    subscription_id=self.subscription_id,
                    resource_group=rg,
                    description=(
                        f"The {label.lower()} '{ep_name}' in workspace '{ws.name}' uses key-based "  # type: ignore[union-attr]
                        "authentication. Callers must supply an API key, which risks exposure "
                        "in app settings, logs, or source control."
                    ),
                    remediation=remediation,
                    details={
                        "workspace": str(ws.name),  # type: ignore[union-attr]
                        "auth_mode": auth_mode,
                    },
                )
            )
        return findings

    # ------------------------------------------------------------------
    # FOUNDRY-004: workspace connections
    # ------------------------------------------------------------------

    def _check_connections(
        self, items: list[dict], ws: object, rg: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        for item in items:
            props = item.get("properties", {})
            auth_type = props.get("authType", "")
            if auth_type not in _KEY_CONN_AUTH_TYPES:
                continue
            conn_name = item.get("name", "unknown")
            category = props.get("category", "")
            target = props.get("target", "")
            findings.append(
                Finding(
                    rule_id="FOUNDRY-004",
                    title=f"Workspace connection uses {auth_type} authentication ({category or 'unknown category'})",
                    severity=Severity.MEDIUM,
                    source=FindingSource.LIVE_AZURE,
                    resource_id=item.get("id", f"{ws.id}/connections/{conn_name}"),  # type: ignore[union-attr]
                    resource_type=item.get("type", ""),
                    subscription_id=self.subscription_id,
                    resource_group=rg,
                    description=(
                        f"The workspace connection '{conn_name}' in '{ws.name}' uses {auth_type} "  # type: ignore[union-attr]
                        f"to connect to '{target or category}'. "
                        "Stored API keys in connections require manual rotation and risk exposure."
                    ),
                    remediation=_FOUNDRY_004_REMEDIATION,
                    details={
                        "workspace": str(ws.name),  # type: ignore[union-attr]
                        "auth_type": auth_type,
                        "category": category,
                        "target": target[:80] if target else "",
                    },
                )
            )
        return findings

    # ------------------------------------------------------------------
    # ARM REST helper
    # ------------------------------------------------------------------

    def _arm_list(
        self, resource_client: ResourceManagementClient, path: str, api_version: str
    ) -> list[dict]:
        """Paginated GET against the ARM REST API, returning raw JSON dicts."""
        items: list[dict] = []
        url: str | None = f"{_ARM_ENDPOINT}{path}?api-version={api_version}"
        while url:
            response = resource_client.send_request(HttpRequest("GET", url))
            response.raise_for_status()
            data: dict = response.json()
            items.extend(data.get("value", []))
            url = data.get("nextLink")
        return items


def _resource_group(resource_id: str) -> str:
    try:
        return resource_id.split("/resourceGroups/")[1].split("/")[0]
    except (IndexError, AttributeError):
        return ""
