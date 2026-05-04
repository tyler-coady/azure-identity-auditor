"""APP-001, APP-002: App Service / Function App app-settings credential checks."""

from __future__ import annotations

from azure.mgmt.web import WebSiteManagementClient

from ..credentials.patterns import match_app_settings
from ..models import Finding, FindingSource, ScanResult, Severity
from .base import LiveScanner

_APP_001_REMEDIATION = (
    "Replace the hardcoded credential with a Key Vault reference "
    "(@Microsoft.KeyVault(SecretUri=...)) or refactor the application to use "
    "DefaultAzureCredential with managed identity — eliminating the need for a key entirely. "
    "See: https://learn.microsoft.com/azure/app-service/app-service-key-vault-references"
)

_APP_002_REMEDIATION = (
    "Switch to managed identity for Azure Storage / Service Bus access. "
    "Remove the connection string with embedded key and grant the app's managed identity "
    "the appropriate data-plane role (e.g. 'Storage Blob Data Contributor'). "
    "Update connection configuration to use the identity-based endpoint format."
)


class AppServicesScanner(LiveScanner):
    name = "app-services"
    description = "Checks App Service and Function Apps for hardcoded AI credentials in app settings"

    def scan(self) -> ScanResult:
        result = ScanResult(subscription_id=self.subscription_id)
        client = WebSiteManagementClient(self.credential, self.subscription_id)

        try:
            sites = list(client.web_apps.list())
        except Exception as exc:
            result.errors.append(f"[app-services] Failed to list web apps: {exc}")
            return result

        for site in sites:
            try:
                result.findings.extend(self._check_site(client, site))
            except Exception as exc:
                result.errors.append(f"[app-services] Error checking {site.name}: {exc}")

        return result

    def _check_site(self, client: WebSiteManagementClient, site: object) -> list[Finding]:
        findings: list[Finding] = []
        resource_group = site.resource_group  # type: ignore[union-attr]

        try:
            settings_obj = client.web_apps.list_application_settings(resource_group, site.name)  # type: ignore[union-attr]
        except Exception:
            return findings

        settings: dict[str, str] = dict(settings_obj.properties or {})
        if not settings:
            return findings

        flagged = match_app_settings(settings)
        for key, redacted_value, pattern in flagged:
            is_connection_string = pattern is not None and "connection" in pattern.description.lower()
            rule_id = "APP-002" if is_connection_string else "APP-001"
            remediation = _APP_002_REMEDIATION if is_connection_string else _APP_001_REMEDIATION
            title = (
                "App setting contains embedded storage/service connection string"
                if is_connection_string
                else "App setting contains potential hardcoded credential"
            )

            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=Severity.CRITICAL,
                    source=FindingSource.LIVE_AZURE,
                    resource_id=site.id,  # type: ignore[union-attr]
                    resource_type=str(site.type),  # type: ignore[union-attr]
                    subscription_id=self.subscription_id,
                    resource_group=resource_group,
                    description=(
                        f"App setting '{key}' in '{site.name}' appears to contain a hardcoded credential. "
                        "Hardcoded credentials in app settings risk exposure through logs, "
                        "ARM exports, and configuration dumps."
                    ),
                    remediation=remediation,
                    details={
                        "setting_key": key,
                        "value_preview": redacted_value,
                        "matched_pattern": pattern.pattern_id if pattern else "key-name-heuristic",
                    },
                )
            )

        return findings
