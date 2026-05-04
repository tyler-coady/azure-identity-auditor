"""Shared pytest fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from azure_identity_auditor.models import Finding, FindingSource, ScanResult, Severity


@pytest.fixture
def mock_credential():
    return MagicMock()


@pytest.fixture
def sample_finding():
    return Finding(
        rule_id="AI-001",
        title="Test finding",
        severity=Severity.HIGH,
        source=FindingSource.LIVE_AZURE,
        resource_id="/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/myai",
        resource_type="Microsoft.CognitiveServices/accounts",
        subscription_id="sub-123",
        resource_group="rg",
        description="Test description",
        remediation="Test remediation",
        details={"key": "value"},
    )


@pytest.fixture
def sample_scan_result(sample_finding):
    result = ScanResult(subscription_id="sub-123")
    result.findings = [
        sample_finding,
        Finding(
            rule_id="IAC-002",
            title="Hardcoded secret in Terraform",
            severity=Severity.CRITICAL,
            source=FindingSource.IAC,
            resource_id="/path/to/main.tf",
            description="Hardcoded credential detected",
            remediation="Use Key Vault",
        ),
    ]
    return result


@pytest.fixture
def arm_template_with_secret(tmp_path: Path) -> Path:
    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "resources": [
            {
                "type": "Microsoft.Web/sites",
                "apiVersion": "2022-03-01",
                "name": "myapp",
                "properties": {
                    "siteConfig": {
                        "appSettings": [
                            {"name": "OPENAI_KEY", "value": "abc123def456abc123def456abc12345"},
                            {"name": "apiKey", "value": "hardcodedSecret99"},
                            {"name": "connectionString", "value": "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=" + "A" * 86 + "=="},
                        ]
                    }
                },
            }
        ],
    }
    p = tmp_path / "azuredeploy.json"
    p.write_text(json.dumps(template, indent=2))
    return p


@pytest.fixture
def arm_template_clean(tmp_path: Path) -> Path:
    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "apiKey": {"type": "secureString"}
        },
        "resources": [
            {
                "type": "Microsoft.Web/sites",
                "properties": {
                    "siteConfig": {
                        "appSettings": [
                            {"name": "API_KEY", "value": "[parameters('apiKey')]"},
                        ]
                    }
                },
            }
        ],
    }
    p = tmp_path / "clean.json"
    p.write_text(json.dumps(template, indent=2))
    return p


@pytest.fixture
def terraform_with_secret(tmp_path: Path) -> Path:
    content = '''
resource "azurerm_cognitive_account" "example" {
  name                = "example-account"
  resource_group_name = azurerm_resource_group.example.name
  kind                = "OpenAI"
}

resource "azurerm_app_service" "example" {
  app_settings = {
    "OPENAI_API_KEY" = "sk-abcdefghijklmnopqrstuvwx12345678"
    "API_KEY"        = "hardcodedapikey1234567890abcdef"
  }
}
'''
    p = tmp_path / "main.tf"
    p.write_text(content)
    return p


@pytest.fixture
def terraform_clean(tmp_path: Path) -> Path:
    content = '''
resource "azurerm_app_service" "example" {
  app_settings = {
    "OPENAI_API_KEY" = var.openai_api_key
    "CONN_STR"       = "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/conn/)"
  }
}
'''
    p = tmp_path / "clean.tf"
    p.write_text(content)
    return p
