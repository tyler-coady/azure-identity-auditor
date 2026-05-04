"""Tests for the AIServicesScanner."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from azure_identity_auditor.models import Severity
from azure_identity_auditor.scanners.ai_services import AIServicesScanner


def _make_account(
    name: str = "my-openai",
    disable_local_auth: bool | None = None,
    identity_type: str | None = None,
    kind: str = "OpenAI",
    location: str = "eastus",
    sub_id: str = "sub-123",
) -> MagicMock:
    account = MagicMock()
    account.name = name
    account.kind = kind
    account.location = location
    account.id = f"/subscriptions/{sub_id}/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/{name}"
    account.properties.disable_local_auth = disable_local_auth
    if identity_type is None:
        account.identity = None
    else:
        account.identity = MagicMock()
        account.identity.type = identity_type
    return account


@patch("azure_identity_auditor.scanners.ai_services.CognitiveServicesManagementClient")
def test_local_auth_enabled_creates_ai001(MockClient, mock_credential):
    account = _make_account(disable_local_auth=False, identity_type="SystemAssigned")
    MockClient.return_value.accounts.list.return_value = [account]

    scanner = AIServicesScanner(mock_credential, "sub-123")
    result = scanner.scan()

    ai001 = [f for f in result.findings if f.rule_id == "AI-001"]
    assert len(ai001) == 1
    assert ai001[0].severity == Severity.HIGH


@patch("azure_identity_auditor.scanners.ai_services.CognitiveServicesManagementClient")
def test_local_auth_disabled_no_ai001(MockClient, mock_credential):
    account = _make_account(disable_local_auth=True, identity_type="SystemAssigned")
    MockClient.return_value.accounts.list.return_value = [account]

    scanner = AIServicesScanner(mock_credential, "sub-123")
    result = scanner.scan()

    assert not any(f.rule_id == "AI-001" for f in result.findings)


@patch("azure_identity_auditor.scanners.ai_services.CognitiveServicesManagementClient")
def test_no_identity_creates_ai002(MockClient, mock_credential):
    account = _make_account(disable_local_auth=True, identity_type=None)
    MockClient.return_value.accounts.list.return_value = [account]

    scanner = AIServicesScanner(mock_credential, "sub-123")
    result = scanner.scan()

    ai002 = [f for f in result.findings if f.rule_id == "AI-002"]
    assert len(ai002) == 1
    assert ai002[0].severity == Severity.HIGH


@patch("azure_identity_auditor.scanners.ai_services.CognitiveServicesManagementClient")
def test_identity_assigned_no_ai002(MockClient, mock_credential):
    account = _make_account(disable_local_auth=True, identity_type="SystemAssigned")
    MockClient.return_value.accounts.list.return_value = [account]

    scanner = AIServicesScanner(mock_credential, "sub-123")
    result = scanner.scan()

    assert not any(f.rule_id == "AI-002" for f in result.findings)


@patch("azure_identity_auditor.scanners.ai_services.CognitiveServicesManagementClient")
def test_sdk_exception_appended_to_errors(MockClient, mock_credential):
    MockClient.return_value.accounts.list.side_effect = Exception("403 Forbidden")

    scanner = AIServicesScanner(mock_credential, "sub-123")
    result = scanner.scan()

    assert result.findings == []
    assert any("403" in e for e in result.errors)


@patch("azure_identity_auditor.scanners.ai_services.CognitiveServicesManagementClient")
def test_both_findings_on_misconfigured_account(MockClient, mock_credential):
    account = _make_account(disable_local_auth=False, identity_type=None)
    MockClient.return_value.accounts.list.return_value = [account]

    scanner = AIServicesScanner(mock_credential, "sub-123")
    result = scanner.scan()

    rule_ids = {f.rule_id for f in result.findings}
    assert "AI-001" in rule_ids
    assert "AI-002" in rule_ids
