"""Tests for the AIFoundryScanner."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, call, patch

import pytest

from azure_identity_auditor.models import Severity
from azure_identity_auditor.scanners.ai_foundry import AIFoundryScanner

_SUB = "sub-123"
_RG = "rg"
_WS_ID = f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.MachineLearningServices/workspaces/my-hub"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_workspace(
    name: str = "my-hub",
    kind: str = "Hub",
    identity_type: str | None = "SystemAssigned",
    resource_id: str | None = None,
) -> MagicMock:
    ws = MagicMock()
    ws.name = name
    ws.kind = kind
    ws.location = "eastus"
    ws.id = resource_id or _WS_ID.replace("my-hub", name)
    if identity_type is None:
        ws.identity = None
    else:
        ws.identity = MagicMock()
        ws.identity.type = identity_type
    return ws


def _json_response(data: dict) -> MagicMock:
    """Mock an ARM HTTP response that returns data as JSON."""
    resp = MagicMock()
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


def _arm_list_response(items: list[dict]) -> MagicMock:
    return _json_response({"value": items})


def _make_resource_client(
    workspaces: list,
    send_request_side_effect=None,
) -> MagicMock:
    client = MagicMock()
    client.resources.list.return_value = workspaces
    if send_request_side_effect is not None:
        client.send_request.side_effect = send_request_side_effect
    else:
        # Default: return empty lists for all sub-resource calls
        client.send_request.return_value = _arm_list_response([])
    return client


def _endpoint_item(name: str, auth_mode: str, ws_id: str = _WS_ID, ep_type: str = "onlineEndpoints") -> dict:
    return {
        "id": f"{ws_id}/{ep_type}/{name}",
        "name": name,
        "type": f"Microsoft.MachineLearningServices/workspaces/{ep_type}",
        "properties": {"authMode": auth_mode},
    }


def _connection_item(name: str, auth_type: str, category: str = "AzureOpenAI", target: str = "https://myoai.openai.azure.com") -> dict:
    return {
        "id": f"{_WS_ID}/connections/{name}",
        "name": name,
        "type": "Microsoft.MachineLearningServices/workspaces/connections",
        "properties": {"authType": auth_type, "category": category, "target": target},
    }


# ---------------------------------------------------------------------------
# FOUNDRY-001: workspace identity
# ---------------------------------------------------------------------------

@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_hub_no_identity_creates_foundry001(MockClient, mock_credential):
    ws = _make_workspace(identity_type=None)
    MockClient.return_value = _make_resource_client([ws])

    result = AIFoundryScanner(mock_credential, _SUB).scan()

    findings = [f for f in result.findings if f.rule_id == "FOUNDRY-001"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Hub" in findings[0].title


@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_hub_identity_type_none_string_creates_foundry001(MockClient, mock_credential):
    ws = _make_workspace(identity_type="None")
    MockClient.return_value = _make_resource_client([ws])

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    assert any(f.rule_id == "FOUNDRY-001" for f in result.findings)


@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_hub_system_assigned_identity_no_foundry001(MockClient, mock_credential):
    ws = _make_workspace(identity_type="SystemAssigned")
    MockClient.return_value = _make_resource_client([ws])

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    assert not any(f.rule_id == "FOUNDRY-001" for f in result.findings)


@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_project_workspace_checked(MockClient, mock_credential):
    ws = _make_workspace(name="my-project", kind="Project", identity_type=None)
    MockClient.return_value = _make_resource_client([ws])

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    findings = [f for f in result.findings if f.rule_id == "FOUNDRY-001"]
    assert len(findings) == 1
    assert "Project" in findings[0].title


# ---------------------------------------------------------------------------
# FOUNDRY-002: serverless endpoints
# ---------------------------------------------------------------------------

@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_serverless_key_auth_creates_foundry002(MockClient, mock_credential):
    ws = _make_workspace()
    ep = _endpoint_item("gpt4-ep", "Key", ep_type="serverlessEndpoints")

    def side_effect(request):
        if "serverlessEndpoints" in request.url:
            return _arm_list_response([ep])
        return _arm_list_response([])

    MockClient.return_value = _make_resource_client([ws], send_request_side_effect=side_effect)

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    findings = [f for f in result.findings if f.rule_id == "FOUNDRY-002"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "gpt4-ep" in findings[0].description


@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_serverless_aad_auth_no_foundry002(MockClient, mock_credential):
    ws = _make_workspace()
    ep = _endpoint_item("gpt4-ep", "AADToken", ep_type="serverlessEndpoints")

    def side_effect(request):
        if "serverlessEndpoints" in request.url:
            return _arm_list_response([ep])
        return _arm_list_response([])

    MockClient.return_value = _make_resource_client([ws], send_request_side_effect=side_effect)

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    assert not any(f.rule_id == "FOUNDRY-002" for f in result.findings)


# ---------------------------------------------------------------------------
# FOUNDRY-003: online endpoints
# ---------------------------------------------------------------------------

@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_online_key_auth_creates_foundry003(MockClient, mock_credential):
    ws = _make_workspace()
    ep = _endpoint_item("inference-ep", "Key")

    def side_effect(request):
        if "onlineEndpoints" in request.url:
            return _arm_list_response([ep])
        return _arm_list_response([])

    MockClient.return_value = _make_resource_client([ws], send_request_side_effect=side_effect)

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    findings = [f for f in result.findings if f.rule_id == "FOUNDRY-003"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_online_aad_auth_no_foundry003(MockClient, mock_credential):
    ws = _make_workspace()
    ep = _endpoint_item("inference-ep", "AADToken")

    def side_effect(request):
        if "onlineEndpoints" in request.url:
            return _arm_list_response([ep])
        return _arm_list_response([])

    MockClient.return_value = _make_resource_client([ws], send_request_side_effect=side_effect)

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    assert not any(f.rule_id == "FOUNDRY-003" for f in result.findings)


@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_online_aml_token_no_foundry003(MockClient, mock_credential):
    ws = _make_workspace()
    ep = _endpoint_item("inference-ep", "AMLToken")

    def side_effect(request):
        if "onlineEndpoints" in request.url:
            return _arm_list_response([ep])
        return _arm_list_response([])

    MockClient.return_value = _make_resource_client([ws], send_request_side_effect=side_effect)

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    assert not any(f.rule_id == "FOUNDRY-003" for f in result.findings)


# ---------------------------------------------------------------------------
# FOUNDRY-004: workspace connections
# ---------------------------------------------------------------------------

@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_api_key_connection_creates_foundry004(MockClient, mock_credential):
    ws = _make_workspace()
    conn = _connection_item("oai-conn", "ApiKey", category="AzureOpenAI")

    def side_effect(request):
        if "connections" in request.url:
            return _arm_list_response([conn])
        return _arm_list_response([])

    MockClient.return_value = _make_resource_client([ws], send_request_side_effect=side_effect)

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    findings = [f for f in result.findings if f.rule_id == "FOUNDRY-004"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "AzureOpenAI" in findings[0].title


@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_managed_identity_connection_no_foundry004(MockClient, mock_credential):
    ws = _make_workspace()
    conn = _connection_item("oai-conn", "ManagedIdentity")

    def side_effect(request):
        if "connections" in request.url:
            return _arm_list_response([conn])
        return _arm_list_response([])

    MockClient.return_value = _make_resource_client([ws], send_request_side_effect=side_effect)

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    assert not any(f.rule_id == "FOUNDRY-004" for f in result.findings)


@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_aad_connection_no_foundry004(MockClient, mock_credential):
    ws = _make_workspace()
    conn = _connection_item("search-conn", "AAD", category="CognitiveSearch")

    def side_effect(request):
        if "connections" in request.url:
            return _arm_list_response([conn])
        return _arm_list_response([])

    MockClient.return_value = _make_resource_client([ws], send_request_side_effect=side_effect)

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    assert not any(f.rule_id == "FOUNDRY-004" for f in result.findings)


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_arm_pagination_followed(MockClient, mock_credential):
    ws = _make_workspace()
    ep1 = _endpoint_item("ep-1", "Key")
    ep2 = _endpoint_item("ep-2", "Key")
    page2_url = "https://management.azure.com/next-page"

    call_count = 0

    def side_effect(request):
        nonlocal call_count
        call_count += 1
        if "onlineEndpoints" in request.url and "next-page" not in request.url:
            return _json_response({"value": [ep1], "nextLink": page2_url})
        if "next-page" in request.url:
            return _arm_list_response([ep2])
        return _arm_list_response([])

    MockClient.return_value = _make_resource_client([ws], send_request_side_effect=side_effect)

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    findings = [f for f in result.findings if f.rule_id == "FOUNDRY-003"]
    assert len(findings) == 2


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_workspace_list_failure_appended_to_errors(MockClient, mock_credential):
    MockClient.return_value.resources.list.side_effect = Exception("403 Forbidden")

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    assert result.findings == []
    assert any("403" in e for e in result.errors)


@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_endpoint_error_does_not_stop_other_checks(MockClient, mock_credential):
    ws = _make_workspace(identity_type=None)

    def side_effect(request):
        if "onlineEndpoints" in request.url:
            raise Exception("permission denied")
        return _arm_list_response([])

    MockClient.return_value = _make_resource_client([ws], send_request_side_effect=side_effect)

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    assert any(f.rule_id == "FOUNDRY-001" for f in result.findings)
    assert any("permission denied" in e for e in result.errors)


@patch("azure_identity_auditor.scanners.ai_foundry.ResourceManagementClient")
def test_multiple_workspaces_all_checked(MockClient, mock_credential):
    hub = _make_workspace(name="hub1", kind="Hub", identity_type=None)
    proj = _make_workspace(name="proj1", kind="Project", identity_type=None)
    MockClient.return_value = _make_resource_client([hub, proj])

    result = AIFoundryScanner(mock_credential, _SUB).scan()
    f001 = [f for f in result.findings if f.rule_id == "FOUNDRY-001"]
    assert len(f001) == 2
