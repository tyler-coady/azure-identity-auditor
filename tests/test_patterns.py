"""Tests for credential detection patterns."""

import pytest

from azure_identity_auditor.credentials.patterns import (
    CREDENTIAL_PATTERNS,
    match_app_settings,
    is_safe_value,
)


# ---------------------------------------------------------------------------
# is_safe_value
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "[parameters('apiKey')]",
    "[variables('secret')]",
    "[listKeys(resourceId('Microsoft.CognitiveServices/accounts', 'myai'), '2022-03-01').key1]",
    "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/key/)",
    "${API_KEY}",
    "$(API_KEY)",
    "{{ secrets.API_KEY }}",
    "var.api_key",
    "PLACEHOLDER",
    "your-api-key-here",
    "<key>",
    "",
])
def test_is_safe_value_returns_true(value):
    assert is_safe_value(value) is True


@pytest.mark.parametrize("value", [
    "abc123def456abc123def456abc12345",        # 32-char hex
    "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=" + "A" * 86 + "==",
    "sk-abcdefghijklmnopqrstuvwx12345678",
])
def test_is_safe_value_returns_false(value):
    assert is_safe_value(value) is False


# ---------------------------------------------------------------------------
# Individual patterns
# ---------------------------------------------------------------------------

class TestCP001StorageConnectionString:
    PATTERN = next(p for p in CREDENTIAL_PATTERNS if p.pattern_id == "CP-001")

    def test_matches_valid_storage_conn_string(self):
        value = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=" + "A" * 86 + "=="
        assert self.PATTERN.regex.search(value) is not None

    def test_no_match_without_account_key(self):
        value = "DefaultEndpointsProtocol=https;AccountName=myaccount;EndpointSuffix=core.windows.net"
        assert self.PATTERN.regex.search(value) is None


class TestCP006OpenAIKey:
    PATTERN = next(p for p in CREDENTIAL_PATTERNS if p.pattern_id == "CP-006")

    def test_matches_sk_prefix_key(self):
        assert self.PATTERN.regex.search('"sk-abcdefghijklmnopqrstuvwxyz123456"') is not None

    def test_no_match_short_value(self):
        assert self.PATTERN.regex.search('"sk-short"') is None


class TestCP004GenericSecret:
    PATTERN = next(p for p in CREDENTIAL_PATTERNS if p.pattern_id == "CP-004")

    def test_matches_api_key_assignment(self):
        assert self.PATTERN.regex.search('api_key = "longSecretValue123456789"') is not None

    def test_matches_password_colon(self):
        assert self.PATTERN.regex.search('password: "SuperSecretPassword1234567890"') is not None

    def test_no_match_variable_reference(self):
        assert self.PATTERN.regex.search('api_key = var.api_key') is None


# ---------------------------------------------------------------------------
# match_app_settings
# ---------------------------------------------------------------------------

def test_match_app_settings_finds_key_vault_safe():
    settings = {
        "OPENAI_KEY": "@Microsoft.KeyVault(SecretUri=https://vault.azure.net/secrets/k/)",
        "SOME_SETTING": "normal-value",
    }
    assert match_app_settings(settings) == []


def test_match_app_settings_flags_suspicious_key_name():
    settings = {
        "COGNITIVE_API_KEY": "notaplaceHolder1234567890abcdefghij",
    }
    flagged = match_app_settings(settings)
    assert len(flagged) == 1
    key, redacted, pattern = flagged[0]
    assert key == "COGNITIVE_API_KEY"
    assert "..." in redacted  # value is redacted


def test_match_app_settings_flags_connection_string_value():
    conn = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=" + "A" * 86 + "=="
    settings = {"STORAGE_CONN": conn}
    flagged = match_app_settings(settings)
    assert len(flagged) == 1
    key, redacted, pattern = flagged[0]
    assert key == "STORAGE_CONN"
    assert pattern is not None
    assert pattern.pattern_id == "CP-001"


def test_match_app_settings_raw_value_never_stored():
    settings = {"API_KEY": "supersecretvalue123456789012345678"}
    flagged = match_app_settings(settings)
    _, redacted, _ = flagged[0]
    assert "supersecret" not in redacted
    assert "..." in redacted
