"""Tests for the IaC file scanner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from azure_identity_auditor.models import Severity
from azure_identity_auditor.scanners.iac import IaCScanner


# ---------------------------------------------------------------------------
# ARM template (JSON)
# ---------------------------------------------------------------------------

def test_arm_template_hardcoded_api_key_detected(arm_template_with_secret):
    scanner = IaCScanner([arm_template_with_secret])
    result = scanner.scan()
    rule_ids = [f.rule_id for f in result.findings]
    assert "IAC-001" in rule_ids


def test_arm_template_connection_string_detected(arm_template_with_secret):
    scanner = IaCScanner([arm_template_with_secret])
    result = scanner.scan()
    # Connection string is caught by text scan (not ARM structural check)
    findings_text = " ".join(f.description for f in result.findings)
    assert len(result.findings) > 0


def test_arm_template_parameter_reference_safe(arm_template_clean):
    scanner = IaCScanner([arm_template_clean])
    result = scanner.scan()
    assert result.findings == []


def test_arm_findings_do_not_contain_raw_secret(arm_template_with_secret):
    scanner = IaCScanner([arm_template_with_secret])
    result = scanner.scan()
    for f in result.findings:
        for v in f.details.values():
            assert "hardcodedSecret99" not in v
            assert "abc123def456" not in v


# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------

def test_terraform_openai_key_detected(terraform_with_secret):
    scanner = IaCScanner([terraform_with_secret])
    result = scanner.scan()
    assert any(f.rule_id == "IAC-002" for f in result.findings)


def test_terraform_clean_no_findings(terraform_clean):
    scanner = IaCScanner([terraform_clean])
    result = scanner.scan()
    assert result.findings == []


# ---------------------------------------------------------------------------
# Bicep
# ---------------------------------------------------------------------------

def test_bicep_secret_detected(tmp_path: Path):
    bicep = tmp_path / "main.bicep"
    bicep.write_text(
        "param location string = 'eastus'\n"
        "var apiKey = 'hardcodedapikey1234567890abcdef'\n"
    )
    scanner = IaCScanner([bicep])
    result = scanner.scan()
    assert any(f.rule_id == "IAC-002" for f in result.findings)


def test_bicep_param_reference_safe(tmp_path: Path):
    bicep = tmp_path / "safe.bicep"
    bicep.write_text(
        "@secure()\nparam apiKey string\n"
        "resource account 'Microsoft.CognitiveServices/accounts@2022-03-01' = {\n"
        "  properties: { apiKey: apiKey }\n"
        "}\n"
    )
    scanner = IaCScanner([bicep])
    result = scanner.scan()
    assert result.findings == []


# ---------------------------------------------------------------------------
# YAML pipelines
# ---------------------------------------------------------------------------

def test_yaml_hardcoded_key_detected(tmp_path: Path):
    yaml = tmp_path / "deploy.yml"
    yaml.write_text(
        "steps:\n"
        "  - script: echo hello\n"
        "    env:\n"
        "      api_key: 'hardcodedapikey1234567890abcdef'\n"
    )
    scanner = IaCScanner([yaml])
    result = scanner.scan()
    assert any(f.rule_id == "IAC-002" for f in result.findings)


def test_yaml_secret_expression_safe(tmp_path: Path):
    yaml = tmp_path / "safe.yml"
    yaml.write_text(
        "steps:\n"
        "  - script: echo hello\n"
        "    env:\n"
        "      api_key: ${{ secrets.OPENAI_KEY }}\n"
    )
    scanner = IaCScanner([yaml])
    result = scanner.scan()
    assert result.findings == []


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_binary_file_skipped(tmp_path: Path):
    binary = tmp_path / "data.json"
    binary.write_bytes(b"\x00\x01\x02\x03" + b"api_key=secret123456789abcdef")
    scanner = IaCScanner([binary])
    result = scanner.scan()
    assert result.findings == []


def test_oversized_file_skipped(tmp_path: Path, monkeypatch):
    from azure_identity_auditor.scanners import iac as iac_module
    monkeypatch.setattr(iac_module, "MAX_FILE_BYTES", 10)
    big = tmp_path / "big.tf"
    big.write_text('api_key = "hardcodedapikey1234567890abcdef"\n' * 100)
    scanner = IaCScanner([big])
    result = scanner.scan()
    assert result.findings == []


def test_skip_dirs_respected(tmp_path: Path):
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    bad = node_modules / "config.json"
    bad.write_text('{"api_key": "hardcodedapikey1234567890abcdef"}')
    scanner = IaCScanner([tmp_path])
    result = scanner.scan()
    assert result.findings == []


def test_scan_directory_recursively(tmp_path: Path):
    subdir = tmp_path / "infra" / "modules"
    subdir.mkdir(parents=True)
    tf = subdir / "main.tf"
    tf.write_text('api_key = "hardcodedapikey1234567890abcdef"\n')
    scanner = IaCScanner([tmp_path])
    result = scanner.scan()
    assert len(result.findings) >= 1
