"""CLI integration tests using CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from azure_identity_auditor.cli import main


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def iac_dir_with_secret(tmp_path: Path) -> Path:
    tf = tmp_path / "main.tf"
    # sk- prefix triggers CP-006 (CRITICAL)
    tf.write_text('openai_key = "sk-abcdefghijklmnopqrstuvwxyz123456"\n')
    return tmp_path


@pytest.fixture
def iac_dir_clean(tmp_path: Path) -> Path:
    tf = tmp_path / "main.tf"
    tf.write_text('api_key = var.api_key\n')
    return tmp_path


def test_version(runner):
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_scan_iac_finds_hardcoded_credential(runner, iac_dir_with_secret):
    result = runner.invoke(main, ["scan-iac", str(iac_dir_with_secret)])
    assert result.exit_code == 1  # CP-006 (CRITICAL) triggers --fail-on CRITICAL default
    assert "IAC-002" in result.output


def test_scan_iac_clean_exits_zero(runner, iac_dir_clean):
    result = runner.invoke(main, ["scan-iac", str(iac_dir_clean)])
    assert result.exit_code == 0


def test_scan_iac_json_format(runner, iac_dir_with_secret, tmp_path):
    out_dir = tmp_path / "out"
    result = runner.invoke(
        main,
        ["scan-iac", str(iac_dir_with_secret), "--format", "json", "--output-dir", str(out_dir)],
    )
    report = out_dir / "report.json"
    assert report.exists()
    data = json.loads(report.read_text())
    assert data["total_findings"] >= 1


def test_scan_iac_html_format(runner, iac_dir_with_secret, tmp_path):
    out_dir = tmp_path / "out"
    result = runner.invoke(
        main,
        ["scan-iac", str(iac_dir_with_secret), "--format", "html", "--output-dir", str(out_dir)],
    )
    report = out_dir / "report.html"
    assert report.exists()
    assert "<!DOCTYPE html>" in report.read_text()


def test_scan_iac_fail_on_never(runner, iac_dir_with_secret):
    result = runner.invoke(
        main,
        ["scan-iac", str(iac_dir_with_secret), "--fail-on", "never"],
    )
    assert result.exit_code == 0


def test_scan_iac_min_severity_filters(runner, iac_dir_with_secret):
    # CRITICAL findings exist; filtering to INFO should show them
    result_info = runner.invoke(
        main,
        ["scan-iac", str(iac_dir_with_secret), "--min-severity", "INFO", "--fail-on", "never"],
    )
    assert "IAC-002" in result_info.output


def test_scan_iac_multiple_paths(runner, tmp_path):
    d1 = tmp_path / "infra1"
    d2 = tmp_path / "infra2"
    d1.mkdir()
    d2.mkdir()
    (d1 / "a.tf").write_text('api_key = "hardcodedapikey1234567890abcdef"\n')
    (d2 / "b.tf").write_text('api_key = var.api_key\n')

    result = runner.invoke(main, ["scan-iac", str(d1), str(d2), "--fail-on", "never"])
    assert result.exit_code == 0
    assert "IAC-002" in result.output
