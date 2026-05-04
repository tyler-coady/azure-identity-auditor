"""Tests for JSON and HTML reporters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from azure_identity_auditor.reporters import HtmlReporter, JsonReporter
from azure_identity_auditor.models import Severity


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------

def test_json_reporter_output_is_valid_json(sample_scan_result):
    output = JsonReporter().write(sample_scan_result)
    data = json.loads(output)
    assert data["total_findings"] == 2
    assert "findings" in data
    assert "summary" in data


def test_json_reporter_enums_serialized_as_strings(sample_scan_result):
    output = JsonReporter().write(sample_scan_result)
    data = json.loads(output)
    for f in data["findings"]:
        assert isinstance(f["severity"], str)
        assert isinstance(f["source"], str)


def test_json_reporter_writes_file(tmp_path, sample_scan_result):
    JsonReporter().write(sample_scan_result, output_dir=tmp_path)
    report_file = tmp_path / "report.json"
    assert report_file.exists()
    data = json.loads(report_file.read_text())
    assert data["total_findings"] == 2


def test_json_reporter_summary_counts(sample_scan_result):
    output = JsonReporter().write(sample_scan_result)
    data = json.loads(output)
    assert data["summary"]["CRITICAL"] == 1
    assert data["summary"]["HIGH"] == 1


# ---------------------------------------------------------------------------
# HTML reporter
# ---------------------------------------------------------------------------

def test_html_reporter_is_valid_html(sample_scan_result):
    output = HtmlReporter().write(sample_scan_result)
    assert output.strip().startswith("<!DOCTYPE html>")
    assert "</html>" in output


def test_html_reporter_contains_rule_ids(sample_scan_result):
    output = HtmlReporter().write(sample_scan_result)
    assert "AI-001" in output
    assert "IAC-002" in output


def test_html_reporter_contains_severity_badges(sample_scan_result):
    output = HtmlReporter().write(sample_scan_result)
    assert "CRITICAL" in output
    assert "HIGH" in output


def test_html_reporter_writes_file(tmp_path, sample_scan_result):
    HtmlReporter().write(sample_scan_result, output_dir=tmp_path)
    report_file = tmp_path / "report.html"
    assert report_file.exists()
    assert "<!DOCTYPE html>" in report_file.read_text()


def test_html_reporter_empty_result():
    from azure_identity_auditor.models import ScanResult
    result = ScanResult()
    output = HtmlReporter().write(result)
    assert "No findings" in output
