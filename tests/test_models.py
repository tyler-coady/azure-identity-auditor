"""Tests for core data models."""

from azure_identity_auditor.models import Finding, FindingSource, ScanResult, Severity


def test_severity_ordering():
    assert Severity.CRITICAL.weight > Severity.HIGH.weight
    assert Severity.HIGH.weight > Severity.MEDIUM.weight
    assert Severity.MEDIUM.weight > Severity.LOW.weight
    assert Severity.LOW.weight > Severity.INFO.weight


def test_severity_lt():
    assert Severity.INFO < Severity.LOW
    assert Severity.LOW < Severity.HIGH
    assert Severity.HIGH < Severity.CRITICAL


def test_finding_is_frozen(sample_finding):
    import pytest
    with pytest.raises((AttributeError, TypeError)):
        sample_finding.title = "changed"  # type: ignore[misc]


def test_finding_to_dict(sample_finding):
    d = sample_finding.to_dict()
    assert d["rule_id"] == "AI-001"
    assert d["severity"] == "HIGH"
    assert d["source"] == "LIVE_AZURE"
    assert "timestamp" in d


def test_scan_result_merge():
    r1 = ScanResult()
    r2 = ScanResult()
    f = Finding(
        rule_id="X-001",
        title="t",
        severity=Severity.HIGH,
        source=FindingSource.IAC,
        resource_id="a",
        description="d",
        remediation="r",
    )
    r2.findings.append(f)
    r2.errors.append("err")
    r1.merge(r2)
    assert len(r1.findings) == 1
    assert len(r1.errors) == 1


def test_scan_result_has_severity(sample_scan_result):
    assert sample_scan_result.has_severity_at_or_above(Severity.CRITICAL)
    assert sample_scan_result.has_severity_at_or_above(Severity.HIGH)
    assert not sample_scan_result.has_severity_at_or_above(Severity.CRITICAL) is False


def test_scan_result_by_severity(sample_scan_result):
    by_sev = sample_scan_result.by_severity
    assert len(by_sev[Severity.CRITICAL]) == 1
    assert len(by_sev[Severity.HIGH]) == 1
