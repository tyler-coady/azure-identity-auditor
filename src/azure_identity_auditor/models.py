from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.weight < other.weight


class FindingSource(str, Enum):
    LIVE_AZURE = "LIVE_AZURE"
    IAC = "IAC"
    RBAC = "RBAC"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    source: FindingSource
    resource_id: str
    description: str
    remediation: str
    subscription_id: str = ""
    resource_group: str = ""
    resource_type: str = ""
    details: dict[str, str] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "source": self.source.value,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "subscription_id": self.subscription_id,
            "resource_group": self.resource_group,
            "description": self.description,
            "remediation": self.remediation,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    subscription_id: str | None = None
    scan_duration_seconds: float = 0.0

    def merge(self, other: "ScanResult") -> None:
        self.findings.extend(other.findings)
        self.errors.extend(other.errors)

    @property
    def by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def has_severity_at_or_above(self, min_severity: Severity) -> bool:
        return any(f.severity.weight >= min_severity.weight for f in self.findings)
