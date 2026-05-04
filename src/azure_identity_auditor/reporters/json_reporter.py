"""JSON reporter."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ..models import Finding, FindingSource, ScanResult, Severity


class _Encoder(json.JSONEncoder):
    def default(self, obj: object) -> object:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, (Severity, FindingSource)):
            return obj.value
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, Finding):
            return obj.to_dict()
        return super().default(obj)


class JsonReporter:
    def write(self, result: ScanResult, output_dir: Path | None = None) -> str:
        from datetime import timezone

        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "subscription_id": result.subscription_id,
            "scan_duration_seconds": result.scan_duration_seconds,
            "summary": {
                sev.value: sum(1 for f in result.findings if f.severity == sev)
                for sev in Severity
            },
            "total_findings": len(result.findings),
            "errors": result.errors,
            "findings": [f.to_dict() for f in result.findings],
        }

        output = json.dumps(payload, indent=2, cls=_Encoder)

        if output_dir is not None:
            (output_dir / "report.json").write_text(output)

        return output
