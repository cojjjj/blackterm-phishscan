from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanResult:
    target: str
    domain: str | None = None
    final_url: str | None = None
    risk_score: int = 0
    threat_level: str = "UNKNOWN"
    confidence: str = "UNKNOWN"
    reasons: list[str] = field(default_factory=list)
    modules: dict[str, Any] = field(default_factory=dict)
    reports: dict[str, str | None] = field(default_factory=dict)
    summary: str | None = None