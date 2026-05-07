from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import time


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class TestStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIP = "SKIP"


@dataclass
class TestResult:
    rule_name: str
    rule_file: str
    mitre_technique: str
    mitre_tactic: str
    severity: str
    status: TestStatus
    true_positive_count: int = 0
    false_positive_count: int = 0
    true_positive_rate: float = 0.0
    false_positive_rate: float = 0.0
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    duration_ms: float = 0.0


class BaseRuleChecker(ABC):
    def __init__(self):
        self._start_time: Optional[float] = None

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def validate(self, rule_content: str, malicious_samples: list, benign_samples: list) -> TestResult:
        pass

    def _start_timer(self):
        self._start_time = time.time()

    def _get_duration_ms(self) -> float:
        if self._start_time is None:
            return 0.0
        return round((time.time() - self._start_time) * 1000, 2)

    def _create_finding(self, sample: dict, matched: bool, reason: str) -> dict:
        return {
            "sample_id": sample.get("id", "unknown"),
            "matched": matched,
            "reason": reason,
            "timestamp": sample.get("TimeGenerated", "unknown")
        }
