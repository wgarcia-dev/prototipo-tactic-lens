from dataclasses import dataclass

LEVELS = ("informational", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Config:
    alert_threshold: str = "high"
    grouping_seconds: int = 300

    def __post_init__(self):
        if self.alert_threshold not in LEVELS or self.grouping_seconds < 0:
            raise ValueError("Invalid alert configuration")
