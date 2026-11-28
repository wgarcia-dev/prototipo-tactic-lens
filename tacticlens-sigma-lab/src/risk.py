from typing import Protocol


class RiskScorer(Protocol):
    """Future policy injection; no arbitrary score is invented by this PoC."""
    def score(self, detection: dict) -> int: ...


def apply_scores(detections, scorer: RiskScorer):
    for detection in detections:
        score = scorer.score(detection)
        if type(score) is not int or not 0 <= score <= 100:
            raise ValueError("Risk scorer must return an integer in [0, 100]")
        detection["risk_score"] = score
