from collections import Counter
from time import perf_counter
from .alerts import generate_alerts
from .config import Config
from .database import SQLiteStore
from .engine import detect
from .evaluation import classification_metrics
from .intelligence import enrich_hashes
from .normalizer import normalize
from .rule_loader import compile_rules
from .risk import apply_scores


def analyze(records, rules_directory, config=Config(), catalog=(), labels=None, scorer=None):
    start = perf_counter()
    events, metrics = normalize(records)
    enrich_hashes(events, catalog)
    rules = compile_rules(rules_directory)
    store = SQLiteStore(events, {f for rule in rules for f in rule["required_fields"]})
    try:
        detections = detect(store, rules, events)
    finally:
        store.close()
    if scorer is not None:
        apply_scores(detections, scorer)
    alerts = generate_alerts(detections, config)
    metrics.update(detections=len(detections), alerts=len(alerts),
                   detections_by_mode=dict(Counter(m for d in detections for m in d["modalities"])),
                   detections_by_rule=dict(Counter(d["rule_id"] for d in detections)),
                   rules_compiled=len(rules), processing_seconds=perf_counter() - start,
                   classification=classification_metrics(detections, labels, [e["id_evento"] for e in events]) if labels is not None else None)
    return {"detections": detections, "alerts": alerts, "metrics": metrics}
