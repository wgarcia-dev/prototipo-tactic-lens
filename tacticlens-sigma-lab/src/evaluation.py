def classification_metrics(detections, labels, event_ids):
    """Binary event-level evaluation on an explicitly, completely labelled corpus."""
    if not isinstance(labels, dict) or set(labels) != set(event_ids) or any(type(v) is not bool for v in labels.values()):
        raise ValueError("Labels must cover exactly all processed event IDs with booleans")
    predicted = {i for d in detections for i in d["event_ids"]}
    tp = sum(labels[i] and i in predicted for i in labels)
    fp = sum(not labels[i] and i in predicted for i in labels)
    fn = sum(labels[i] and i not in predicted for i in labels)
    tn = sum(not labels[i] and i not in predicted for i in labels)
    return {"unit": "event_with_any_detection", "true_positives": tp, "false_positives": fp,
            "false_negatives": fn, "true_negatives": tn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None}
