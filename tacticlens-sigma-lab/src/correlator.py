import json


def related_ids(result):
    """Adapt native Sigma correlation results; no Python rule interpreter."""
    identities = json.loads(result["event_ids"])
    # Backend 2.2 namespaces IDs by source index. This adapter uses only logs (0).
    if any(not isinstance(value, str) or not value.startswith("0:") for value in identities):
        raise ValueError("Unsupported correlation source identity")
    return [value.split(":", 1)[1] for value in identities]
