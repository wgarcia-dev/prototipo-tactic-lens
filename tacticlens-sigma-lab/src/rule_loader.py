import json
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from sigma.rule import SigmaRule


class RuleError(ValueError):
    pass


def compile_rules(directory):
    paths = sorted([*directory.rglob("*.yml"), *directory.rglob("*.yaml")])
    if not paths:
        raise RuleError("No Sigma rules found")
    documents = []
    for path in paths:
        try:
            # Parsing and all detection semantics belong to pySigma.
            parsed = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"), resolve_references=False)
            documents.extend(parsed.rules)
        except Exception as exc:
            raise RuleError(f"Invalid rule file {path.name}: {type(exc).__name__}") from None
    ids = [str(r.id) for r in documents]
    if "None" in ids or len(ids) != len(set(ids)):
        raise RuleError("All rules require unique UUIDs")
    if any(r.level is None for r in documents):
        raise RuleError("All rules require a severity")
    if any(isinstance(r, SigmaRule) and r.logsource.product != "cowrie" for r in documents):
        raise RuleError("This adapter only supports logsource product cowrie")
    try:
        collection = SigmaCollection(documents)
        collection.resolve_rule_references()
        return json.loads(sqliteBackend(event_id_field="id_evento", collate_nocase=True).convert(collection, "zircolite"))
    except Exception as exc:
        raise RuleError(f"Incompatible Sigma collection: {type(exc).__name__}") from None
