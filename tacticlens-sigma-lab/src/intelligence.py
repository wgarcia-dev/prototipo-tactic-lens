"""Optional, offline, operator-curated hash intelligence; never trust event labels."""
import re
from .normalizer import parse_time


def enrich_hashes(events, catalog):
    verified = {}
    for entry in catalog:
        digest = entry.get("sha256", "").lower()
        if (not re.fullmatch(r"[0-9a-f]{64}", digest) or entry.get("verified") is not True
                or not entry.get("source") or not entry.get("reference")):
            raise ValueError("Hash intelligence requires SHA256, verification and provenance")
        parse_time(entry.get("verified_at"))
        verified[digest] = entry
    for event in events:
        digest = str(event.get("sha256") or event.get("shasum") or "").lower()
        event["verified_malware"] = (event["eventid"] in {"cowrie.session.file_download", "cowrie.session.file_upload"}
                                     and digest in verified)
        if event["verified_malware"]:
            event["_hash_provenance"] = verified[digest]
