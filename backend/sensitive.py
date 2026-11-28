"""Public projections of telemetry. The stored evidence is never modified here."""
import re
from collections.abc import Mapping
from itertools import groupby
from urllib.parse import quote, quote_plus, unquote, unquote_plus, urlsplit, urlunsplit

from sqlalchemy import select

REDACTED = "[REDACTED]"
URL = re.compile(r"""[a-z][a-z0-9+.-]*://[^\s<>"']+""", re.I)
PRIVATE_KEY = re.compile(r"-----BEGIN [^-\n]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-\n]*PRIVATE KEY-----|$)", re.I)
CREDENTIAL_NAME = (
    r"password|passwd|passphrase|secret|(?:access|refresh|id)[_-]?token|token|"
    r"(?:x[_-]?)?api[_-]?key|private[_-]?key|client[_-]?secret|credential(?:s)?"
)
SECRET_FIELD = re.compile(
    rf"(?:^|[_-])(?:{CREDENTIAL_NAME}|authorization|(?:set[_-]?)?cookie)(?:$|[_-])", re.I
)
HEADER = re.compile(r"""(?im)(\b(?:proxy-authorization|authorization|set-cookie|cookie)\s*:\s*)([^\r\n'"]+)""")
CREDENTIAL = re.compile(
    rf"""(?ix)(["']?\b(?:[\w-]+[_-])?(?:{CREDENTIAL_NAME})["']?\s*[:=]\s*"""
    r"""|(?<!\S)(?:--password|--token|--secret|--api-key|--proxy-user|--user|-u)(?:\s+|=)"""
    r"""|\bsshpass\s+-p\s+|\b(?:Bearer|Basic)\s+)"""
    r"""("(?:\\.|[^"\\])*"|'[^']*'|[^\s;,'"<>&]+)"""
)
URL_SECRET = re.compile(
    rf"(?:^|[-_])(?:{CREDENTIAL_NAME}|key|auth(?:orization)?|sig(?:nature)?)(?:$|[-_])", re.I
)
RAW_FIELDS = frozenset({
    "data", "output", "stdout", "stderr", "response", "payload", "ttylog", "headers", "outfile",
})
EVENT_INTEGERS = frozenset({"src_port", "dst_port", "size", "duration", "duration_ms", "width", "height"})


def sensitive_field(name):
    name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(name)).lower()
    return name == "key" or bool(SECRET_FIELD.search(name))


def credential_parts(value):
    value = value.strip().strip("'\"")
    if value and value != REDACTED:
        yield value
        # Authorization and curl/URL credentials may also be copied without their prefix.
        if match := re.fullmatch(r"(?i)(?:bearer|basic)\s+(\S+)", value):
            yield match[1]
        if ":" in value and not any(char.isspace() for char in value):
            yield value.partition(":")[2]
        for pair in value.split(";"):
            if "=" in pair:
                yield pair.partition("=")[2].strip()


def captured_strings(value, secrets, credential=False):
    if isinstance(value, Mapping):
        for key, item in value.items():
            captured_strings(item, secrets, credential or sensitive_field(key))
    elif isinstance(value, (list, tuple)):
        for item in value:
            captured_strings(item, secrets, credential)
    elif isinstance(value, (str, int)) and not isinstance(value, bool):
        value = str(value)
        if credential:
            secrets.update(credential_parts(value))
        for pattern in (HEADER, CREDENTIAL):
            for match in pattern.finditer(value):
                secrets.update(credential_parts(match[2]))
        for match in URL.finditer(value):
            try:
                parts = urlsplit(match[0])
            except ValueError:
                continue
            for item in (parts.username, parts.password):
                if item:
                    secrets.add(unquote(item))
            segments = parts.path.split("/")
            secrets.update(unquote(item) for name, item in zip(segments, segments[1:])
                           if URL_SECRET.fullmatch(unquote(name)))
            for component in (parts.query, parts.fragment):
                for parameter in re.split(r"[&;]", component):
                    name, sep, item = parameter.partition("=")
                    if sep and URL_SECRET.search(unquote_plus(name)):
                        secrets.add(unquote_plus(item))


class Redactor:
    def __init__(self, sources=()):
        secrets = set()
        for value in sources:
            captured_strings(value, secrets)
        aliases = {form for value in secrets if value and value != REDACTED
                   for form in (value, quote(value, safe=""), quote_plus(value, safe=""))}
        alternatives = []
        for value in sorted(aliases, key=lambda item: (-len(item), item)):
            escaped = re.escape(value)
            # Common short passwords should not alter words, identifiers, or hashes.
            alternatives.append(escaped if len(value) >= 5 else rf"(?<!\w){escaped}(?!\w)")
        self.captured = re.compile("|".join(alternatives)) if alternatives else None

    def replace_captured(self, value):
        return self.captured.sub(REDACTED, value) if self.captured else value

    def url(self, value):
        try:
            parts = urlsplit(value)
            if not parts.hostname:
                return "[URL omitida]"
            authority = parts.netloc.rsplit("@", 1)[-1]
            if self.captured and self.captured.search(unquote(authority)):
                return REDACTED
            segments = parts.path.split("/")
            path = "/".join(
                REDACTED if (index and URL_SECRET.fullmatch(unquote(segments[index - 1])))
                or (self.captured and self.captured.search(unquote(segment))) else segment
                for index, segment in enumerate(segments)
            )
            def public_component(component):
                parameters = re.split(r"[&;]", component)
                if any(URL_SECRET.search(unquote_plus(part.partition("=")[0])) for part in parameters):
                    return ""
                if self.captured and self.captured.search(unquote_plus(component)):
                    return ""
                return component
            query = "" if parts.username is not None else public_component(parts.query)
            fragment = "" if parts.username is not None else public_component(parts.fragment)
            return urlunsplit((parts.scheme, authority, path, query, fragment))
        except ValueError:
            return "[URL omitida]"

    def text(self, value, *, observable_url=False):
        if not isinstance(value, str):
            return self.payload(value)
        if observable_url and URL.fullmatch(value):
            return self.url(value)
        value = PRIVATE_KEY.sub(REDACTED, value)
        # Clean inline credentials before applying the contextual replacement.
        # URL parameters and userinfo are parsed before substitutions alter their syntax.
        parts = []
        start = 0
        for match in URL.finditer(value):
            parts.extend((self._plain(value[start:match.start()]), self.url(match[0])))
            start = match.end()
        parts.append(self._plain(value[start:]))
        return "".join(parts)

    def _plain(self, value):
        value = HEADER.sub(r"\1" + REDACTED, value)
        value = CREDENTIAL.sub(r"\1" + REDACTED, value)
        return self.replace_captured(value)

    def payload(self, value, *, raw_event=False, field=None):
        if isinstance(value, Mapping):
            result = {}
            for key, item in value.items():
                public_key = self.replace_captured(key) if raw_event and isinstance(key, str) else key
                if sensitive_field(key) or (raw_event and str(key).lower() in RAW_FIELDS):
                    public = REDACTED
                elif key == "datos_originales":
                    public = self.payload(item, raw_event=True)
                else:
                    public = self.payload(item, raw_event=raw_event, field=key)
                result[public_key] = public
            return result
        if isinstance(value, (list, tuple)):
            return [self.payload(item, raw_event=raw_event, field=field) for item in value]
        if isinstance(value, str) and field in {
            "evento", "eventos", "id_evento", "id_evento_texto", "eventos_texto", "evento_orden",
            "eventos_entregados", "referencias_tty", "command_event_id",
        } and re.fullmatch(r"[0-9]{1,19}", value):
            return value
        if isinstance(value, str) and field in {"codigo_mitre", "codigo_tecnica", "codigo_tactica"} and re.fullmatch(
            r"(?:TA[0-9]{4}|T[0-9]{4}(?:\.[0-9]{3})?)", value
        ):
            return value
        if raw_event and type(value) is int and field not in EVENT_INTEGERS and self.captured:
            if self.captured.fullmatch(str(value)):
                return REDACTED
        return self.text(value) if isinstance(value, str) else value


def redact(value):
    return Redactor((value,)).payload(value)


def protected_text(sources):
    """Compatibility entry point for the narrative builder and model facts."""
    return Redactor(sources).text


def session_redactors(conn, event, session_ids):
    # Include every event of each selected session, even if the response is paged
    # or the credential was observed in a historical login outside the page.
    redactors = dict.fromkeys(session_ids)
    if not redactors:
        return redactors
    query = (select(event.c.id_sesion, event.c.datos_originales).where(event.c.id_sesion.in_(redactors))
             .order_by(event.c.id_sesion).execution_options(yield_per=256))
    with conn.execute(query) as rows:
        for sid, events in groupby(rows, key=lambda row: row.id_sesion):
            redactors[sid] = Redactor(row.datos_originales for row in events)
    return {sid: redactor or Redactor() for sid, redactor in redactors.items()}
