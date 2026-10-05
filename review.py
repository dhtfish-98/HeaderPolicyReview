"""Review security header declarations in an exported local HAR file."""
from __future__ import annotations
from collections import defaultdict
from urllib.parse import urlsplit
from strict_json import loads

RELEVANT = {"content-type", "strict-transport-security", "content-security-policy", "x-content-type-options"}
_TOKEN_SEPARATORS = frozenset('()<>@,;:/[]?={} \t') | frozenset(('"', "\\"))
__version__ = "0.1.4"


def _active_hsts(value: str) -> bool:
    """Check one HSTS declaration's finite directive syntax and positive max-age."""
    if "\r" in value or "\n" in value:
        unfolded = []
        index = 0
        while index < len(value):
            if value.startswith("\r\n", index):
                index += 2
                if index == len(value) or value[index] not in " \t":
                    return False
                while index < len(value) and value[index] in " \t":
                    index += 1
                unfolded.append(" ")
            elif value[index] in "\r\n":
                return False
            else:
                unfolded.append(value[index])
                index += 1
        value = "".join(unfolded)
    length = len(value)

    def skip_space(position: int) -> int:
        while position < length and value[position] in " \t":
            position += 1
        return position

    def token_at(position: int) -> tuple[str, int]:
        start = position
        while position < length and "!" <= value[position] <= "~" and value[position] not in _TOKEN_SEPARATORS:
            position += 1
        return value[start:position], position

    position = 0
    seen = set()
    max_age = None
    while True:
        position = skip_space(position)
        if position == length:
            break
        if value[position] == ";":
            position += 1
            continue
        name, position = token_at(position)
        if not name:
            return False
        name = name.lower()
        if name in seen:
            return False
        seen.add(name)
        position = skip_space(position)
        directive_value = None
        if position < length and value[position] == "=":
            position = skip_space(position + 1)
            if position == length:
                return False
            if value[position] == '"':
                position += 1
                parts = []
                while position < length:
                    char = value[position]
                    if char == '"':
                        position += 1
                        break
                    if char == "\\":
                        position += 1
                        if position == length:
                            return False
                        char = value[position]
                        if char != "\t" and not 32 <= ord(char) <= 126:
                            return False
                    elif char not in " \t" and not (33 <= ord(char) <= 126 or 128 <= ord(char) <= 255):
                        return False
                    parts.append(char)
                    position += 1
                else:
                    return False
                directive_value = "".join(parts)
            else:
                directive_value, position = token_at(position)
                if not directive_value:
                    return False
            position = skip_space(position)
        if name == "max-age":
            if not directive_value or any(char not in "0123456789" for char in directive_value):
                return False
            max_age = directive_value
        elif name == "includesubdomains" and directive_value is not None:
            return False
        if position == length:
            break
        if value[position] != ";":
            return False
        position += 1
    return max_age is not None and any(char != "0" for char in max_age)


def review_text(text: str) -> list[dict[str, str]]:
    document = loads(text)
    log = document.get("log") if isinstance(document, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise ValueError("expected log.entries array")
    findings = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError("HAR entry must be an object")
        request, response = entry.get("request"), entry.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            raise ValueError("HAR request and response must be objects")
        url, headers = request.get("url"), response.get("headers")
        if not isinstance(url, str) or not url or not isinstance(headers, list):
            raise ValueError("HAR needs a URL and headers array")
        try:
            parsed = urlsplit(url)
        except ValueError as exc:
            raise ValueError("invalid HAR URL") from exc
        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
            raise ValueError("expected an absolute HTTP or HTTPS URL")
        names = defaultdict(list)
        for item in headers:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"] or not isinstance(item.get("value"), str):
                raise ValueError("HAR header needs string name and value")
            names[item["name"].lower()].append(item["value"])
        where = f"log.entries[{index}]"
        def add(rule, note):
            findings.append({"rule": rule, "location": where, "note": note})
        if any(len(names[field]) > 1 for field in RELEVANT):
            add("duplicate-security-header", "Repeated security or content-type headers need ambiguity review")
        if parsed.scheme.lower() == "https":
            hsts_values = names["strict-transport-security"]
            if not hsts_values or not all(_active_hsts(value) for value in hsts_values):
                add("hsts-review", "HTTPS response lacks an unambiguous active HSTS declaration")
        content = response.get("content", {})
        if not isinstance(content, dict):
            raise ValueError("HAR content must be an object")
        mime = content.get("mimeType", "")
        if not isinstance(mime, str):
            raise ValueError("HAR mimeType must be a string")
        html = mime.lower().partition(";")[0].strip() == "text/html" or any(value.lower().partition(";")[0].strip() == "text/html" for value in names["content-type"])
        if html:
            if not names["content-security-policy"] or any(not value.strip() for value in names["content-security-policy"]):
                add("csp-review", "HTML response lacks a nonempty CSP declaration")
            if not names["x-content-type-options"] or any(value.strip().lower() != "nosniff" for value in names["x-content-type-options"]):
                add("nosniff-review", "HTML response lacks an unambiguous nosniff declaration")
    return findings
