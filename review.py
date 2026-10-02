"""Review security header declarations in an exported local HAR file."""

from __future__ import annotations
import json
import re
from urllib.parse import urlsplit


def review_text(text: str) -> list[dict[str, str]]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid HAR JSON") from exc
    log = document.get("log") if isinstance(document, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise ValueError("expected log.entries array")
    findings = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError("HAR entry must be an object")
        request = entry.get("request", {})
        response = entry.get("response", {})
        if not isinstance(request, dict) or not isinstance(response, dict):
            raise ValueError("HAR request and response must be objects")
        url = request.get("url", "")
        headers = response.get("headers", [])
        if not isinstance(url, str) or not isinstance(headers, list):
            raise ValueError("HAR URL or headers have an invalid type")
        names = {}
        for item in headers:
            if isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(item.get("value"), str):
                names[item["name"].lower()] = item["value"].lower()
        where = f"log.entries[{index}]"
        def add(rule, note):
            findings.append({"rule": rule, "location": where, "note": note})
        if urlsplit(url).scheme.lower() == "https":
            hsts = names.get("strict-transport-security", "")
            max_age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)(?:\s*;|$)", hsts)
            if not max_age or int(max_age.group(1)) == 0:
                add("hsts-review", "HTTPS response lacks an active HSTS declaration")
        if "text/html" in names.get("content-type", ""):
            if "content-security-policy" not in names:
                add("csp-review", "HTML response lacks a CSP declaration")
            if names.get("x-content-type-options", "").strip() != "nosniff":
                add("nosniff-review", "HTML response lacks X-Content-Type-Options: nosniff")
    return findings
