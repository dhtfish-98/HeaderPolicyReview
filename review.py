"""Review security header declarations in an exported local HAR file."""
from __future__ import annotations
from collections import defaultdict
import re
from urllib.parse import urlsplit
from strict_json import loads

RELEVANT = {"content-type", "strict-transport-security", "content-security-policy", "x-content-type-options"}


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
            names[item["name"].lower()].append(item["value"].lower().strip())
        where = f"log.entries[{index}]"
        def add(rule, note):
            findings.append({"rule": rule, "location": where, "note": note})
        if any(len(names[field]) > 1 for field in RELEVANT):
            add("duplicate-security-header", "Repeated security or content-type headers need ambiguity review")
        if parsed.scheme.lower() == "https":
            hsts_values = names["strict-transport-security"]
            def active(value):
                matches = re.findall(r"(?:^|;)\s*max-age\s*=\s*(\d+)(?=\s*;|\s*$)", value)
                return len(matches) == 1 and bool(matches[0].strip("0"))
            if not hsts_values or not all(active(value) for value in hsts_values):
                add("hsts-review", "HTTPS response lacks an unambiguous active HSTS declaration")
        content = response.get("content", {})
        if not isinstance(content, dict):
            raise ValueError("HAR content must be an object")
        mime = content.get("mimeType", "")
        if not isinstance(mime, str):
            raise ValueError("HAR mimeType must be a string")
        html = mime.lower().partition(";")[0].strip() == "text/html" or any(value.partition(";")[0].strip() == "text/html" for value in names["content-type"])
        if html:
            if not names["content-security-policy"] or any(not value for value in names["content-security-policy"]):
                add("csp-review", "HTML response lacks a nonempty CSP declaration")
            if not names["x-content-type-options"] or any(value != "nosniff" for value in names["x-content-type-options"]):
                add("nosniff-review", "HTML response lacks an unambiguous nosniff declaration")
    return findings
