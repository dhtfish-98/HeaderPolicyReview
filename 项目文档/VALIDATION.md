# Validation record

## Version 0.1.2 maintenance

The descriptor-ownership failure path was checked with a synthetic local file and a forced stream-construction error. The current source suite passed on Python 3.14.6 before publication; exact counts and public CI belong in the delivery receipt. This check does not exercise a live target.

## Version 0.1.1 maintenance

The HSTS declaration parser and version display were checked against synthetic local HAR input on Python 3.14.6. The source suite passed in the independent current-HEAD checkout before publication; the exact test count and public-commit CI must be recorded with the delivery receipt. This does not prove browser enforcement, live-site behavior, or CVP approval.

Scope: Absent or disabled HSTS for HTTPS and absent CSP/nosniff for HTML.

Local checks to rerun:

```sh
python -m unittest discover -s tests -v
python cli.py --help
python -m compileall -q review.py cli.py tests
```

Check the exact public GitHub commit and its workflow run separately after publishing. Tests use synthetic input; no production system or external target is exercised. A HAR may contain sensitive data; use a scrubbed export. This tool does not issue requests or prove browser enforcement or policy quality.

## Current source result (2026-10-02)

- Python 3.14.6: 8/8 unit and CLI integration tests passed.
- Tests include the specific malformed-input, incomplete-review and declaration cases added during the source audit.
- Malformed HAR header records are errors. Empty CSP, repeated security headers, disabled/ambiguous HSTS, and HTML MIME metadata are reviewed. No policy strength or browser enforcement verdict is produced.
- Test input is synthetic. No external target, live credential or production cluster is exercised.
- The public commit and its corresponding GitHub workflow must be verified separately after this update.
