> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# HeaderPolicyReview

Current source version: **0.1.2**. Use `python cli.py --version` to check the installed source.

Review declared security headers in a local HTTP Archive export. It runs locally, does not contact targets, and reports review prompts instead of exploit instructions.

## Input and checks

- Input: HAR JSON from a system you own or are authorized to inspect.
- Checks: Absent or disabled HSTS for HTTPS and absent CSP/nosniff for HTML.
- Output: rule, local location and short note. No source snippets, credential values or log identities are printed.

## Run

```sh
python cli.py ./owned-input
python cli.py ./owned-input --json
python -m unittest discover -s tests -v
```

Exit code 0 means no findings, 1 means review findings, 2 means invalid input or read failure. A clean result is not a security guarantee. The input file is read through a bounded regular-file descriptor with a 4 MiB limit.

## Boundaries

A HAR may contain sensitive data; use a scrubbed export. This tool does not issue requests or prove browser enforcement or policy quality. Work only on local, authorized inputs. The analysis does not send data to a service or modify the inspected files.

## Source and policy context

- Technical reference: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- See [ORIGIN.md](<ORIGIN.md>) for implementation provenance and [VALIDATION.md](<VALIDATION.md>) for checks performed.
- CVP eligibility depends on a real, legitimate defensive task affected by Claude's cyber safeguards and the applicant's organization/identity review; this repository alone does not establish eligibility or approval. [Anthropic CVP guidance](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude-opus-and-sonnet).

## Reviewed input behavior

Malformed HAR header records are errors. Empty CSP, repeated security headers, disabled/ambiguous HSTS, and HTML MIME metadata are reviewed. No policy strength or browser enforcement verdict is produced.

The HSTS declaration review conservatively checks one HAR field against RFC 6797 directive syntax: unique case-insensitive names, a positive ASCII `max-age` value (quoted or unquoted), and valueless `includeSubDomains`. Unknown syntactically valid directives and legacy CRLF folding followed by space or tab are accepted; unsupported control characters are flagged for review. It cannot establish whether a browser accepted or enforced the policy. [RFC 6797 section 6.1](https://www.rfc-editor.org/rfc/rfc6797#section-6.1).

JSON input rejects duplicate object keys and nonstandard numbers; container nesting is limited to 128 levels.
