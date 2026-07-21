<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/airtight-logo-dark.png">
    <img src="assets/airtight-logo-light.png" alt="airtight — secure-coding gates for AI-written code" width="540">
  </picture>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-3a9d3a" alt="MIT"></a>
  <img src="https://img.shields.io/badge/works%20with-Claude%20Code%20%7C%20Cursor%20%7C%20Codex-2f6db0" alt="works with Claude Code, Cursor, Codex">
  <img src="https://img.shields.io/badge/checks-67%20across%2013%20topics-3E6FA8" alt="67 checks across 13 topics">
  <img src="https://img.shields.io/badge/mapped-OWASP%20Top%2010%20%2B%20CWE-b5502f" alt="mapped to OWASP Top 10 + CWE">
  <a href="https://github.com/Zyoffsec/airtight-secure-coding/stargazers"><img src="https://img.shields.io/github/stars/Zyoffsec/airtight-secure-coding?color=414651" alt="GitHub stars"></a>
  <a href="https://www.linkedin.com/in/ashot-mxitaryan/"><img src="https://img.shields.io/badge/LinkedIn-Ashot%20Mxitaryan-0A66C2?logo=linkedin&logoColor=white" alt="LinkedIn"></a>
</p>

**AI writes your code. Who checks it?**

Ask for a profile-update endpoint and you get a good one — validated input, parameterized query, ownership checked. The model knows all that. What it skips is the part nobody asked for: the field allowlist. The handler spreads the request body straight into the record, so send `"role": "admin"` next to your new username — and the server writes it. No error, no log, admin.

**Airtight is the part of the request nobody makes:** hard gates on what the assistant may emit, checked *before* the code reaches you.

```mermaid
flowchart LR
  A[You ask for a feature] --> B[Model writes it]
  B --> C{Airtight<br/>67 gates}
  C -->|fails| D[Rewrite]
  D --> C
  C -->|passes| E[Code that<br/>already passed]
```

## Measured, not claimed

One login brief, two agents — one with Airtight, one without. A blind third scored and ran both.

> **Twelve controls compared &rarr; 12/12 with Airtight, six missing without.**

Both builds got the fundamentals right — password hashing, parameterized SQL, `httpOnly` cookies, clean session handling. The model is not incompetent. What the control skipped is the part nobody asks for: **rate limiting, account lockout, CSRF protection, security logging, length bounds — and it shipped a guessable session-secret fallback.** Verified live: thirty guesses, thirty `401`s, zero throttle, zero records; the Airtight build answered `429` and wrote ten audit lines. **Omissions, not incompetence.**

And that is one brief. A login app wakes only a slice of the 67 gates — injection, XSS, SSRF, secrets and supply-chain checks had nothing to bite here. The full map is in [What it catches](#what-it-catches).

Both apps and the full comparison &rarr; [`validation/`](validation/).

## Install

```bash
npx skills add Zyoffsec/airtight-secure-coding
```

Or clone it into your skills folder (Claude Code, Cursor, Codex):

```bash
git clone https://github.com/Zyoffsec/airtight-secure-coding ~/.claude/skills/airtight
```

**Then forget it.** Airtight runs itself — write code as usual and the gates apply silently. No command to invoke.

## Usage

| Command | What it does |
| --- | --- |
| *(default)* | You write code; gates apply silently. |
| `airtight audit <target>` | Scores code against the gates. Read-only. |
| `airtight harden <target>` | Finds and fixes gate failures. |
| `airtight prove <target>` | Probes your local code with edge-case input. |

## What it catches

**67 gates across 13 topics**, mapped to **OWASP Top 10 (2021) + CWE**. Each is binary and numbered — every finding cites its gate. Full list &rarr; [`references/gates.md`](references/gates.md).

What it **doesn't**: business-logic bugs, unknown CVEs in your dependencies, or architecture review — those need a human. Airtight is the *first* check, on the mistakes mechanical enough to check mechanically. It never calls code "secure" — only which gates held.

## Demo

*A short recording is coming — one innocent request with one extra JSON field, an account that quietly becomes admin, then the same request against the Airtight build bouncing off Gate 13. It is the point of the whole project. [Contributions welcome.](CONTRIBUTING.md)*

---

MIT License &middot; [Contributing](CONTRIBUTING.md)
