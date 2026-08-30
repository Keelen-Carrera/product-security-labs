# Lab 1 — Dependency, Static-Analysis, and Secrets Scans
 
**Companion to:** [threat-model.md](./threat-model.md) — read that first for architecture and the STRIDE analysis this lab cross-checks against.
**Target:** `management_service` in [`smart-kitchen-mgmt`](https://github.com/allaboutmike/smart-kitchen-mgmt)
**Date:** 2026-08-28
**Method:** Ran SCA (`npm audit`), SAST (`semgrep`), and secrets (`gitleaks`) scans by hand once against the codebase and full git history, triaged findings by actual reachability, fixed what needed fixing.
 
## Scan results
 
Three tools, three different angles — dependencies, code patterns, and secrets:
 
| Tool | Scope | Result |
|---|---|---|
| `npm audit` (SCA) | `management_service` dependency tree | 15 vulnerabilities found (2 low, 3 moderate, 10 high) — triaged by production-reachability, fixed via `npm audit fix`, a scoped `--force` bump, and a `package.json` `overrides` entry for a transitively-pinned dependency automated tooling couldn't otherwise reach. **0 remaining.** See [commit `8b8c310`](https://github.com/Keelen-Carrera/smart-kitchen-mgmt/commit/8b8c310). |
| `semgrep` (SAST) | 43 tracked files, OWASP Top 10 + JS + TS rulesets (83 rules) | **0 findings.** Confirms the code that exists doesn't contain flawed patterns (unsafe eval, injection-prone string building, weak crypto) — it does not and cannot detect a missing control, which is why this result doesn't change the headline finding in the threat model. |
| `gitleaks` (secrets) | Full git history, 384 commits | **0 leaks found.** No credentials or secrets were ever committed and left behind, not just absent from the current working tree. |
 
Clean SAST and secrets results are a real, honest finding worth stating plainly — not a formality. But paired with the threat model's headline finding, they make a specific point: this codebase's exposure isn't from sloppy code, it's from an architectural control that was never built.
 
## What this lab doesn't cover
 
Running these scans by hand, once, doesn't verify the scanners themselves are configured correctly or would actually catch something if it were there — a clean result on already-clean code proves nothing about detection capability. That gap, and wiring these same three scans into CI so they run automatically, is [Lab 2](./lab-2-ci-pipeline.md).
 