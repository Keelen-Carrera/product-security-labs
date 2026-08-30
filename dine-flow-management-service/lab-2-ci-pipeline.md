# Lab 2 — GitHub Actions Security Pipeline and Scanner Verification
 
**Companion to:** [threat-model.md](./threat-model.md) and [Lab 1](./lab-1-dependency-and-code-scans.md).
**Target:** `management_service` in [`smart-kitchen-mgmt`](https://github.com/allaboutmike/smart-kitchen-mgmt), via [`security.yml`](https://github.com/Keelen-Carrera/smart-kitchen-mgmt/blob/main/.github/workflows/security.yml)
**What this lab adds:** Lab 1 ran SCA/SAST/secrets scans by hand, once. This lab wires the same three scans into CI so they run on every push and pull request to `main` — and, the actual point of the lab, verifies the scanners are configured correctly and behave as expected, instead of trusting a green checkmark at face value.
 
## Secrets scan (gitleaks) — CI tooling verification
 
Rather than take "no leaks found" from CI at face value, I ran two constructed test cases through gitleaks to check that its AWS-key detection actually works as expected, and traced both results back to root cause instead of stopping at pass/fail.
 
**Test 1 — the canonical AWS docs placeholder key (`AKIAIOSFODNN7EXAMPLE`) is never flagged, by design.** Confirmed directly in gitleaks' [default config](https://github.com/gitleaks/gitleaks/blob/main/config/gitleaks.toml): the `aws-access-token` rule carries a rule-level allowlist, `regexes = ['''.+EXAMPLE$''']`, exempting any match ending in `EXAMPLE`. This is a deliberate upstream exception for AWS's own documentation example key, not a detection gap — but it means anyone who copy-pastes that exact string into example code gets a false negative from gitleaks regardless of version.
 
**Test 2 — a second fabricated key (`AKIAABCD1234EFGH5678`) surfaced a real CI configuration issue.** It was only caught by the generic `generic-api-key` rule, not the AWS-specific one. Digging into why led to finding that this repo's CI (`gitleaks-action@v2`, no `GITLEAKS_VERSION` set) was silently running **gitleaks 8.24.3** — a version that predates a [regex tightening fix](https://github.com/gitleaks/gitleaks/commit/d29ee55) (merged 2025-05-27, first shipped in 8.27.0) that restricts the AWS key charset to base32 (`[A-Z2-7]`, matching how AWS actually encodes these tokens) instead of the looser `[A-Z0-9]`. Checking `gitleaks-action`'s own source confirmed the root cause: both the `v2` and current `v3.0.0` releases hardcode `gitleaksVersion = process.env.GITLEAKS_VERSION || "8.24.3"` — the Action's major version has no bearing on which gitleaks build actually runs. To be precise about the real risk: the pre-fix regex is *looser*, not narrower, so this test didn't reveal a missed real AWS key specifically — the actual exposure was over a year of unrelated rule additions (new token formats for other services) that this pipeline was never picking up, silently, with nothing that would have surfaced it short of this check.
 
**Fix applied and verified:** pinned `gitleaks-action` to an exact tag and set `GITLEAKS_VERSION` explicitly in [`security.yml`](https://github.com/Keelen-Carrera/smart-kitchen-mgmt/commit/f025621):
 
```yaml
- uses: gitleaks/gitleaks-action@v2.3.9
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITLEAKS_VERSION: "8.30.0"
```
 
Verified against a live CI run on the PR that introduced this change — the job log confirms `gitleaks version: 8.30.0` and a clean scan (`no leaks found`) against the actual diff.
 
**Process note, kept in rather than cleaned up out of the record:** the PR that introduced this fix ([#1](https://github.com/Keelen-Carrera/smart-kitchen-mgmt/pull/1), merge commit `e332c39`) also carried an unrelated commit — a deliberately vulnerable test fixture (`eval()` on unsanitized input, a pinned-vulnerable `minimist@0.0.8` devDependency, and the AWS example key) built to confirm the `sca`/`sast`/`secrets` CI jobs actually fail on real bad input. That commit should not have shipped to `main`; it was only caught by manually diffing the branch against `main` before merging, not by anything automated — GitHub allowed the merge with `2 of 3` checks failing, meaning branch protection on this repo currently has no required-status-check gate at all. Remediated via a straight revert of the test commit ([#2](https://github.com/Keelen-Carrera/smart-kitchen-mgmt/pull/2), merge commit `c58e636`), which re-ran all three jobs clean. Left in the document instead of silently fixed because it's a more concrete demonstration of "verify the diff before you trust the PR" than any of the scanner findings above it — and because the gap it exposed (no required status checks on `main`) is tracked below.
 
## SAST scan (semgrep) — verification
 
Same standard as the secrets scan: don't treat a clean CI job as a finding on its own without checking what it actually ran against.
 
The `sast` job in `security.yml` runs `semgrep scan --config=p/owasp-top-ten --config=p/javascript --config=p/typescript --error management_service` on every push/PR to `main`. On the PR that included the deliberately-vulnerable test fixture ([#1](https://github.com/Keelen-Carrera/smart-kitchen-mgmt/pull/1)), which contained `eval(userInput)` in `scratch-test.ts`, the job reported **0 findings**. Confirmed via the job's own checkout log that it scanned the commit with the fixture present (9 TypeScript files, matching `f025621`'s tree — not the 8-file clean state), so this wasn't a case of the bait simply not being in scope.
 
Root-caused against the actual rule rather than assumed to be a gap: the most relevant community rule is [`eval-detected`](https://github.com/semgrep/semgrep-rules/blob/main/javascript/browser/security/eval-detected.yaml), which matches `eval(...)` while exempting a literal-string argument (`pattern-not: eval("...")`) — the string-literal case is treated as intentional, non-dynamic use. Pulled the rule file directly and ran it locally (semgrep 1.175.0, matching CI) against five constructed variants to isolate the actual behavior:
 
- `eval(userInput)`, `userInput` a `const` assigned `"test"` and never reassigned — **not flagged**
- `eval(userInput)`, `userInput` a function parameter — flagged
- `eval(userInput)`, `userInput` reassigned to a non-constant value before use — flagged
- `eval(code)`, `code` sourced from `req.query.code` — flagged
- `eval("console.log(1)")`, a plain literal — not flagged (the intended exemption, working correctly)
Semgrep performs constant propagation before pattern matching: because `scratch-test.ts` assigned `userInput` a literal and never touched it again, `eval(userInput)` was resolved to the equivalent of `eval("test")` and fell into the rule's own literal-eval exemption. That's not a detection gap in the tool or a CI misconfiguration — it's the test fixture's shape landing on the one form of "bad eval" this rule is specifically written to treat as safe. (I couldn't independently confirm from this environment whether `eval-detected` is actually included in the `p/javascript`/`p/owasp-top-ten` packs — semgrep.dev's registry wasn't reachable — but the mechanism above is sufficient to explain a 0-finding result regardless of pack membership.)
 
Unlike the gitleaks finding, there's no fix to apply here — no version pin, no workflow change. The lesson is methodological, the same category as the AWS test key not being valid base32: a hand-built adversarial test case can accidentally land on the one input shape a scanner is designed to wave through, so a clean result on a synthetic fixture needs the same scrutiny as a clean result on real code before it counts as verification.
 
## Open items
 
- **Branch protection on `main`** — no required status checks currently configured; a PR merged with a failing CI job during this lab (see process note above). Should require `sca`, `sast`, and `secrets` to pass before merge is allowed.
 