# Product Security Labs

A running log of hands-on product security / application security work — threat models, dependency and code scans, CI/CD security pipelines, and the write-ups that go with them.

## Approach

Every lab here follows the same standard: a scanner's pass/fail output isn't a finding on its own until the ruleset or configuration behind it is verified, not assumed. That means reading the actual source of a detection rule when a result looks off, reproducing behavior locally instead of trusting a log, and documenting mistakes — including my own — in the record rather than cleaning them out after the fact. A threat model or scan result is only as credible as the process that produced it.

## Labs

### [Dine Flow — `management_service`](./dine-flow-management-service/)

Retrospective security assessment of the backend for [Dine Flow](https://github.com/allaboutmike/smart-kitchen-mgmt) (a 6-person cohort project restaurant management platform; forked to [my copy](https://github.com/Keelen-Carrera/smart-kitchen-mgmt) for scan results and remediation commits). Not a critique of the original team — security wasn't the assignment, a working app in a compressed timeframe was. That's exactly the kind of codebase this practice needs.

- **[Threat model](./dine-flow-management-service/threat-model.md)** — STRIDE analysis, architecture, headline finding (broken access control, OWASP A01:2021).
- **[Lab 1 — Dependency, static-analysis, and secrets scans](./dine-flow-management-service/lab-1-dependency-and-code-scans.md)** — SCA/SAST/secrets scans run by hand, triaged, and fixed.
- **[Lab 2 — CI pipeline and scanner verification](./dine-flow-management-service/lab-2-ci-pipeline.md)** — wired the same scans into GitHub Actions, then verified the scanners themselves actually behave as expected instead of trusting a green checkmark. Includes a real process incident (a bad merge to `main`, caught and reverted) documented rather than scrubbed from the history.

More labs will land here as they're built — detection engineering, cloud security, and further AppSec work.

## License

[MIT](./LICENSE)