# Design
The deterministic rules produce reproducible evidence-bearing alerts. The LLM is optional analyst assistance for summarization and recommendations.

## Detection engine

Two layers:

1. **Batch rules** (stateless, per event): suspicious PowerShell, privilege-escalation indicators, port-scan keywords.
2. **Campaign correlation** (stateful): brute force (5+ failed logins from one IP in 10 minutes), password spraying (one IP failing against 3+ accounts in 10 minutes), and concurrent access (one user authenticating from 2+ distinct IPs in 30 minutes). Correlation runs against stored history, so attacks split across uploads are still caught. Each campaign emits exactly one alert; an already-open campaign is not re-alerted inside its window.

The old "impossible travel" keyword match was removed — matching the literal phrase "impossible travel" in a log line is not detection. `CONCURRENT_ACCESS` replaces it with an honest, computable signal.

Security logs are attacker-controlled input. The LLM prompt explicitly treats them as untrusted data and never as instructions.

Write endpoints require `X-API-Key` when `API_KEY` is set; the app logs a warning at startup if it is empty.

Production extensions: PostgreSQL, Kafka, OpenTelemetry, RBAC/SSO, alert deduplication, asynchronous enrichment workers, SIEM connectors, model gateway controls, and stronger identity/access controls.
