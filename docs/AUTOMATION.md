# Automation plan

Rule: automate wherever a person is guessing, waiting or babysitting.
**Never** automate where a person is the security control.

Priority: **P1** = build next · P2 = after templates work · P3 = later.

## 1. Connecting a vendor
| P | Automation | Owner |
|---|---|---|
| P1 | **Test on save**: one request, no storage; result per stage (auth → request → items path → mapping) with raw vs mapped sample; the failing stage names the fix | A |
| P1 | **Form generated from the template** (`secret_fields`, `options`) | B (UI) from A's template |
| P2 | Setup guide inside each template: how to create the key, least-privilege role | template author |
| P2 | Missing-permission hint: 403 → "add scope X" (template lists required scopes) | A |
| P2 | Region discovery via the vendor's official lookup only (never try the key on every region host) | A |
| P2 | Vendor identity ("GitHub: ravi-acme") auto-filled after the test | A + B |
| P2 | First-run backfill (`lookback` option), then incremental | A + B |

## 2. Daily running (no humans)
| P | Automation | Owner |
|---|---|---|
| done | Token refresh, retries, 429 / Retry-After backoff | A |
| P1 | Incremental sync state (time window / cursor / bookmark) | A + B |
| P2 | Default schedule per template; rate budget per credential across connectors | A + B |
| P2 | Deduplication of records fetched twice | B |

## 3. Credentials
| P | Automation | Owner |
|---|---|---|
| done | Engine classifies problems (`missing`, `incomplete`, `binding_mismatch`, `needs_reauth`, `insufficient_permissions`) with `credential_id` | A |
| P1 | Notify the credential **owner** (not the whole tenant) with a fix link | B |
| P1 | Expiry reminders at 30 / 7 / 1 days | B |
| P2 | Safe rotation: test the new key before swapping, keep the old one until it works | A + B |
| P2 | Duplicate-key detection via HMAC fingerprint | B |
| P3 | Orphans: unused 90 days → suggest revoke; owner removed in SSO → flag | B |

## 4. Vendor API changes
| P | Automation | Owner |
|---|---|---|
| P2 | **Drift detection across tenants**: same template failing the same way for several tenants → alert template authors; tenants see "vendor change detected" | A + B |
| P1 | Quarantine with reasons (nothing dropped silently) | B |

## 5. Adding vendors (our team)
| P | Automation | Owner |
|---|---|---|
| P2 | AI drafting: docs → template + fixture + CEL mapping → validator + contract tests → errors fed back → human PR review | A |
| P1 | CI runs every template's contract tests | A |
| P3 | Nightly live checks against vendor sandboxes update the "Verified" column | A |

## 6. Approvals and security
| P | Automation | Owner |
|---|---|---|
| P2 | Plain-language diff for the second approver; host / port / binding changes highlighted | B |
| P1 | Alerts on `egress_blocked`, repeated `auth_failed`, volume spikes; grouped per incident | B |

## Never automated
- Approving configs or templates (two-person rule).
- Choosing hosts, ports, secret bindings.
- Rotating keys through vendor APIs (needs write access; platform is read-only).
- Merging AI drafts.
- Sending tenant data to an AI model without the tenant's opt-in.
