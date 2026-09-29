# Notification event schemas

Each file below documents the **versioned JSON event envelope**, including its `data` object, as serialized for a notification webhook. The source of truth is `internal/domain/notification/catalog.go` (`EventCatalog()`); the same version number is carried in `schema_version`. Fixtures are illustrative, contain no credentials and are checked against their schema by `go test ./internal/domain/notification`.

| Event | Contract and fixture | Maximum data class |
| --- | --- | --- |
| `vulnerability_action.created` — Risk action; severity and engagement | [JSON Schema](vulnerability_action.created.v1.schema.json) · [fixture](vulnerability_action.created.v1.fixture.json) | `detail` |
| `scan.completed` — Persisted scan completion; engagement | [JSON Schema](scan.completed.v1.schema.json) · [fixture](scan.completed.v1.fixture.json) | `summary` |
| `quality_gate.failed` — Failed project-analysis gate | [JSON Schema](quality_gate.failed.v1.schema.json) · [fixture](quality_gate.failed.v1.fixture.json) | `summary` |
| `sla.approaching_deadline` — Finding deadline and reminder lead time | [JSON Schema](sla.approaching_deadline.v1.schema.json) · [fixture](sla.approaching_deadline.v1.fixture.json) | `summary` |
| `fleet.agent.offline` — Stale agent heartbeat | [JSON Schema](fleet.agent.offline.v1.schema.json) · [fixture](fleet.agent.offline.v1.fixture.json) | `summary` |
| `incident.created` — Persisted correlated incident; optional engagement/severity | [JSON Schema](incident.created.v1.schema.json) · [fixture](incident.created.v1.fixture.json) | `detail` |
| `finding.ownership_changed` — Structured finding assignment decision | [JSON Schema](finding.ownership_changed.v1.schema.json) · [fixture](finding.ownership_changed.v1.fixture.json) | `detail` |
| `notification.destination_changed` (operator-only) — channel destination notice | [JSON Schema](notification.destination_changed.v1.schema.json) · [fixture](notification.destination_changed.v1.fixture.json) | `summary` |
| `notification.channel_paused` (operator-only) — automatic channel pause notice to tenant admins | [JSON Schema](notification.channel_paused.v1.schema.json) · [fixture](notification.channel_paused.v1.fixture.json) | `summary` |
| `notification.test` (operator-only) — channel test | [JSON Schema](notification.test.v1.schema.json) · [fixture](notification.test.v1.fixture.json) | `signal` |

## Version and compatibility

The v1 envelope contains `id`, `type`, `source_kind`, `source_id`, `schema_version`, `occurred_at` (RFC 3339) and `data`. `engagement_id` and `severity` appear only when supplied by the producer. `tenant_id` is intentionally omitted. An event's `source_kind` and `source_id` describe its idempotency origin; `type` describes the public event kind. Do not construct private/internal links by concatenating untrusted payload values.

**Additive optional fields** may be introduced without changing the schema version; unknown fields are accepted via `additionalProperties: true` so existing consumers remain compatible. **Renaming, removing or changing an existing field's type or meaning requires a new `schema_version` and a new versioned schema and fixture**. Never silently change an existing v1 contract. A new event type also needs its own schema and fixture. A test checks every `EventCatalog()` entry, validates both files and rejects stale schema/fixture pairs.

This directory covers **all catalog entries**: seven configurable notification events plus three operator-only event types. Operator-only events cannot be selected as routing rules. These schemas describe wire-format structure, not delivery or authorization policy. `MaxDataClass` is catalog metadata declaring a ceiling; the notification pipeline does **not yet enforce data-class filtering**, so consumers must not assume payloads are filtered or redacted by that setting. For `incident.created`, an incident without an asset carries `data.asset_id: ""` (an empty string, never `null`). See [Notifications and webhooks](../../notifications.md) for routing, retries, signature verification and retention.
