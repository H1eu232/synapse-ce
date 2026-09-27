# SIEM streams

Synapse can export committed audit events and incident events to Splunk HEC or
Elasticsearch. The stream is separate from notification delivery. One bad
destination does not decide another tenant's cursor.

## What is exported

- Tenant audit rows on the v2 hash chain, from genesis unless an operator
  explicitly starts a new generation at the current head.
- Incident events captured in the same transaction as the append. A historical
  backfill uses a separate cursor and is not described as happening before the
  live stream.
- Legacy v1 audit rows are not part of the tenant chain. The status page says
  so. They are not marked verified.

Audit row ids are not a gap when they skip. Other tenants and rolled-back
inserts leave holes. A row whose previous hash does not match the cursor stops
that partition. Nothing is skipped automatically.

## Delivery

Export is at least once. A worker can crash after the destination accepts a
batch and before Synapse stores that result. The next attempt sends the batch
again. Record ids stay stable so the destination can collapse duplicates.
Splunk is not exactly once.

Splunk HTTP 200 is not enough. The HEC code must be success. Indexer
acknowledgement is used only when the sink is configured for it. Splunk Cloud
does not provide indexer acknowledgement; leave that mode off there. An
acknowledgement can expire or be lost, and it does not prove the event is
searchable.
The HEC receipt is stored in the open batch before polling. Later ticks,
including after a worker restart, poll the same receipt without another POST.
A crash between HEC acceptance and storing the receipt can still cause a
duplicate POST. After eight unsuccessful polls, the sink blocks for an
operator; resume continues polling the stored receipt.

Elasticsearch bulk responses are read item by item. The cursor moves only
through the contiguous successful prefix. HTTP 409 is not treated as proof
that the current document was stored. The target is one normal index, not a
data stream.

## Privacy

The sink data class defaults to signal. An engagement whose policy is unknown
does not rise above signal. A record with no engagement stays at signal.
`none` suppresses the record and is not a gap.
The current API and worker do not install a shared engagement policy, so the
settings page offers Signal only. An API request for Summary or Detail stores
that request but exports Signal until the shared policy is wired. Incident and
vulnerability events that lack required OCSF fields use the versioned Signal
envelope instead of disappearing into quarantine.

Signal carries the event type, severity, and a console link when
`SYNAPSE_SIEM_PUBLIC_BASE_URL` is configured. Summary can add a title, actor, and host. Detail can
add an advisory id, asset id, or comment. Raw audit metadata and raw incident
payloads are not serialized. Text passes through the shared secret scrubber.
The source-chain hash in the payload is a reference to the local chain. It is
not a digest of the redacted body. The redacted body has its own digest.

## Credentials and hosts

Secrets are sealed with the vault key and associated data that includes the
tenant, sink, and provider. API responses return the origin, not the secret.
Replacing the secret keeps the cursor. Replacing the host pauses the sink,
drops prepared batches, and requires an explicit choice: continue from the
cursor, or start at the current head so the old backlog is not sent to the
new host.

Destinations must be `https` with no userinfo. Private, loopback, and metadata
addresses are rejected. The dial uses the shared HTTP client, which does not
follow redirects or use a proxy. A private self-hosted collector stays blocked
until the shared egress allowlist lands. Do not turn on private-network dialing
to bypass that.

## Operations

Pause stops new sends and leaves cursors where they are. Resume clears a
blocked reason. The settings page offers Resume for a paused sink and for a
sink that is blocked while delivery is still enabled. If the source chain is
still broken, the next pass blocks again. Failed records in that blocked batch
are retried; records the destination already accepted are not sent again.

Export acknowledgements are not written back into the audit log. Configuration
changes are. Batch state and metrics are the operational record.

Set `SYNAPSE_SIEM_ENABLED=false` on all API/writer and worker replicas to stop
both incident capture and outbound sends. Events written while capture is off
do not enter the live partition; use a historical backfill before relying on
coverage after re-enabling. Pausing a sink only stops sends and keeps capture
active. Tenants without an enabled sink do not capture incident identities.

After seven days, a bounded sweep removes sealed batch payloads, completed
batch manifests, and obsolete credential versions. It prunes incident capture
rows only below every sink's committed cursor, including paused and blocked
sinks, while retaining one anchor row. Each removed identity is tombstoned.
Historical backfill does not assign a new sequence to a tombstoned event.
Events that were never captured, including those written while the kill switch
was off, can still be backfilled. A new sink starts from the retained anchor
if old capture rows were pruned. The incident counter is never reset. Capture,
prune, and backfill take the same per-tenant retention lock.

When metrics are enabled, scrape the worker's separate `/metrics` listener
for SIEM delivery counters. Give API and worker distinct metrics addresses if
they share a host; both default to `127.0.0.1:9090`.

## What this release does not prove

No Splunk or Elasticsearch service was available while this was built, so
there are no screenshots of received English or Vietnamese events. The provider
behavior is covered by contract tests against a local TLS server. Browser
screenshots of the settings page in light and dark themes were not captured
in a running console. The page uses the existing settings components.

These shared pieces were still open, so this stream does not replace them:

- dial-time host allowlists
- engagement data-class overrides beyond the fail-closed signal ceiling
- an integration administrator role
- offline validation against the official, pinned OCSF schema artifacts

Syslog and Microsoft Sentinel are not part of this stream.
