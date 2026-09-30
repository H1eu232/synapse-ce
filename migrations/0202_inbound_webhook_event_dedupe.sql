-- +goose Up
-- #1452. Provider event IDs are claimed only after webhook authentication.
-- The composite endpoint key prevents a privileged row mix-up from attaching
-- an event claim to another tenant's opaque endpoint.
ALTER TABLE inbound_webhook_endpoints
    ADD CONSTRAINT inbound_webhook_tenant_public_unique UNIQUE (tenant_id, public_id);

CREATE TABLE inbound_webhook_events (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    public_id TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    event_id TEXT NOT NULL CHECK (length(event_id) BETWEEN 1 AND 128),
    received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, public_id, provider, event_id),
    CONSTRAINT inbound_webhook_event_endpoint_fk
        FOREIGN KEY (tenant_id, public_id)
        REFERENCES inbound_webhook_endpoints(tenant_id, public_id)
        ON DELETE CASCADE
);

CREATE INDEX inbound_webhook_events_received
    ON inbound_webhook_events (tenant_id, received_at DESC);

ALTER TABLE inbound_webhook_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE inbound_webhook_events FORCE ROW LEVEL SECURITY;
CREATE POLICY inbound_webhook_events_tenant_all ON inbound_webhook_events
    FOR ALL TO PUBLIC
    USING (tenant_id = synapse_current_tenant())
    WITH CHECK (tenant_id = synapse_current_tenant());

-- +goose Down
DROP TABLE inbound_webhook_events;
ALTER TABLE inbound_webhook_endpoints
    DROP CONSTRAINT inbound_webhook_tenant_public_unique;
