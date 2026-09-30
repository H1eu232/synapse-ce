package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestMigration0202InboundWebhookEventDedupe(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 202, 201)
	db := isolated.db
	if err := goose.UpTo(db, ".", 202); err != nil {
		t.Fatalf("apply inbound event dedupe migration: %v", err)
	}
	requireMigrationTable(t, db, "inbound_webhook_events", true)
	requireMigrationRLS(t, db, "inbound_webhook_events")
	requireMigrationPolicies(t, db, "inbound_webhook_events", "inbound_webhook_events_tenant_all")
	requireMigrationIndexes(t, db, "inbound_webhook_events_received")
	if err := goose.DownTo(db, ".", 201); err != nil {
		t.Fatalf("rollback inbound event dedupe migration: %v", err)
	}
	requireMigrationTable(t, db, "inbound_webhook_events", false)
}

func TestInboundWebhookEventDedupeHostileTenant(t *testing.T) {
	fixture := newRLS817Fixture(t)
	ctx := context.Background()
	const publicA = "dedupeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const publicB = "dedupebbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const ownerA = "github-dedupe-A"
	const ownerB = "github-dedupe-B"
	t.Cleanup(func() {
		_, _ = fixture.owner.Exec(context.Background(), "DELETE FROM inbound_webhook_endpoints WHERE public_id IN ($1,$2)", publicA, publicB)
		_, _ = fixture.owner.Exec(context.Background(), "DELETE FROM integrations WHERE id IN ($1,$2)", ownerA, ownerB)
	})
	for _, row := range []struct {
		tenant shared.ID
		public, owner string
	}{
		{rls817TenantA, publicA, ownerA},
		{rls817TenantB, publicB, ownerB},
	} {
		if _, err := fixture.owner.Exec(ctx,
			"INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,enabled,created_at,updated_at) VALUES($1,$2,'github',$1,$3,true,now(),now())",
			row.owner, row.tenant, "https://github.com"); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.owner.Exec(ctx,
			"INSERT INTO inbound_webhook_endpoints(public_id,tenant_id,owner_kind,owner_id,enabled,current_version,current_sealed,rate_per_minute) VALUES($1,$2,'integration',$3,true,1,'encrypted-placeholder',10)",
			row.public, row.tenant, row.owner); err != nil {
			t.Fatal(err)
		}
	}
	store := NewInboundWebhookRepository(fixture.runtime)
	idA := ports.InboundWebhookIdentity{PublicID: publicA, TenantID: rls817TenantA, OwnerKind: "integration", OwnerID: ownerA}
	claimed, err := store.ClaimInboundWebhookEvent(ctx, idA, "github", "delivery-1", time.Now())
	if err != nil || !claimed {
		t.Fatalf("first claim=%v err=%v", claimed, err)
	}
	claimed, err = store.ClaimInboundWebhookEvent(ctx, idA, "github", "delivery-1", time.Now())
	if err != nil || claimed {
		t.Fatalf("replay claim=%v err=%v", claimed, err)
	}
	// A forged tenant/public-ID combination cannot attach an event to B.
	forged := ports.InboundWebhookIdentity{PublicID: publicB, TenantID: rls817TenantA, OwnerKind: "integration", OwnerID: ownerB}
	claimed, err = store.ClaimInboundWebhookEvent(ctx, forged, "github", "delivery-x", time.Now())
	if err == nil && claimed {
		t.Fatal("cross-tenant event claim succeeded")
	}
}
