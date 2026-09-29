package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

func TestNotificationCapturedSourceQuarantineDoesNotBlockNextSource(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := shared.WithTenant(context.Background(), "quarantine-a")
	tenant := shared.ID("quarantine-a")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('quarantine-a','A'),('quarantine-b','B')`); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, now, 10); err != nil {
		t.Fatal(err)
	}
	channel := notification.Channel{TenantID: tenant, ID: "quarantine-hook", Name: "Hook", Type: notification.ChannelWebhook, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateChannel(ctx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateRule(ctx, notification.Rule{TenantID: tenant, ID: "quarantine-rule", Name: "Scans", Enabled: true, EventType: notification.EventScanCompleted, ChannelIDs: []shared.ID{channel.ID}, Revision: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	bad, _ := json.Marshal(map[string]string{"title": strings.Repeat("x", 17*1024)})
	good := []byte(`{"title":"Scan completed","summary":"Done"}`)
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		for i, item := range []struct {
			id   string
			data []byte
		}{{"bad", bad}, {"good", good}} {
			_, err := tx.Exec(ctx, `INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,occurred_at,data) VALUES($1,'scan_job',$2,'scan.completed',$3,$4)`, tenant, item.id, now.Add(time.Duration(i+1)*time.Second), item.data)
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := source.Poll(ctx, now.Add(3*time.Second), 2); err != nil || n != 2 {
		t.Fatalf("poll processed %d records: %v", n, err)
	}
	page, err := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: tenant})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("valid event deliveries = %d: %v", len(page.Items), err)
	}
	failures, err := repo.ListSourceFailures(ctx, ports.NotificationSourceFailureFilter{TenantID: tenant})
	if err != nil || len(failures.Items) != 1 {
		t.Fatalf("quarantined sources = %d: %v", len(failures.Items), err)
	}
	if got := failures.Items[0]; got.SourceID != "bad" || got.FailedReason != "event_data_too_large" || got.ProcessedAt.IsZero() {
		t.Fatalf("unexpected quarantine row: %+v", got)
	}
	if other, err := repo.ListSourceFailures(shared.WithTenant(context.Background(), "quarantine-b"), ports.NotificationSourceFailureFilter{TenantID: "quarantine-b"}); err != nil || len(other.Items) != 0 {
		t.Fatalf("other tenant can see failures: %+v, %v", other, err)
	}
	if n, err := source.Poll(ctx, now.Add(4*time.Second), 2); err != nil || n != 0 {
		t.Fatalf("replay processed %d records: %v", n, err)
	}
}

func TestNotificationPollUsesOneTotalSourceBudget(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := shared.WithTenant(context.Background(), "budget-a")
	tenant := shared.ID("budget-a")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('budget-a','A')`); err != nil {
		t.Fatal(err)
	}
	source := NewNotificationSource(pool, NewNotificationRepository(pool), time.Minute)
	if _, err := source.Poll(ctx, now, 10); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		for _, kind := range []string{"scan_job", "project_analysis_gate"} {
			_, err := tx.Exec(ctx, `INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,occurred_at,data) VALUES($1,$2,$2,$3,$4,'{"title":"ok"}')`, tenant, kind, map[string]string{"scan_job": "scan.completed", "project_analysis_gate": "quality_gate.failed"}[kind], now.Add(time.Second))
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := source.Poll(ctx, now.Add(2*time.Second), 1); err != nil || n != 1 {
		t.Fatalf("first poll: %d, %v", n, err)
	}
	if n, err := source.Poll(ctx, now.Add(3*time.Second), 1); err != nil || n != 1 {
		t.Fatalf("second poll: %d, %v", n, err)
	}
}
