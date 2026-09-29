package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/testutil/notificationoutboxtest"
)

// TestNotificationOutboxConformance runs the shared outbox suite against Postgres, as the
// non-superuser application role, so row level security applies to every read and write.
func TestNotificationOutboxConformance(t *testing.T) {
	if os.Getenv("SYNAPSE_TEST_DB_DSN") == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	pool := notificationTestPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, notificationoutboxtest.TenantA.String(), notificationoutboxtest.TenantB.String()); err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	notificationoutboxtest.Run(t, func(t *testing.T) notificationoutboxtest.Harness {
		for _, tenant := range []shared.ID{notificationoutboxtest.TenantA, notificationoutboxtest.TenantB} {
			resetOutboxTenant(t, pool, tenant)
		}
		return notificationoutboxtest.Harness{
			Outbox:       NewNotificationOutbox(pool),
			Transactions: NewTenantTransactionRunner(pool),
			Activate:     func(t *testing.T, tenant shared.ID, at time.Time) { activateNotifications(t, pool, tenant, at) },
			Records: func(t *testing.T, tenant shared.ID) []notification.SourceRecord {
				return committedSourceRecords(t, pool, tenant)
			},
		}
	})
}

func resetOutboxTenant(t *testing.T, pool *pgxpool.Pool, tenant shared.ID) {
	t.Helper()
	err := WithTenant(context.Background(), pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `DELETE FROM notification_source_records WHERE tenant_id=$1`, tenant.String()); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `DELETE FROM notification_source_state WHERE tenant_id=$1`, tenant.String())
		return err
	})
	if err != nil {
		t.Fatalf("reset %s: %v", tenant, err)
	}
}

func activateNotifications(t *testing.T, pool *pgxpool.Pool, tenant shared.ID, at time.Time) {
	t.Helper()
	err := WithTenant(context.Background(), pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at)
			VALUES($1,'framework','activation','',true,$2)
			ON CONFLICT (tenant_id,source_kind,source_id) DO UPDATE SET observed_at=EXCLUDED.observed_at`, tenant.String(), at)
		return err
	})
	if err != nil {
		t.Fatalf("activate %s: %v", tenant, err)
	}
}

func committedSourceRecords(t *testing.T, pool *pgxpool.Pool, tenant shared.ID) []notification.SourceRecord {
	t.Helper()
	var out []notification.SourceRecord
	err := WithTenant(context.Background(), pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT source_kind,source_id,event_type,engagement_id,severity,occurred_at,data,schema_version,subject_kind,subject_id,context
			FROM notification_source_records WHERE tenant_id=$1 ORDER BY occurred_at,source_kind,source_id`, tenant.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r := notification.SourceRecord{TenantID: tenant}
			if err := rows.Scan(&r.SourceKind, &r.SourceID, &r.EventType, &r.EngagementID, &r.Severity, &r.OccurredAt, &r.Data, &r.SchemaVersion, &r.SubjectKind, &r.SubjectID, &r.Context); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("read source records of %s: %v", tenant, err)
	}
	return out
}
