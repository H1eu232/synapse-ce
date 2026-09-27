package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestSIEMMigrationAndTenantIsolation(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	var table string
	if err := admin.QueryRow(ctx, `SELECT to_regclass('public.siem_sinks')::text`).Scan(&table); err != nil || table == "" {
		t.Fatalf("siem_sinks missing after migrate: %v %q", err, table)
	}
	var trigger string
	if err := admin.QueryRow(ctx, `SELECT tgname FROM pg_trigger WHERE tgname = 'siem_incident_events_capture'`).Scan(&trigger); err != nil {
		t.Fatalf("capture trigger missing: %v", err)
	}
	const role = "synapse_siem_rls_test"
	_, _ = admin.Exec(ctx, `DROP OWNED BY `+role)
	_, _ = admin.Exec(ctx, `DROP ROLE IF EXISTS `+role)
	if _, err := admin.Exec(ctx, `CREATE ROLE `+role+` LOGIN PASSWORD 'test-password' NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP OWNED BY `+role)
		_, _ = admin.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})
	if _, err := admin.Exec(ctx, `GRANT USAGE ON SCHEMA public TO `+role); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `GRANT SELECT ON tenants TO `+role); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `GRANT SELECT, INSERT, UPDATE, DELETE ON siem_sinks, siem_sink_secrets, siem_checkpoints, siem_leases, siem_batches, siem_batch_items, siem_incident_counters, siem_incident_capture TO `+role); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = role
	config.ConnConfig.Password = "test-password"
	restricted, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restricted.Close)
	repo := NewSIEMRepository(restricted)
	if _, err := repo.ListSinks(shared.WithTenant(ctx, "tenant-a")); err != nil {
		t.Fatal(err)
	}
	ids, err := repo.TenantIDs(ctx)
	if err != nil || len(ids) == 0 {
		t.Fatalf("tenant directory: %v %v", ids, err)
	}
}
