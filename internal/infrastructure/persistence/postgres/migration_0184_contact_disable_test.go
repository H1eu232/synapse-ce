package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestMigration0184ConsumesChallengesAndRestoresTenantSetting(t *testing.T) {
	pool, _ := ownershipTestDatabase(t, 183, nil)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('contact-owner','Contact owner')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled)
		VALUES('contact-owner-user','Contact owner','member','contact-owner-hash','contact-owner',false)`); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, "contact-owner", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO user_contacts(tenant_id,id,user_id,kind,value)
			VALUES('contact-owner','contact-1','contact-owner-user','email','owner@example.com')`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO user_contact_challenges(tenant_id,id,user_id,contact_id,contact_version,code_digest,sealed_code,expires_at)
			VALUES('contact-owner','challenge-1','contact-owner-user','contact-1',1,$1,'sealed',now()+interval '1 hour')`, strings.Repeat("a", 64))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant','previous-scope',true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET disabled=true WHERE id='contact-owner-user' AND ownership_tenant_id='contact-owner'`); err != nil {
		t.Fatal(err)
	}
	var scope string
	if err := tx.QueryRow(ctx, `SELECT current_setting('app.current_tenant',true)`).Scan(&scope); err != nil || scope != "previous-scope" {
		t.Fatalf("trigger left tenant scope %q: %v", scope, err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant','contact-owner',true)`); err != nil {
		t.Fatal(err)
	}
	var consumed bool
	if err := tx.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM user_contact_challenges WHERE tenant_id='contact-owner' AND id='challenge-1'`).Scan(&consumed); err != nil || !consumed {
		t.Fatalf("disable did not consume challenge: %v %v", consumed, err)
	}
}
