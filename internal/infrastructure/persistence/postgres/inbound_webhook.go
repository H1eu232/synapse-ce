package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// InboundWebhookRepository accesses the global routing registry ONLY through
// one narrow migration-owner lookup plus tenant-scoped RLS reads/admission. The
// runtime role has no unscoped row visibility and no direct write privilege.
type InboundWebhookRepository struct{ pool *pgxpool.Pool }

func NewInboundWebhookRepository(pool *pgxpool.Pool) *InboundWebhookRepository {
	return &InboundWebhookRepository{pool: pool}
}

var _ ports.InboundWebhookStore = (*InboundWebhookRepository)(nil)

// LookupInboundWebhook first asks the single privileged lookup for ONLY a
// tenant ID. The sealed keys, owner and status are then read under FORCE RLS
// in that tenant's transaction. Unknown IDs execute a dummy tenant-scoped
// read too, reducing the known-vs-unknown timing difference.
func (s *InboundWebhookRepository) LookupInboundWebhook(ctx context.Context, publicID string) (ports.InboundWebhookEndpoint, bool, error) {
	if s == nil || s.pool == nil || len(publicID) < 32 || len(publicID) > 64 {
		return ports.InboundWebhookEndpoint{}, false, nil
	}
	var tenantID shared.ID
	err := s.pool.QueryRow(ctx,
		"SELECT tenant_id FROM synapse_lookup_inbound_webhook($1)", publicID).Scan(&tenantID)
	known := err == nil && !tenantID.IsZero()
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ports.InboundWebhookEndpoint{}, false, err
	}
	if !known {
		tenantID = "synapse-webhook-unmapped-dummy"
	}

	var e ports.InboundWebhookEndpoint
	e.PublicID = publicID
	var previousExpiresAt *time.Time
	err = requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
            SELECT e.owner_kind, e.owner_id,
                e.enabled AND i.enabled AND NOT i.archived,
                e.current_version, e.current_sealed, e.previous_sealed,
                e.previous_expires_at, e.revoked_at, e.rate_per_minute
            FROM inbound_webhook_endpoints e
            JOIN integrations i ON i.tenant_id=e.tenant_id AND i.id=e.owner_id
            WHERE e.public_id=$1 AND e.tenant_id=$2
        `, publicID, tenantID).Scan(
			&e.OwnerKind, &e.OwnerID, &e.Enabled, &e.CurrentVersion,
			&e.CurrentSealed, &e.PreviousSealed, &previousExpiresAt,
			&e.RevokedAt, &e.RatePerMinute,
		)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.InboundWebhookEndpoint{}, false, nil
	}
	if err != nil {
		return ports.InboundWebhookEndpoint{}, false, err
	}
	if !known {
		return ports.InboundWebhookEndpoint{}, false, nil
	}
	e.TenantID = tenantID
	if previousExpiresAt != nil {
		e.PreviousExpiresAt = *previousExpiresAt
	}
	return e, true, nil
}

func (s *InboundWebhookRepository) AdmitInboundWebhook(ctx context.Context, identity ports.InboundWebhookIdentity, version int, usedPrevious bool) (int, error) {
	if s == nil || s.pool == nil || identity.PublicID == "" || identity.TenantID.IsZero() ||
		identity.OwnerKind != "integration" || identity.OwnerID == "" || version < 1 {
		return -1, nil
	}
	decision := -1
	err := requireTenant(ctx, s.pool, identity.TenantID, func(tx pgx.Tx) error {
		// A FOR SHARE lock prevents disable/archive racing with the request's
		// admission. A missing, archived or other-tenant owner always denies.
		var active bool
		err := tx.QueryRow(ctx, `
            SELECT enabled AND NOT archived FROM integrations
            WHERE tenant_id=$1 AND id=$2 FOR SHARE
        `, identity.TenantID, identity.OwnerID).Scan(&active)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !active {
			return nil
		}
		return tx.QueryRow(ctx,
			"SELECT synapse_admit_inbound_webhook($1,$2,$3,$4,$5,$6)",
			identity.PublicID, identity.TenantID.String(),
			identity.OwnerKind, identity.OwnerID, version, usedPrevious,
		).Scan(&decision)
	})
	return decision, err
}
