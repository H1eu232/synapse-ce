package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/jackc/pgx/v5"
)

func (s *NotificationSource) pollCaptured(ctx context.Context, tx pgx.Tx, tenant shared.ID, kind string, now time.Time, limit int) (int, error) {
	rows, err := tx.Query(ctx, `SELECT source_id,event_type,engagement_id,severity,occurred_at,data FROM notification_source_records WHERE tenant_id=$1 AND source_kind=$2 AND processed_at IS NULL ORDER BY occurred_at,source_id LIMIT $3 FOR UPDATE SKIP LOCKED`, tenant, kind, limit)
	if err != nil {
		return 0, err
	}
	var events []notification.Event
	for rows.Next() {
		e := notification.Event{TenantID: tenant, SourceKind: kind, SchemaVersion: 1}
		if err := rows.Scan(&e.SourceID, &e.Type, &e.EngagementID, &e.Severity, &e.OccurredAt, &e.Data); err != nil {
			rows.Close()
			return 0, err
		}
		e.ID = stableID(tenant.String(), kind, e.SourceID)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	for _, e := range events {
		// pgx uses a savepoint for a nested transaction. A bad event may have
		// reached SQL before failing, so roll back that record's work alone.
		itemTx, err := tx.Begin(ctx)
		if err != nil {
			return 0, err
		}
		_, err = s.repo.publishTx(ctx, itemTx, e, "")
		if err != nil {
			if rollbackErr := itemTx.Rollback(ctx); rollbackErr != nil {
				return 0, rollbackErr
			}
			if !errors.Is(err, shared.ErrValidation) {
				return 0, err
			}
			reason := "invalid_event"
			if len(e.Data) > 16384 {
				reason = "event_data_too_large"
			}
			if _, err := tx.Exec(ctx, `UPDATE notification_source_records SET processed_at=$4,failed_reason=$5 WHERE tenant_id=$1 AND source_kind=$2 AND source_id=$3`, tenant, kind, e.SourceID, now, reason); err != nil {
				return 0, err
			}
			continue
		}
		if err := itemTx.Commit(ctx); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_source_records SET processed_at=$4 WHERE tenant_id=$1 AND source_kind=$2 AND source_id=$3`, tenant, kind, e.SourceID, now); err != nil {
			return 0, err
		}
	}
	return len(events), nil
}
