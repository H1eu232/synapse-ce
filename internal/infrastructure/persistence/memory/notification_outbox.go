package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// NotificationOutbox is the in-memory twin of the Postgres outbox. It joins the memory
// TenantTransactionRunner, so a rolled-back transaction leaves no record, and applies the same
// idempotency and activation rules.
type NotificationOutbox struct {
	mu        sync.Mutex
	records   map[sourceRecordKey]notification.SourceRecord
	activated map[shared.ID]time.Time
}

type sourceRecordKey struct {
	tenant   shared.ID
	kind, id string
}

var _ ports.NotificationOutbox = (*NotificationOutbox)(nil)

func NewNotificationOutbox() *NotificationOutbox {
	return &NotificationOutbox{records: map[sourceRecordKey]notification.SourceRecord{}, activated: map[shared.ID]time.Time{}}
}

// Activate records when the tenant turned notifications on; records dated earlier are dropped.
// It stands in for the framework activation row of notification_source_state.
func (o *NotificationOutbox) Activate(tenant shared.ID, at time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.activated[tenant] = at.UTC()
}

func (o *NotificationOutbox) Append(ctx context.Context, record notification.SourceRecord) error {
	if err := record.Normalize(); err != nil {
		return err
	}
	transaction, ok := ctx.Value(tenantTransactionKey{}).(*tenantTransaction)
	if !ok {
		return fmt.Errorf("%w: notification outbox append requires a tenant transaction", shared.ErrValidation)
	}
	if transaction.tenantID != record.TenantID {
		return fmt.Errorf("%w: notification outbox record belongs to another tenant", shared.ErrValidation)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	activatedAt, active := o.activated[record.TenantID]
	key := sourceRecordKey{tenant: record.TenantID, kind: record.SourceKind, id: record.SourceID}
	if _, exists := o.records[key]; exists || !active || record.OccurredAt.Before(activatedAt) {
		return nil
	}
	o.records[key] = cloneSourceRecord(record)
	registerTenantRollback(ctx, func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		delete(o.records, key)
	})
	return nil
}

// Records returns the tenant's committed records ordered by occurrence, then source key, the
// order the worker drains them in.
func (o *NotificationOutbox) Records(tenant shared.ID) []notification.SourceRecord {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []notification.SourceRecord
	for key, record := range o.records {
		if key.tenant == tenant {
			out = append(out, cloneSourceRecord(record))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].OccurredAt.Before(out[j].OccurredAt)
		}
		if out[i].SourceKind != out[j].SourceKind {
			return out[i].SourceKind < out[j].SourceKind
		}
		return out[i].SourceID < out[j].SourceID
	})
	return out
}

func cloneSourceRecord(record notification.SourceRecord) notification.SourceRecord {
	record.Data = append([]byte(nil), record.Data...)
	record.Context = append([]byte(nil), record.Context...)
	return record
}
