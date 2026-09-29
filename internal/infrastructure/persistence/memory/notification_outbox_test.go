package memory

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/testutil/notificationoutboxtest"
)

func TestNotificationOutboxConformance(t *testing.T) {
	notificationoutboxtest.Run(t, func(t *testing.T) notificationoutboxtest.Harness {
		outbox := NewNotificationOutbox()
		return notificationoutboxtest.Harness{
			Outbox:       outbox,
			Transactions: NewTenantTransactionRunner(),
			Activate:     func(_ *testing.T, tenant shared.ID, at time.Time) { outbox.Activate(tenant, at) },
			Records:      func(_ *testing.T, tenant shared.ID) []notification.SourceRecord { return outbox.Records(tenant) },
		}
	})
}
