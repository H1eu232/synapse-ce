// Package notificationoutboxtest is the conformance suite for ports.NotificationOutbox. Every
// adapter runs the same cases, so producers tested against the memory outbox get the behaviour
// they will see in production.
package notificationoutboxtest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Harness is one adapter under test. Each call of the factory must return a fresh store with
// tenants TenantA and TenantB present and notifications not yet activated.
type Harness struct {
	Outbox       ports.NotificationOutbox
	Transactions ports.TenantTransactionRunner
	// Activate marks the tenant's notification framework active from at onwards.
	Activate func(t *testing.T, tenant shared.ID, at time.Time)
	// Records returns the tenant's committed records.
	Records func(t *testing.T, tenant shared.ID) []notification.SourceRecord
}

const (
	TenantA shared.ID = "outbox-tenant-a"
	TenantB shared.ID = "outbox-tenant-b"
)

var activatedAt = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

// Run executes every case against a fresh harness.
func Run(t *testing.T, newHarness func(t *testing.T) Harness) {
	cases := map[string]func(*testing.T, Harness){
		"committed append is visible":            committedAppendIsVisible,
		"rolled-back append leaves no record":    rolledBackAppendLeavesNoRecord,
		"append is idempotent on the source key": appendIsIdempotent,
		"append outside a transaction fails":     appendOutsideTransactionFails,
		"append for another tenant fails":        appendForAnotherTenantFails,
		"invalid record fails":                   invalidRecordFails,
		"records before activation are dropped":  recordsBeforeActivationAreDropped,
	}
	for name, check := range cases {
		t.Run(name, func(t *testing.T) {
			harness := newHarness(t)
			harness.Activate(t, TenantA, activatedAt)
			check(t, harness)
		})
	}
}

func record(sourceID string) notification.SourceRecord {
	return notification.SourceRecord{
		TenantID: TenantA, SourceKind: "scan_job", SourceID: sourceID, EventType: notification.EventScanCompleted,
		OccurredAt: activatedAt.Add(time.Hour), Data: json.RawMessage(`{"title":"Scan completed"}`),
		SubjectKind: "scan_job", SubjectID: sourceID, Context: json.RawMessage(`{"scan_id":"` + sourceID + `"}`),
	}
}

func appendIn(t *testing.T, h Harness, tenant shared.ID, records ...notification.SourceRecord) error {
	t.Helper()
	return h.Transactions.Run(context.Background(), tenant, func(ctx context.Context) error {
		for _, r := range records {
			if err := h.Outbox.Append(ctx, r); err != nil {
				return err
			}
		}
		return nil
	})
}

func committedAppendIsVisible(t *testing.T, h Harness) {
	if err := appendIn(t, h, TenantA, record("scan-1")); err != nil {
		t.Fatal(err)
	}
	got := h.Records(t, TenantA)
	if len(got) != 1 {
		t.Fatalf("records = %+v", got)
	}
	r := got[0]
	if r.SourceID != "scan-1" || r.EventType != notification.EventScanCompleted || r.SchemaVersion != 1 ||
		r.SubjectKind != "scan_job" || r.SubjectID != "scan-1" || !sameJSON(r.Context, `{"scan_id":"scan-1"}`) || !sameJSON(r.Data, `{"title":"Scan completed"}`) {
		t.Fatalf("stored record = %+v", r)
	}
	if other := h.Records(t, TenantB); len(other) != 0 {
		t.Fatalf("tenant B sees %d records", len(other))
	}
}

func rolledBackAppendLeavesNoRecord(t *testing.T, h Harness) {
	businessFailure := errors.New("business write failed")
	err := h.Transactions.Run(context.Background(), TenantA, func(ctx context.Context) error {
		if err := h.Outbox.Append(ctx, record("scan-1")); err != nil {
			return err
		}
		return businessFailure
	})
	if !errors.Is(err, businessFailure) {
		t.Fatalf("err = %v", err)
	}
	if got := h.Records(t, TenantA); len(got) != 0 {
		t.Fatalf("rolled-back append left %+v", got)
	}
}

func appendIsIdempotent(t *testing.T, h Harness) {
	first := record("scan-1")
	second := record("scan-1")
	second.Data = json.RawMessage(`{"title":"replayed"}`)
	if err := appendIn(t, h, TenantA, first); err != nil {
		t.Fatal(err)
	}
	if err := appendIn(t, h, TenantA, second); err != nil {
		t.Fatalf("replayed append: %v", err)
	}
	got := h.Records(t, TenantA)
	if len(got) != 1 || !sameJSON(got[0].Data, `{"title":"Scan completed"}`) {
		t.Fatalf("records after replay = %+v", got)
	}
}

func appendOutsideTransactionFails(t *testing.T, h Harness) {
	ctx := shared.WithTenant(context.Background(), TenantA)
	if err := h.Outbox.Append(ctx, record("scan-1")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want a validation error", err)
	}
	if got := h.Records(t, TenantA); len(got) != 0 {
		t.Fatalf("append outside a transaction wrote %+v", got)
	}
}

func appendForAnotherTenantFails(t *testing.T, h Harness) {
	h.Activate(t, TenantB, activatedAt)
	foreign := record("scan-1")
	foreign.TenantID = TenantB
	if err := appendIn(t, h, TenantA, foreign); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want a validation error", err)
	}
	if got := h.Records(t, TenantB); len(got) != 0 {
		t.Fatalf("cross-tenant append wrote %+v", got)
	}
}

func invalidRecordFails(t *testing.T, h Harness) {
	invalid := record("scan-1")
	invalid.EventType = "not_in.catalog"
	if err := appendIn(t, h, TenantA, invalid); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want a validation error", err)
	}
}

func recordsBeforeActivationAreDropped(t *testing.T, h Harness) {
	early := record("scan-early")
	early.OccurredAt = activatedAt.Add(-time.Minute)
	onTime := record("scan-on-time")
	onTime.OccurredAt = activatedAt
	if err := appendIn(t, h, TenantA, early, onTime); err != nil {
		t.Fatal(err)
	}
	got := h.Records(t, TenantA)
	if len(got) != 1 || got[0].SourceID != "scan-on-time" {
		t.Fatalf("records = %+v, want only the one at activation", got)
	}
	if err := appendIn(t, h, TenantB, notification.SourceRecord{
		TenantID: TenantB, SourceKind: "scan_job", SourceID: "scan-b", EventType: notification.EventScanCompleted,
		OccurredAt: activatedAt.Add(time.Hour), Data: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if got := h.Records(t, TenantB); len(got) != 0 {
		t.Fatalf("tenant without activation recorded %+v", got)
	}
}

func sameJSON(raw json.RawMessage, want string) bool {
	var got, expected any
	return json.Unmarshal(raw, &got) == nil && json.Unmarshal([]byte(want), &expected) == nil && equalJSON(got, expected)
}

func equalJSON(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}
