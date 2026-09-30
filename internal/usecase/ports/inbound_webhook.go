package ports

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// InboundWebhookEndpoint is a privileged, transient authentication record. It must
// never be serialized, cached across requests, logged, or sent to a receiver.
type InboundWebhookEndpoint struct {
	PublicID          string
	TenantID          shared.ID
	OwnerKind         string
	OwnerID           string
	Provider          string
	CurrentVersion    int
	CurrentSealed     string
	PreviousSealed    string
	PreviousExpiresAt time.Time
	RevokedAt         *time.Time
	Enabled           bool
	RatePerMinute     int
}

// InboundWebhookStore is the only cross-tenant lookup permitted to the hook plane.
// Lookup returns secrets sealed under the vault master key. The provider receiver
// sees only the verified InboundWebhookIdentity, never these authentication fields.
type InboundWebhookStore interface {
	LookupInboundWebhook(context.Context, string) (InboundWebhookEndpoint, bool, error)
	// AdmitInboundWebhook returns 1 on admission, 0 on rate-limit and -1 when
	// revoked or rotated since the earlier lookup. It is atomic across API replicas.
	AdmitInboundWebhook(context.Context, InboundWebhookIdentity, int, bool) (int, error)
}

type InboundWebhookEventDeduper interface {
	// ClaimInboundWebhookEvent atomically records a provider event ID after
	// authentication. false,nil is an exact replay.
	ClaimInboundWebhookEvent(context.Context, InboundWebhookIdentity, string, string, time.Time) (bool, error)
	// ReleaseInboundWebhookEvent removes a claim when provider processing failed
	// before durable work was accepted, allowing a provider retry to run again.
	ReleaseInboundWebhookEvent(context.Context, InboundWebhookIdentity, string, string) error
}

type InboundWebhookIdentity struct {
	PublicID  string
	TenantID  shared.ID
	OwnerKind string
	OwnerID   string
}

type InboundWebhookEvent struct {
	Provider  string
	EventType string
	EventID   string
	Body      []byte
}

type InboundWebhookReceiver interface {
	ReceiveInboundWebhook(context.Context, InboundWebhookIdentity, InboundWebhookEvent) error
}

// InboundWebhookAAD binds each sealed key to its tenant, opaque endpoint,
// owner identity and version, preventing a privileged row copy from retargeting
// an existing ciphertext into another tenant or integration.
func InboundWebhookAAD(tenant shared.ID, publicID, ownerKind, ownerID string, version int) []byte {
	value, _ := json.Marshal([6]string{
		"synapse:inbound:webhook:v1", tenant.String(), publicID,
		ownerKind, ownerID, strconv.Itoa(version),
	})
	return value
}
