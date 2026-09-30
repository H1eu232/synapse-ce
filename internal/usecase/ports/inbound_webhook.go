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
	// ProcessInboundWebhookEvent atomically commits dedupe and durable enqueue.
	// The callback must use the supplied transaction context and perform no
	// inline work or remote writes. Failure rolls back both; false,nil is a replay.
	ProcessInboundWebhookEvent(context.Context, InboundWebhookIdentity, InboundWebhookEvent, func(context.Context) error) (bool, error)
}

type InboundWebhookIdentity struct {
	PublicID  string
	TenantID  shared.ID
	OwnerKind string
	OwnerID   string
}

type InboundWebhookEvent struct {
	Provider      string
	EventType     string
	EventID       string
	PayloadSHA256 string
	Body          []byte
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

// WebhookScanTarget contains authenticated source metadata. The repository URL
// is always read from the stored project, never from the webhook body.
type WebhookScanTarget struct {
	Provider           string
	Ref                string
	FetchRef           string
	SHA                string
	BaseRef            string
	MergeRequestNumber int64
	Fork               bool
}
