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
	// ClaimInboundWebhookEvent atomically records a provider event ID after
	// authentication. false,nil is an exact replay that must be acknowledged
	// without invoking the provider receiver again.
	ClaimInboundWebhookEvent(context.Context, InboundWebhookIdentity, string, string, time.Time) (bool, error)
	// ReleaseInboundWebhookEvent makes a claimed delivery retryable when the
	// provider receiver fails before durably accepting its work.
	ReleaseInboundWebhookEvent(context.Context, InboundWebhookIdentity, string, string) error
}

// InboundWebhookAdminStore is the tenant-scoped management surface for a
// provider-owned endpoint. The runtime role still has no direct DML on the
// routing table; PostgreSQL implements mutations through narrow SECURITY DEFINER
// functions that re-bind the tenant to synapse_current_tenant().
type InboundWebhookAdminStore interface {
	GetInboundWebhookForOwner(context.Context, shared.ID, string, string) (InboundWebhookEndpoint, bool, error)
	ProvisionInboundWebhook(context.Context, InboundWebhookEndpoint) (bool, error)
	RotateInboundWebhook(context.Context, InboundWebhookIdentity, int, string, time.Time) (bool, error)
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
	Ref       string
	SHA       string
	Fork      bool
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
