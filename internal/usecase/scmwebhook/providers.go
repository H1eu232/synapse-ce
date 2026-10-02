package scmwebhook

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ProviderReceiver routes by the authenticated endpoint provider. Both receivers
// share the hook plane while retaining their own payload and replay handling.
type ProviderReceiver struct {
	github ports.InboundWebhookReceiver
	gitlab ports.InboundWebhookReceiver
}

var _ ports.InboundWebhookReceiver = (*ProviderReceiver)(nil)

func NewProviderReceiver(github, gitlab ports.InboundWebhookReceiver) (*ProviderReceiver, error) {
	if github == nil || gitlab == nil {
		return nil, fmt.Errorf("%w: both SCM webhook receivers are required", shared.ErrValidation)
	}
	return &ProviderReceiver{github: github, gitlab: gitlab}, nil
}

func (r *ProviderReceiver) ReceiveInboundWebhook(ctx context.Context, identity ports.InboundWebhookIdentity, event ports.InboundWebhookEvent) error {
	switch event.Provider {
	case "github":
		return r.github.ReceiveInboundWebhook(ctx, identity, event)
	case "gitlab":
		return r.gitlab.ReceiveInboundWebhook(ctx, identity, event)
	default:
		return fmt.Errorf("%w: unsupported SCM webhook provider", shared.ErrValidation)
	}
}
