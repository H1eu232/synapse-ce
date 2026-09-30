package scmwebhook

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

const githubWebhookActor = "system:github-webhook"

var (
	githubCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	githubRefPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)
)

type integrationReader interface {
	Get(context.Context, shared.ID, shared.ID) (integration.Integration, error)
	ListBindings(context.Context, shared.ID, shared.ID) ([]integration.Binding, error)
}

type projectScanStarter interface {
	StartWebhookAnalysis(context.Context, string, shared.ID, shared.ID, projectuc.WebhookAnalysisInput) (ports.ScanJob, error)
}

type webhookSealer interface {
	Seal([]byte, []byte) (string, error)
}


// Service turns an authenticated provider event into a scan of one already
// configured Project. Repository identity never comes from provider JSON.
type Service struct {
	integrations integrationReader
	projects     projectScanStarter
	admin        ports.InboundWebhookAdminStore
	sealer       webhookSealer
	audit        ports.AuditLogger
	clock        ports.Clock
	transactions ports.TenantTransactionRunner
}

func NewService(integrations integrationReader, projects projectScanStarter) *Service {
	return &Service{integrations: integrations, projects: projects}
}

// SetAdmin wires the tenant-authorized endpoint lifecycle. It is kept separate
// from NewService so receiver-only unit tests stay small, while production
// requires every dependency before exposing the management route.
func (s *Service) SetAdmin(store ports.InboundWebhookAdminStore, sealer webhookSealer, audit ports.AuditLogger, clock ports.Clock, transactions ports.TenantTransactionRunner) error {
	if s == nil || store == nil || sealer == nil || audit == nil || clock == nil || transactions == nil {
		return fmt.Errorf("%w: inbound webhook admin dependencies are required", shared.ErrValidation)
	}
	s.admin, s.sealer, s.audit, s.clock, s.transactions = store, sealer, audit, clock, transactions
	return nil
}

type GitHubWebhookCredentials struct {
	Path                    string     `json:"path"`
	Secret                  string     `json:"secret"`
	Version                 int        `json:"version"`
	Rotated                 bool       `json:"rotated"`
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at,omitempty"`
}

func randomWebhookToken(bytes int) (string, error) {
	if bytes < 32 {
		return "", fmt.Errorf("%w: webhook random token size is too small", shared.ErrValidation)
	}
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate webhook credential: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ConfigureGitHubWebhook provisions the endpoint on first use and rotates its
// secret thereafter. The plaintext secret is returned exactly once and is never
// persisted or added to audit metadata.
func (s *Service) ConfigureGitHubWebhook(ctx context.Context, tenantID, integrationID shared.ID, actor string) (GitHubWebhookCredentials, error) {
	if s == nil || s.admin == nil || s.sealer == nil || s.audit == nil || s.clock == nil || s.transactions == nil {
		return GitHubWebhookCredentials{}, fmt.Errorf("%w: inbound webhook administration is not configured", shared.ErrValidation)
	}
	if tenantID.IsZero() || integrationID.IsZero() || strings.TrimSpace(actor) == "" {
		return GitHubWebhookCredentials{}, fmt.Errorf("%w: webhook administration identity is required", shared.ErrValidation)
	}
	item, err := s.integrations.Get(ctx, tenantID, integrationID)
	if err != nil {
		return GitHubWebhookCredentials{}, err
	}
	if item.Provider != integration.Provider("github") || item.Archived {
		return GitHubWebhookCredentials{}, fmt.Errorf("%w: integration is not an active GitHub integration", shared.ErrValidation)
	}
	bindings, err := s.integrations.ListBindings(ctx, tenantID, integrationID)
	if err != nil {
		return GitHubWebhookCredentials{}, err
	}
	if len(bindings) != 1 || bindings[0].ProjectID.IsZero() {
		return GitHubWebhookCredentials{}, fmt.Errorf("%w: bind exactly one Project before configuring the GitHub webhook", shared.ErrConflict)
	}

	secret, err := randomWebhookToken(32)
	if err != nil {
		return GitHubWebhookCredentials{}, err
	}
	var result GitHubWebhookCredentials
	err = s.transactions.Run(ctx, tenantID, func(txCtx context.Context) error {
		existing, found, err := s.admin.GetInboundWebhookForOwner(txCtx, tenantID, "integration", integrationID.String())
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		action := "integration.github_webhook_provisioned"
		if !found {
			publicID, err := randomWebhookToken(32)
			if err != nil {
				return err
			}
			sealed, err := s.sealer.Seal([]byte(secret), ports.InboundWebhookAAD(tenantID, publicID, "integration", integrationID.String(), 1))
			if err != nil {
				return fmt.Errorf("seal GitHub webhook secret: %w", err)
			}
			created, err := s.admin.ProvisionInboundWebhook(txCtx, ports.InboundWebhookEndpoint{
				PublicID: publicID, TenantID: tenantID, OwnerKind: "integration", OwnerID: integrationID.String(),
				Provider: "github", CurrentVersion: 1, CurrentSealed: sealed, Enabled: true, RatePerMinute: 60,
			})
			if err != nil {
				return err
			}
			if !created {
				return fmt.Errorf("%w: GitHub webhook endpoint already exists", shared.ErrConflict)
			}
			result = GitHubWebhookCredentials{Path: "/api/v1/hooks/" + publicID, Secret: secret, Version: 1}
		} else {
			if existing.Provider != "github" || existing.RevokedAt != nil || existing.CurrentVersion < 1 {
				return fmt.Errorf("%w: GitHub webhook endpoint cannot be rotated", shared.ErrConflict)
			}
			nextVersion := existing.CurrentVersion + 1
			sealed, err := s.sealer.Seal([]byte(secret), ports.InboundWebhookAAD(tenantID, existing.PublicID, "integration", integrationID.String(), nextVersion))
			if err != nil {
				return fmt.Errorf("seal rotated GitHub webhook secret: %w", err)
			}
			// Leave a small clock-skew margin below the hard 24-hour database cap.
			expires := now.Add(23*time.Hour + 59*time.Minute)
			rotated, err := s.admin.RotateInboundWebhook(txCtx, ports.InboundWebhookIdentity{
				PublicID: existing.PublicID, TenantID: tenantID, OwnerKind: "integration", OwnerID: integrationID.String(),
			}, existing.CurrentVersion, sealed, expires)
			if err != nil {
				return err
			}
			if !rotated {
				return fmt.Errorf("%w: GitHub webhook endpoint changed concurrently", shared.ErrConflict)
			}
			action = "integration.github_webhook_rotated"
			result = GitHubWebhookCredentials{
				Path: "/api/v1/hooks/" + existing.PublicID, Secret: secret,
				Version: nextVersion, Rotated: true, PreviousSecretExpiresAt: &expires,
			}
		}
		return s.audit.Record(txCtx, ports.AuditEntry{
			Actor: strings.TrimSpace(actor), Action: action, Target: integrationID.String(), At: now,
			Metadata: map[string]string{"provider": "github", "webhook_version": fmt.Sprintf("%d", result.Version)},
		})
	})
	if err != nil {
		return GitHubWebhookCredentials{}, err
	}
	return result, nil
}

func (s *Service) ReceiveInboundWebhook(ctx context.Context, identity ports.InboundWebhookIdentity, event ports.InboundWebhookEvent) error {
	if s == nil || s.integrations == nil || s.projects == nil {
		return fmt.Errorf("%w: SCM webhook receiver is not configured", shared.ErrValidation)
	}
	if identity.OwnerKind != "integration" || identity.OwnerID == "" || identity.TenantID.IsZero() {
		return fmt.Errorf("%w: invalid webhook owner", shared.ErrValidation)
	}
	if event.Provider != "github" {
		return fmt.Errorf("%w: unsupported SCM webhook provider", shared.ErrValidation)
	}
	item, err := s.integrations.Get(ctx, identity.TenantID, shared.ID(identity.OwnerID))
	if err != nil {
		return err
	}
	if item.Provider != integration.Provider("github") || !item.Enabled || item.Archived {
		return fmt.Errorf("%w: GitHub integration is not active", shared.ErrValidation)
	}
	bindings, err := s.integrations.ListBindings(ctx, identity.TenantID, item.ID)
	if err != nil {
		return err
	}
	if len(bindings) != 1 || bindings[0].ProjectID.IsZero() {
		return fmt.Errorf("%w: GitHub inbound integration must bind exactly one project", shared.ErrValidation)
	}

	ref, commit, fork, scan, err := githubScanTarget(event)
	if err != nil {
		return err
	}
	if !scan {
		return nil
	}
	_, err = s.projects.StartWebhookAnalysis(ctx, githubWebhookActor, identity.TenantID, bindings[0].ProjectID, projectuc.WebhookAnalysisInput{
		Ref: ref, Commit: commit,
		DisableGitCredentials: fork,
		NoBuildExecution:      fork,
	})
	return err
}

func githubScanTarget(event ports.InboundWebhookEvent) (ref, commit string, fork, scan bool, err error) {
	if event.Provider != "github" {
		return "", "", false, false, fmt.Errorf("%w: unsupported SCM webhook provider", shared.ErrValidation)
	}
	switch event.EventType {
	case "push", "pull_request":
		ref = strings.TrimSpace(event.Ref)
		commit = strings.TrimSpace(event.SHA)
		fork = event.EventType == "pull_request" && event.Fork
	default:
		return "", "", false, false, nil
	}
	if !githubRefPattern.MatchString(ref) || !githubCommitPattern.MatchString(commit) {
		return "", "", false, false, fmt.Errorf("%w: invalid GitHub webhook ref or commit", shared.ErrValidation)
	}
	return ref, commit, fork, true, nil
}


