package scmwebhook

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

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

// Service turns an authenticated provider event into a scan of one already
// configured Project. Repository identity never comes from provider JSON.
type Service struct {
	integrations integrationReader
	projects     projectScanStarter
}

func NewService(integrations integrationReader, projects projectScanStarter) *Service {
	return &Service{integrations: integrations, projects: projects}
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
	switch event.EventType {
	case "push":
		var payload struct {
			Ref     string `json:"ref"`
			After   string `json:"after"`
			Deleted bool   `json:"deleted"`
		}
		if err := json.Unmarshal(event.Body, &payload); err != nil {
			return "", "", false, false, fmt.Errorf("%w: invalid GitHub push payload", shared.ErrValidation)
		}
		if payload.Deleted || allZeroGitHubSHA(payload.After) {
			return "", "", false, false, nil
		}
		ref, commit = strings.TrimSpace(payload.Ref), strings.TrimSpace(payload.After)
	case "pull_request":
		var payload struct {
			Action      string `json:"action"`
			PullRequest struct {
				Head struct {
					Ref  string `json:"ref"`
					SHA  string `json:"sha"`
					Repo struct {
						Fork bool `json:"fork"`
					} `json:"repo"`
				} `json:"head"`
			} `json:"pull_request"`
		}
		if err := json.Unmarshal(event.Body, &payload); err != nil {
			return "", "", false, false, fmt.Errorf("%w: invalid GitHub pull request payload", shared.ErrValidation)
		}
		switch payload.Action {
		case "opened", "reopened", "synchronize", "ready_for_review":
		default:
			return "", "", false, false, nil
		}
		ref = strings.TrimSpace(payload.PullRequest.Head.Ref)
		commit = strings.TrimSpace(payload.PullRequest.Head.SHA)
		fork = payload.PullRequest.Head.Repo.Fork
	default:
		return "", "", false, false, nil
	}
	if !githubRefPattern.MatchString(ref) || !githubCommitPattern.MatchString(commit) {
		return "", "", false, false, fmt.Errorf("%w: invalid GitHub webhook ref or commit", shared.ErrValidation)
	}
	return ref, commit, fork, true, nil
}

func allZeroGitHubSHA(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, c := range value {
		if c != '0' {
			return false
		}
	}
	return true
}
