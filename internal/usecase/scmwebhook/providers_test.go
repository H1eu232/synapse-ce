package scmwebhook

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestBothSCMProvidersScanThroughSharedReceiver(t *testing.T) {
	github, githubScans, githubIdentity := webhookFixture()
	gitlabScans := &fakeProjectScanner{}
	gitlab := newReceiverForTest(t, &fakeBindingReader{bindings: []integration.Binding{
		{IntegrationID: "gitlab-hook", ProjectID: "gitlab-project"},
	}}, gitlabScans, nil)
	receiver, err := NewProviderReceiver(github, gitlab)
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 40)
	if err := receiver.ReceiveInboundWebhook(context.Background(), githubIdentity, ports.InboundWebhookEvent{
		Provider: "github", EventType: "pull_request", EventID: "github-delivery", Ref: "fork/fix", SHA: sha, Fork: true,
	}); err != nil {
		t.Fatal(err)
	}
	if len(githubScans.calls) != 1 || len(gitlabScans.calls) != 0 {
		t.Fatalf("GitHub delivery: github=%d gitlab=%d", len(githubScans.calls), len(gitlabScans.calls))
	}
	if in := githubScans.calls[0].input; !in.DisableGitCredentials || !in.NoBuildExecution || in.Commit != sha {
		t.Fatalf("GitHub fork restrictions lost during dispatch: %+v", in)
	}
	event := ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Push Hook", EventID: "gitlab-delivery",
		Body: []byte(`{"object_kind":"push","ref":"refs/heads/main","after":"` + sha + `"}`),
	}
	for range 2 {
		if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), event); err != nil {
			t.Fatal(err)
		}
	}
	if len(githubScans.calls) != 1 || len(gitlabScans.calls) != 1 {
		t.Fatalf("GitLab replay: github=%d gitlab=%d", len(githubScans.calls), len(gitlabScans.calls))
	}
	if got := gitlabScans.calls[0]; got.project != "gitlab-project" || got.tenant != "tenant" || got.sha != sha {
		t.Fatalf("GitLab dispatch lost its bound identity or pin: %+v", got)
	}
	event.Provider = "unknown"
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), event); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown provider error=%v", err)
	}
	if len(githubScans.calls) != 1 || len(gitlabScans.calls) != 1 {
		t.Fatal("unsupported provider invoked an SCM receiver")
	}
}
