package scmwebhook

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

type fakeIntegrations struct {
	item     integration.Integration
	bindings []integration.Binding
	err      error
}

func (f *fakeIntegrations) Get(context.Context, shared.ID, shared.ID) (integration.Integration, error) {
	return f.item, f.err
}
func (f *fakeIntegrations) ListBindings(context.Context, shared.ID, shared.ID) ([]integration.Binding, error) {
	return append([]integration.Binding(nil), f.bindings...), f.err
}

type capturedWebhookScan struct {
	tenant  shared.ID
	project shared.ID
	input   projectuc.WebhookAnalysisInput
}
type fakeProjectScans struct {
	calls []capturedWebhookScan
	err   error
}
func (f *fakeProjectScans) StartWebhookAnalysis(_ context.Context, _ string, tenant, project shared.ID, in projectuc.WebhookAnalysisInput) (ports.ScanJob, error) {
	f.calls = append(f.calls, capturedWebhookScan{tenant: tenant, project: project, input: in})
	return ports.ScanJob{ID: "job"}, f.err
}

func webhookFixture() (*Service, *fakeProjectScans, ports.InboundWebhookIdentity) {
	integrations := &fakeIntegrations{
		item: integration.Integration{ID: "integration-1", TenantID: "tenant-1", Provider: "github", Enabled: true},
		bindings: []integration.Binding{{ID: "binding-1", TenantID: "tenant-1", IntegrationID: "integration-1", ProjectID: "project-1"}},
	}
	scans := &fakeProjectScans{}
	return NewService(integrations, scans), scans, ports.InboundWebhookIdentity{
		PublicID: "hook", TenantID: "tenant-1", OwnerKind: "integration", OwnerID: "integration-1",
	}
}

func TestGitHubPushUsesOnlyStoredProjectBindingAndPinsCommit(t *testing.T) {
	svc, scans, identity := webhookFixture()
	sha := "0123456789abcdef0123456789abcdef01234567"
	body := []byte(`{"ref":"refs/heads/main","after":"` + sha + `","repository":{"clone_url":"https://evil.invalid/attacker/repo.git"}}`)
	err := svc.ReceiveInboundWebhook(context.Background(), identity, ports.InboundWebhookEvent{Provider: "github", EventType: "push", EventID: "d1", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 1 {
		t.Fatalf("scan calls=%d, want 1", len(scans.calls))
	}
	got := scans.calls[0]
	if got.tenant != "tenant-1" || got.project != "project-1" || got.input.Ref != "refs/heads/main" || got.input.Commit != sha {
		t.Fatalf("scan target=%+v", got)
	}
	if got.input.DisableGitCredentials || got.input.NoBuildExecution {
		t.Fatal("ordinary push unexpectedly used fork restrictions")
	}
}

func TestGitHubForkPullRequestDisablesCredentialsAndBuildExecution(t *testing.T) {
	svc, scans, identity := webhookFixture()
	sha := "abcdef0123456789abcdef0123456789abcdef01"
	body := []byte(`{"action":"synchronize","pull_request":{"head":{"ref":"contrib/fix","sha":"` + sha + `","repo":{"fork":true}},"base":{"ref":"main"},"repository":{"clone_url":"https://evil.invalid/fork.git"}}}`)
	err := svc.ReceiveInboundWebhook(context.Background(), identity, ports.InboundWebhookEvent{Provider: "github", EventType: "pull_request", EventID: "d2", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 1 {
		t.Fatalf("scan calls=%d, want 1", len(scans.calls))
	}
	got := scans.calls[0].input
	if got.Ref != "contrib/fix" || got.Commit != sha || !got.DisableGitCredentials || !got.NoBuildExecution {
		t.Fatalf("fork scan=%+v", got)
	}
}

func TestGitHubWebhookRejectsInvalidSHAAndAmbiguousBinding(t *testing.T) {
	svc, scans, identity := webhookFixture()
	err := svc.ReceiveInboundWebhook(context.Background(), identity, ports.InboundWebhookEvent{
		Provider: "github", EventType: "push", EventID: "d3",
		Body: []byte(`{"ref":"refs/heads/main","after":"ABCDEF"}`),
	})
	if !errors.Is(err, shared.ErrValidation) || len(scans.calls) != 0 {
		t.Fatalf("invalid sha err=%v calls=%d", err, len(scans.calls))
	}
	f := svc.integrations.(*fakeIntegrations)
	f.bindings = append(f.bindings, integration.Binding{ID: "binding-2", TenantID: "tenant-1", IntegrationID: "integration-1", ProjectID: "project-2"})
	err = svc.ReceiveInboundWebhook(context.Background(), identity, ports.InboundWebhookEvent{
		Provider: "github", EventType: "push", EventID: "d4",
		Body: []byte(`{"ref":"refs/heads/main","after":"0123456789abcdef0123456789abcdef01234567"}`),
	})
	if !errors.Is(err, shared.ErrValidation) || len(scans.calls) != 0 {
		t.Fatalf("ambiguous binding err=%v calls=%d", err, len(scans.calls))
	}
}

func TestGitHubWebhookIgnoresNonScanningEvents(t *testing.T) {
	svc, scans, identity := webhookFixture()
	if err := svc.ReceiveInboundWebhook(context.Background(), identity, ports.InboundWebhookEvent{Provider:"github", EventType:"issues", EventID:"d5", Body:[]byte(`{"action":"opened"}`)}); err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 0 {
		t.Fatalf("unexpected scans=%d", len(scans.calls))
	}
}
