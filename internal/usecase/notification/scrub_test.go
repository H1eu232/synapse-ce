package notification

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
)

// TestBuildersScrubSecretsFromVariables is the #1361 golden test: secrets a scanner put in a
// finding title, or anywhere else a variable comes from, are gone from the snapshot before any
// template sees them, and the rest of the text is kept.
func TestBuildersScrubSecretsFromVariables(t *testing.T) {
	cases := []struct {
		name, title, want string
	}{
		{"AWS access key", "Leaked key AKIAIOSFODNN7EXAMPLE in config", "Leaked key [redacted] in config"},
		// The token is split so secret scanners do not flag the fixture, as the privacy tests do.
		{"bearer token", "Header Authorization: Bearer " + "eyJhbGciOiJIUzI1NiJ9" + ".payload.sig sent", "Header Authorization: Bearer [redacted] sent"},
		{"password assignment", "Default creds password=Hunter2! on admin", "Default creds password=[redacted] on admin"},
		{"PEM block", "Key -----BEGIN RSA PRIVATE KEY----- MIIEow -----END RSA PRIVATE KEY----- committed", "Key [redacted] committed"},
		{"URL credentials", "Clone from https://ci:s3cr3t@git.example.test/repo failed", "Clone from https://***@git.example.test/repo failed"},
		{"plain title", "SQL injection in /login", "SQL injection in /login"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			seed, err := domain.TemplateContext{Vars: map[string]string{"finding_title": c.title, "reason": c.title}}.Encode()
			if err != nil {
				t.Fatal(err)
			}
			e := domain.Event{TenantID: "tenant-1", ID: "event", Type: domain.EventOwnershipChanged, SourceKind: "ownership_decision", SourceID: "d1",
				SchemaVersion: 1, OccurredAt: time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC), Data: json.RawMessage(`{"title":` + quote(c.title) + `}`), Context: seed}
			projected, err := NewEventBuilders().Project(context.Background(), e)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := domain.DecodeTemplateContext(projected.Context)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"finding_title", "reason", "title"} {
				if got := snapshot.Vars[name]; got != c.want {
					t.Errorf("%s = %q, want %q", name, got, c.want)
				}
			}
		})
	}
}

func quote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}
