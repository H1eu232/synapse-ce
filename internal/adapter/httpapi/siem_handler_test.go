package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	siemuc "github.com/KKloudTarus/synapse-ce/internal/usecase/siem"
)

func TestSIEMRoutesAreAdminOnlyAndHideSecrets(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := vault.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	store := siemuc.NewMemory()
	svc, err := siemuc.NewService(store, store, store, vaultSealer{cipher}, nil, nil, siemClock{now: time.Unix(1_700_000_000, 0).UTC()}, &siemIDs{})
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rt.SetSIEM(svc)
	mux := rt.routes()

	denied := httptest.NewRequest(http.MethodGet, "/api/v1/siem/sinks", nil)
	denied = denied.WithContext(context.WithValue(denied.Context(), principalKey, Principal{ID: "ada", Role: "readonly", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, denied)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly status %d", rec.Code)
	}

	body := []byte(`{"name":"Main","provider":"splunk_hec","origin":"https://splunk.example:8088","secret":"splunk-token-value"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/siem/sinks", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "ada", Role: "admin", TenantID: "tenant-a"}))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("splunk-token-value")) {
		t.Fatalf("response leaked the secret: %s", rec.Body.String())
	}
	var created struct {
		ID string `json:"ID"`
	}
	// Encoding uses the Go field name unless the domain struct has json tags.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	id, _ := raw["ID"].(string)
	if id == "" {
		id, _ = raw["id"].(string)
	}
	if id == "" {
		t.Fatalf("missing id in %s", rec.Body.String())
	}
	_ = created
	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/siem/sinks/"+id+"/status", nil)
	statusReq = statusReq.WithContext(context.WithValue(statusReq.Context(), principalKey, Principal{ID: "ada", Role: "admin", TenantID: "tenant-a"}))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, statusReq)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte("legacy v1")) {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

type vaultSealer struct{ cipher *vault.Cipher }

func (v vaultSealer) Seal(context.Context, []byte, []byte) (string, error) { return "sealed", nil }
func (v vaultSealer) Open(context.Context, string, []byte) ([]byte, error) {
	return nil, shared.ErrValidation
}

type siemClock struct{ now time.Time }

func (c siemClock) Now() time.Time { return c.now }

type siemIDs struct{ n int }

func (s *siemIDs) NewID() shared.ID {
	s.n++
	return shared.ID("sink-1")
}

var _ ports.SIEMSealer = vaultSealer{}
