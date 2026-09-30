package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const inboundWebhookBodyLimit = 1 << 20 // 1 MiB of raw, signed bytes.
const inboundWebhookSignature = "X-Synapse-Hook-Signature"

const (
	githubSignatureHeader = "X-Hub-Signature-256"
	githubEventHeader     = "X-GitHub-Event"
	githubDeliveryHeader  = "X-GitHub-Delivery"
)

var (
	githubWebhookSHA = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const inboundWebhookBodyLimit = 1 << 20 // 1 MiB of raw, signed bytes.
const inboundWebhookSignature = "X-Synapse-Hook-Signature"

const (
	githubSignatureHeader = "X-Hub-Signature-256"
	githubEventHeader     = "X-GitHub-Event"
	githubDeliveryHeader  = "X-GitHub-Delivery"
)

var (
	githubWebhookSHA = regexp.MustCompile()
	githubWebhookRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)
)

// The hook plane is mounted on a method-aware top-level mux outside the human
// bearer/OIDC/AUP chain. Only its own header HMAC can establish tenant identity.
// There is deliberately no in-memory tenant fallback or caller-supplied tenant ID.
type inboundWebhookPlane struct {
	store    ports.InboundWebhookStore
	cipher   *vault.Cipher
	receiver ports.InboundWebhookReceiver
}

func (rt *Router) SetInboundWebhookPlane(store ports.InboundWebhookStore, cipher *vault.Cipher, receiver ports.InboundWebhookReceiver) {
	if store == nil || cipher == nil {
		rt.inboundWebhooks = nil
		return
	}
	rt.inboundWebhooks = &inboundWebhookPlane{store: store, cipher: cipher, receiver: receiver}
}

func webhookUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthorized"})
}

func webhookUnauthorizedAt(w http.ResponseWriter, r *http.Request, started time.Time) {
	// Uniform minimum duration on every 401, including disabled integrations
	// discovered after MAC verification. Never reveal whether the failure was
	// the endpoint, its authentication state, or its owner.
	if remaining := 12*time.Millisecond - time.Since(started); remaining > 0 {
		timer := time.NewTimer(remaining)
		select {
		case <-timer.C:
		case <-r.Context().Done():
			timer.Stop()
		}
	}
	webhookUnauthorized(w)
}

func (p *inboundWebhookPlane) handle(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	// Every hook response is credential-adjacent. Prevent intermediaries and
	// browsers from retaining authentication failures, quota state or receiver
	// availability for an opaque endpoint URL.
	w.Header().Set("Cache-Control", "no-store")
	// Read the body before checking any credential or looking up an endpoint.
	// A streaming request cannot make an unbounded allocation, even on a 401.
	r.Body = http.MaxBytesReader(w, r.Body, inboundWebhookBodyLimit)
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: "body_too_large"})
		} else {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_body"})
		}
		return
	}

	publicID := r.PathValue("public_id")
	// A query string cannot carry credentials, routing, or tenant overrides.
	malformed := !validInboundPublicID(publicID) || r.URL.RawQuery != ""

	var endpoint ports.InboundWebhookEndpoint
	var found bool
	var lookupErr error
	if validInboundPublicID(publicID) {
		endpoint, found, lookupErr = p.store.LookupInboundWebhook(r.Context(), publicID)
	}
	if lookupErr != nil {
		// Infrastructure errors are not reported as unknown credentials.
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "webhook_unavailable"})
		return
	}

	// Evaluate both keys, even for missing, revoked or malformed endpoints.
	// Never distinguish which key matched or whether an endpoint exists.
	valid, usedPrevious := p.verifyRequest(endpoint, publicID, body, r.Header, time.Now())
	if malformed || !found || !valid {
		// Bound response-time differences between known/unknown and malformed
		// credential paths. Timing over a remote DB is inherently noisy; the
		// primary isolation controls remain uniform 401 and constant-time MACs.
		webhookUnauthorizedAt(w, r, started)
		return
	}
	// A version change or revocation between lookup and admission is a 401,
	// not an accidental acceptance against a stale cross-tenant record.
	identity := ports.InboundWebhookIdentity{
		PublicID: publicID, TenantID: endpoint.TenantID,
		OwnerKind: endpoint.OwnerKind, OwnerID: endpoint.OwnerID,
	}
	decision, err := p.store.AdmitInboundWebhook(r.Context(), identity, endpoint.CurrentVersion, usedPrevious)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "webhook_unavailable"})
		return
	}
	switch decision {
	case -1:
		webhookUnauthorizedAt(w, r, started)
		return
	case 0:
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, errorBody{Error: "rate_limited"})
		return
	case 1:
		// The store contract has exactly three outcomes. Continue only for the
		// one explicit admission value; a corrupt or future implementation must
		// not accidentally widen authentication by returning another positive.
	default:
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "webhook_unavailable"})
		return
	}
	if p.receiver == nil {
		// A verified hook without a registered provider-specific handler must
		// never acknowledge and silently discard the provider's event.
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "webhook_receiver_unavailable"})
		return
	}

	event := ports.InboundWebhookEvent{Provider: endpoint.Provider, Body: body}
	if endpoint.Provider == "github" {
		var supported, eventOK bool
		event, supported, eventOK = githubEventMetadata(r.Header, body)
		if !eventOK {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_webhook_event"})
			return
		}
		if !supported {
			writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
			return
		}
	}

	// Bind ONLY the authenticated record's tenant; do not use TenantOrDefault.
	ctx := shared.WithTenant(r.Context(), endpoint.TenantID)
	if event.EventID != "" {
		claimed, err := p.store.ClaimInboundWebhookEvent(ctx, identity, event.Provider, event.EventID, time.Now())
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "webhook_unavailable"})
			return
		}
		if !claimed {
			writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
			return
		}
	}
	if err := p.receiver.ReceiveInboundWebhook(ctx, identity, event); err != nil {
		if event.EventID != "" {
			_ = p.store.ReleaseInboundWebhookEvent(ctx, identity, event.Provider, event.EventID)
		}
		if errors.Is(err, shared.ErrValidation) {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_webhook_event"})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "webhook_receiver_unavailable"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func validInboundPublicID(s string) bool {
	if len(s) < 32 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func inboundSignature(values []string) ([sha256.Size]byte, bool) {
	var result [sha256.Size]byte
	if len(values) != 1 || len(values[0]) != len("sha256=")+sha256.Size*2 ||
		!strings.HasPrefix(values[0], "sha256=") {
		return result, false
	}
	raw, err := hex.DecodeString(values[0][len("sha256="):])
	if err != nil || len(raw) != sha256.Size {
		return result, false
	}
	copy(result[:], raw)
	return result, true
}

func (p *inboundWebhookPlane) verifyRequest(e ports.InboundWebhookEndpoint, publicID string, body []byte, header http.Header, now time.Time) (bool, bool) {
	signatureHeader := inboundWebhookSignature
	if e.Provider == "github" {
		signatureHeader = githubSignatureHeader
	}
	presented, signatureOK := inboundSignature(header.Values(signatureHeader))
	valid, usedPrevious := p.verify(e, publicID, body, presented, now)
	return valid && signatureOK, usedPrevious
}

func githubEventMetadata(header http.Header, body []byte) (ports.InboundWebhookEvent, bool, bool) {
	eventType, typeOK := singleInboundWebhookHeader(header, githubEventHeader)
	eventID, idOK := singleInboundWebhookHeader(header, githubDeliveryHeader)
	eventType = strings.ToLower(strings.TrimSpace(eventType))
	eventID = strings.TrimSpace(eventID)
	event := ports.InboundWebhookEvent{Provider: "github", EventType: eventType, EventID: eventID}
	if !typeOK || !idOK || len(eventType) < 1 || len(eventType) > 64 || !validGitHubDelivery(eventID) {
		return event, false, false
	}
	for _, r := range eventType {
		if !((r >= 'a' && r <= 'z') || r == '_') {
			return event, false, false
		}
	}

	switch eventType {
	case "push":
		var payload struct {
			Ref     string `json:"ref"`
			After   string `json:"after"`
			Deleted bool   `json:"deleted"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return event, true, false
		}
		if payload.Deleted || allZeroGitHubWebhookSHA(payload.After) {
			return event, false, true
		}
		ref, ok := normalizeGitHubWebhookRef(payload.Ref)
		sha := strings.TrimSpace(payload.After)
		if !ok || !githubWebhookSHA.MatchString(sha) {
			return event, true, false
		}
		event.Ref, event.SHA, event.Body = ref, sha, nil
		return event, true, true

	case "pull_request":
		var payload struct {
			Action string `json:"action"`
			PullRequest struct {
				Head struct {
					Ref  string `json:"ref"`
					SHA  string `json:"sha"`
					Repo *struct {
						ID int64 `json:"id"`
					} `json:"repo"`
				} `json:"head"`
				Base struct {
					Repo *struct {
						ID int64 `json:"id"`
					} `json:"repo"`
				} `json:"base"`
			} `json:"pull_request"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return event, true, false
		}
		switch strings.ToLower(strings.TrimSpace(payload.Action)) {
		case "", "opened", "reopened", "synchronize", "ready_for_review":
			// GitHub test fixtures and older deliveries may omit action; a valid
			// PR head still represents a scan-worthy state.
		default:
			return event, false, true
		}
		ref, ok := normalizeGitHubWebhookRef(payload.PullRequest.Head.Ref)
		sha := strings.TrimSpace(payload.PullRequest.Head.SHA)
		if !ok || !githubWebhookSHA.MatchString(sha) {
			return event, true, false
		}
		headRepo, baseRepo := payload.PullRequest.Head.Repo, payload.PullRequest.Base.Repo
		event.Ref, event.SHA, event.Body = ref, sha, nil
		// Repository identity is used only to decide whether credentials/build
		// execution must be suppressed. It is never used as an acquisition URL.
		event.Fork = headRepo == nil || baseRepo == nil || headRepo.ID == 0 || baseRepo.ID == 0 || headRepo.ID != baseRepo.ID
		return event, true, true

	default:
		return event, false, true
	}
}

func validGitHubDelivery(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func normalizeGitHubWebhookRef(value string) (string, bool) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "refs/heads/")
	if !githubWebhookRef.MatchString(value) {
		return "", false
	}
	return value, true
}

func allZeroGitHubWebhookSHA(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, r := range value {
		if r != '0' {
			return false
		}
	}
	return true
}

func singleInboundWebhookHeader(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

func (p *inboundWebhookPlane) verify(e ports.InboundWebhookEndpoint, publicID string, body []byte, signature [sha256.Size]byte, now time.Time) (valid, usedPrevious bool) {
	dummy := make([]byte, 32)
	current, errCurrent := p.cipher.Open(e.CurrentSealed, ports.InboundWebhookAAD(e.TenantID, publicID, e.OwnerKind, e.OwnerID, e.CurrentVersion))
	validCurrent := errCurrent == nil && len(current) >= 32
	if !validCurrent {
		for i := range current {
			current[i] = 0
		}
		current = dummy
	}
	previous, errPrevious := p.cipher.Open(e.PreviousSealed, ports.InboundWebhookAAD(e.TenantID, publicID, e.OwnerKind, e.OwnerID, e.CurrentVersion-1))
	validPrevious := errPrevious == nil && len(previous) >= 32 && e.PreviousExpiresAt.After(now) &&
		!e.PreviousExpiresAt.After(now.Add(24*time.Hour))
	if !validPrevious {
		// Even expired but successfully decrypted keys must be wiped before
		// the dummy key replaces them.
		for i := range previous {
			previous[i] = 0
		}
		previous = dummy
	}
	a := hmac.New(sha256.New, current)
	_, _ = a.Write(body)
	b := hmac.New(sha256.New, previous)
	_, _ = b.Write(body)
	c := a.Sum(nil)
	d := b.Sum(nil)
	matchCurrent := hmac.Equal(c, signature[:]) && validCurrent
	matchPrevious := hmac.Equal(d, signature[:]) && validPrevious
	for i := range current {
		current[i] = 0
	}
	for i := range previous {
		previous[i] = 0
	}
	authenticated := e.Enabled && !e.TenantID.IsZero() && e.OwnerKind != "" && e.OwnerID != "" && e.CurrentVersion > 0 &&
		e.RevokedAt == nil && e.RatePerMinute > 0 && (matchCurrent || matchPrevious)
	return authenticated, authenticated && !matchCurrent && matchPrevious
}
