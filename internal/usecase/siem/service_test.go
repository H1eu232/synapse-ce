package siemuc

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

type seqIDs struct{ n int }

func (s *seqIDs) NewID() shared.ID {
	s.n++
	return shared.ID("id-" + itoa(s.n))
}

type vaultSealer struct{ cipher *vault.Cipher }

func (v vaultSealer) Seal(_ context.Context, plaintext, aad []byte) (string, error) {
	return v.cipher.Seal(plaintext, aad)
}
func (v vaultSealer) Open(_ context.Context, ciphertext string, aad []byte) ([]byte, error) {
	return v.cipher.Open(ciphertext, aad)
}

type memAudit struct{ entries []ports.AuditEntry }

func (m *memAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	m.entries = append(m.entries, entry)
	return nil
}

type scriptDriver struct {
	mu    sync.Mutex
	calls int
	seen  [][]byte
	fn    func(call int, req siem.Delivery) (siem.DeliveryResult, error)
}

func (d *scriptDriver) Deliver(_ context.Context, req siem.Delivery) (siem.DeliveryResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	for _, record := range req.Records {
		d.seen = append(d.seen, append([]byte(nil), record.Body...))
		if json.Valid(record.Body) == false {
			return siem.DeliveryResult{}, errNotJSON
		}
	}
	return d.fn(d.calls, req)
}

var errNotJSON = invalid("driver saw a non-JSON body")

func ackAll(req siem.Delivery) siem.DeliveryResult {
	items := make([]siem.DeliveryItem, len(req.Records))
	for i := range items {
		items[i].Disposition = siem.ItemAcked
	}
	return siem.DeliveryResult{Items: items}
}

func testService(t *testing.T) (*Service, *Memory, *scriptDriver, *memAudit, fakeClock) {
	t.Helper()
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	for i := range [32]byte{} {
		_ = i
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err = vault.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemory()
	driver := &scriptDriver{fn: func(_ int, req siem.Delivery) (siem.DeliveryResult, error) { return ackAll(req), nil }}
	auditLog := &memAudit{}
	clock := fakeClock{now: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	svc, err := NewService(store, store, store, vaultSealer{cipher}, map[siem.Provider]ports.SIEMDriver{siem.ProviderSplunk: driver}, auditLog, clock, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return svc, store, driver, auditLog, clock
}

func chain(actor, action, target, prev string, at time.Time, meta map[string]string) siem.AuditFact {
	if meta == nil {
		meta = map[string]string{}
	}
	hash := audit.ComputeHash(prev, actor, action, target, meta, at)
	return siem.AuditFact{
		Actor: actor, Action: action, Target: target, AtUnixMicro: at.UnixMicro(),
		Hash: hash, PreviousHash: prev, HashVersion: 2, Severity: meta["severity"],
		EngagementID: meta["engagement_id"], AdvisoryID: meta["advisory_id"], Title: meta["title"],
	}
}

func TestCreateRejectsMachineAndTickExportsWithoutAuditingTheBatch(t *testing.T) {
	svc, store, driver, auditLog, clock := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	if _, err := svc.Create(ctx, "mcp", SinkInput{Name: "Main", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088", Secret: "splunk-token"}); err == nil {
		t.Fatal("machine principal created a sink")
	}
	sink, err := svc.Create(ctx, "ada", SinkInput{Name: "Main", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088", Secret: "splunk-token"})
	if err != nil {
		t.Fatal(err)
	}
	at := clock.now
	meta := map[string]string{"severity": "high"}
	first := chain("ada", "user.login", "console", "", at, meta)
	first.ID = 4
	second := chain("ada", "user.login", "console", first.Hash, at, meta)
	second.ID = 11
	store.AddAudit("tenant-a", first, meta)
	store.AddAudit("tenant-a", second, meta)
	stats, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 4, Deadline: clock.now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Sent == 0 || driver.calls == 0 {
		t.Fatalf("stats %+v calls %d", stats, driver.calls)
	}
	body := string(driver.seen[0])
	if body == "" || contains(body, "splunk-token") {
		t.Fatalf("payload leaked or empty: %s", body)
	}
	cp, ok, err := store.Checkpoint(ctx, sink.ID, siem.SourceAudit)
	if err != nil || !ok || cp.Position.AuditID != 11 {
		t.Fatalf("checkpoint %+v ok %v err %v", cp, ok, err)
	}
	before := len(auditLog.entries)
	if _, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 4}); err != nil {
		t.Fatal(err)
	}
	if driver.calls != 1 {
		t.Fatalf("caught-up tick sent again: %d", driver.calls)
	}
	if len(auditLog.entries) != before {
		t.Fatal("export wrote an audit event")
	}
}

func TestBrokenChainDoesNotAdvanceAndPartialAckResumes(t *testing.T) {
	svc, store, driver, _, clock := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	sink, err := svc.Create(ctx, "ada", SinkInput{Name: "Main", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088", Secret: "splunk-token"})
	if err != nil {
		t.Fatal(err)
	}
	at := clock.now
	meta := map[string]string{}
	good := chain("ada", "user.login", "console", "", at, meta)
	good.ID = 1
	bad := chain("ada", "user.login", "console", good.Hash, at, meta)
	bad.ID = 2
	bad.Hash = "tampered"
	store.AddAudit("tenant-a", good, meta)
	store.AddAudit("tenant-a", bad, meta)
	if _, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 1}); err != nil {
		t.Fatal(err)
	}
	cp, ok, err := store.Checkpoint(ctx, sink.ID, siem.SourceAudit)
	if err != nil || !ok || cp.Position.AuditID != 1 {
		t.Fatalf("cursor passed the break: %+v", cp)
	}
	fresh, err := svc.Get(ctx, "ada", sink.ID)
	if err != nil || fresh.BlockedReason == "" {
		t.Fatalf("break was not blocked: %+v %v", fresh, err)
	}

	store2 := NewMemory()
	driver.calls = 0
	driver.fn = func(call int, req siem.Delivery) (siem.DeliveryResult, error) {
		if call == 1 {
			return siem.DeliveryResult{Items: []siem.DeliveryItem{
				{Disposition: siem.ItemAcked},
				{Disposition: siem.ItemFailed, Retryable: true},
				{Disposition: siem.ItemAcked},
			}}, nil
		}
		return ackAll(req), nil
	}
	cipher, _ := vault.NewCipher(bytesKey())
	svc, err = NewService(store2, store2, store2, vaultSealer{cipher}, map[siem.Provider]ports.SIEMDriver{siem.ProviderSplunk: driver}, &memAudit{}, clock, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	sink, err = svc.Create(ctx, "ada", SinkInput{Name: "Partial", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088", Secret: "splunk-token"})
	if err != nil {
		t.Fatal(err)
	}
	var prev string
	for id := int64(1); id <= 3; id++ {
		row := chain("ada", "user.login", "console", prev, at, meta)
		row.ID = id
		prev = row.Hash
		store2.AddAudit("tenant-a", row, meta)
	}
	if _, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 1}); err != nil {
		t.Fatal(err)
	}
	cp, _, _ = store2.Checkpoint(ctx, sink.ID, siem.SourceAudit)
	if cp.Position.AuditID != 1 {
		t.Fatalf("partial cursor = %d", cp.Position.AuditID)
	}
	svc.clock = fakeClock{now: clock.now.Add(time.Minute)}
	if _, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 1}); err != nil {
		t.Fatal(err)
	}
	cp, _, _ = store2.Checkpoint(ctx, sink.ID, siem.SourceAudit)
	if cp.Position.AuditID != 3 {
		t.Fatalf("resumed cursor = %d", cp.Position.AuditID)
	}
	if driver.calls != 2 {
		t.Fatalf("calls = %d", driver.calls)
	}
}

func TestTimeoutThenSuccessIsAtLeastOnce(t *testing.T) {
	svc, store, driver, _, clock := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	driver.fn = func(call int, req siem.Delivery) (siem.DeliveryResult, error) {
		if call == 1 {
			return siem.DeliveryResult{}, context.DeadlineExceeded
		}
		return ackAll(req), nil
	}
	sink, err := svc.Create(ctx, "ada", SinkInput{Name: "Retry", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088", Secret: "splunk-token"})
	if err != nil {
		t.Fatal(err)
	}
	row := chain("ada", "user.login", "console", "", clock.now, map[string]string{})
	row.ID = 1
	store.AddAudit("tenant-a", row, map[string]string{})
	if _, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 1}); err != nil {
		t.Fatal(err)
	}
	cp, ok, _ := store.Checkpoint(ctx, sink.ID, siem.SourceAudit)
	if ok && cp.Position.AuditID != 0 {
		t.Fatalf("timeout advanced the cursor: %+v", cp)
	}
	svc.clock = fakeClock{now: clock.now.Add(time.Minute)}
	if _, err := svc.Tick(ctx, "siem-worker-1", TickBudget{MaxPartitions: 1}); err != nil {
		t.Fatal(err)
	}
	cp, ok, _ = store.Checkpoint(ctx, sink.ID, siem.SourceAudit)
	if !ok || cp.Position.AuditID != 1 || driver.calls != 2 {
		t.Fatalf("retry cursor %+v ok %v calls %d", cp, ok, driver.calls)
	}
}

func TestTwoWorkersCannotBothCommit(t *testing.T) {
	svc, store, driver, _, clock := testService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	if _, err := svc.Create(ctx, "ada", SinkInput{Name: "Race", Provider: siem.ProviderSplunk, Origin: "https://splunk.example:8088", Secret: "splunk-token"}); err != nil {
		t.Fatal(err)
	}
	row := chain("ada", "user.login", "console", "", clock.now, nil)
	row.ID = 1
	store.AddAudit("tenant-a", row, map[string]string{})
	var wg sync.WaitGroup
	wg.Add(2)
	for _, worker := range []string{"siem-worker-1", "siem-worker-2"} {
		go func(worker string) {
			defer wg.Done()
			_, _ = svc.Tick(ctx, worker, TickBudget{MaxPartitions: 1})
		}(worker)
	}
	wg.Wait()
	if driver.calls != 1 {
		t.Fatalf("workers sent %d times", driver.calls)
	}
}

func bytesKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func contains(s, part string) bool {
	return len(part) > 0 && len(s) >= len(part) && (s == part || len(s) > len(part) && indexOf(s, part) >= 0)
}

func indexOf(s, part string) int {
	for i := 0; i+len(part) <= len(s); i++ {
		if s[i:i+len(part)] == part {
			return i
		}
	}
	return -1
}
