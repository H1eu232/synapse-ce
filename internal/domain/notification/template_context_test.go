package notification

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestSnapshotKeepsDeclaredVariablesUpToTheClass(t *testing.T) {
	spec := EventSpec{MaxDataClass: DataClassSummary, Variables: []Variable{
		{Name: "severity", Class: DataClassSignal},
		{Name: "title", Class: DataClassSummary},
		{Name: "asset_name", Class: DataClassDetail},
		{Name: "items", Class: DataClassSignal, ListCap: 5},
	}}
	got := spec.Snapshot(map[string]string{
		"severity": "high", "title": "  Scan" + string(rune(0x202e)) + " done\n ", "asset_name": "db-1", "items": "x", "undeclared": "secret",
	}).Vars
	want := map[string]string{"severity": "high", "title": "Scan done"}
	if len(got) != len(want) || got["severity"] != want["severity"] || got["title"] != want["title"] {
		t.Fatalf("snapshot = %v, want %v", got, want)
	}
}

func TestSnapshotBoundsLongValues(t *testing.T) {
	spec := EventSpec{MaxDataClass: DataClassSummary, Variables: []Variable{{Name: "title", Class: DataClassSummary}}}
	got := spec.Snapshot(map[string]string{"title": strings.Repeat("é", 5000)}).Vars["title"]
	if n := len([]rune(got)); n != 1000 {
		t.Fatalf("title kept %d runes, want 1000", n)
	}
}

func TestTemplateContextRoundTrips(t *testing.T) {
	raw, err := TemplateContext{Vars: map[string]string{"title": "Scan completed"}}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeTemplateContext(raw)
	if err != nil || back.Vars["title"] != "Scan completed" {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
	for _, empty := range []json.RawMessage{nil, json.RawMessage(`{}`)} {
		c, err := DecodeTemplateContext(empty)
		if err != nil || c.Vars == nil || len(c.Vars) != 0 {
			t.Fatalf("decode %q = %+v, %v, want an empty context", empty, c, err)
		}
	}
	if _, err := DecodeTemplateContext(json.RawMessage(`[]`)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("decode of a non-object = %v", err)
	}
}

// TestEventWireFormatOmitsSubjectAndContext keeps the webhook body, the raw event, unchanged: the
// subject and the snapshot are stored with the event but never sent (D4).
func TestEventWireFormatOmitsSubjectAndContext(t *testing.T) {
	e := Event{TenantID: "tenant", ID: "event", Type: EventScanCompleted, SourceKind: "scan_job", SourceID: "scan-1", SchemaVersion: 1,
		OccurredAt: time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC), Data: json.RawMessage(`{"title":"Scan completed"}`),
		SubjectKind: "scan_job", SubjectID: "scan-1", Context: json.RawMessage(`{"vars":{"title":"Scan completed"}}`)}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"event","type":"scan.completed","source_kind":"scan_job","source_id":"scan-1","schema_version":1,"occurred_at":"2026-09-27T08:00:00Z","data":{"title":"Scan completed"}}`
	if string(raw) != want {
		t.Fatalf("wire = %s\nwant %s", raw, want)
	}
}

func TestEventValidateChecksSubjectAndContext(t *testing.T) {
	valid := Event{TenantID: "tenant", ID: "event", Type: EventScanCompleted, SourceKind: "scan_job", SourceID: "scan-1", SchemaVersion: 1,
		OccurredAt: time.Now(), Data: json.RawMessage(`{}`)}
	for name, mutate := range map[string]func(*Event){
		"subject kind shape": func(e *Event) { e.SubjectKind = "Scan Job" },
		"subject id length":  func(e *Event) { e.SubjectID = strings.Repeat("x", 513) },
		"context not object": func(e *Event) { e.Context = json.RawMessage(`[]`) },
	} {
		e := valid
		mutate(&e)
		if err := e.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want ErrValidation", name, err)
		}
	}
	valid.SubjectKind, valid.SubjectID, valid.Context = "scan_job", "scan-1", json.RawMessage(`{"vars":{}}`)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid event: %v", err)
	}
}

// TestEveryEventDeclaresTheCommonVariables keeps "*" templates usable: #1370 validates them against
// every catalog event, so a variable missing from one event would make it unusable in all.
func TestEveryEventDeclaresTheCommonVariables(t *testing.T) {
	for _, spec := range EventCatalog() {
		declared := map[string]bool{}
		for _, v := range spec.Variables {
			if declared[v.Name] {
				t.Errorf("%s declares %s twice", spec.Type, v.Name)
			}
			declared[v.Name] = true
			if v.Class.Rank() == 0 || v.Description == "" {
				t.Errorf("%s.%s has no class or description", spec.Type, v.Name)
			}
		}
		for _, common := range commonVariables {
			if !declared[common.Name] {
				t.Errorf("%s does not declare %s", spec.Type, common.Name)
			}
		}
	}
}
