package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEngagementIngestURLEscapesTheID(t *testing.T) {
	for _, tc := range []struct {
		name, server, id, asset, want string
		wantErr                       bool
	}{
		{name: "plain", server: "https://console.example", id: "eng-1", want: "https://console.example/api/v1/engagements/eng-1/sarif"},
		{name: "trailing slash", server: "https://console.example/", id: "eng-1", want: "https://console.example/api/v1/engagements/eng-1/sarif"},
		{name: "base path", server: "https://console.example/synapse", id: "eng-1", want: "https://console.example/synapse/api/v1/engagements/eng-1/sarif"},
		{name: "asset", server: "https://console.example", id: "eng-1", asset: "asset 1", want: "https://console.example/api/v1/engagements/eng-1/sarif?asset_id=asset+1"},
		// A slash in the id would otherwise reach a different route than the one the operator named.
		{name: "slash in id", server: "https://console.example", id: "eng/../../users", want: "https://console.example/api/v1/engagements/eng%2F..%2F..%2Fusers/sarif"},
		{name: "empty id", server: "https://console.example", id: "  ", wantErr: true},
		{name: "relative server", server: "/console", id: "eng-1", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engagementIngestURL(tc.server, tc.id, tc.asset)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("url = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPushEngagementSARIFReportsWhatTheServerDid(t *testing.T) {
	var gotBody []byte
	var gotAuth, gotType, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotAuth, gotType, gotPath = r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accepted":3,"deduplicated":1,"matched_first_party":2,
			"refused":[{"rule":"no-location","reason":"result has no artifact location"}],
			"coverage":["severity 'note' mapped to info"]}`))
	}))
	defer srv.Close()

	target := pushTarget{server: srv.URL, engagement: "eng-1", token: "tok"}
	result, err := pushEngagementSARIF(context.Background(), srv.Client(), target, []byte(`{"runs":[]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/api/v1/engagements/eng-1/sarif" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer tok" || gotType != "application/json" {
		t.Fatalf("auth = %q, content-type = %q", gotAuth, gotType)
	}
	if string(gotBody) != `{"runs":[]}` {
		t.Fatalf("body = %q", gotBody)
	}
	if result.Accepted != 3 || result.Deduplicated != 1 || result.Matched != 2 {
		t.Fatalf("counts = %+v", result)
	}

	var out bytes.Buffer
	reportEngagementIngest(&out, "eng-1", result)
	report := out.String()
	for _, want := range []string{"3 finding(s) accepted", "1 deduplicated", "2 matched", "refused no-location", "coverage: severity"} {
		if !strings.Contains(report, want) {
			t.Fatalf("report is missing %q:\n%s", want, report)
		}
	}
}

func TestPushEngagementSARIFPassesTheServerRefusalThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found: engagement"}`))
	}))
	defer srv.Close()

	_, err := pushEngagementSARIF(context.Background(), srv.Client(),
		pushTarget{server: srv.URL, engagement: "missing", token: "tok"}, []byte(`{}`))
	if err == nil {
		t.Fatal("a 404 must fail the push")
	}
	// The operator needs the server's reason, not just the status.
	if !strings.Contains(err.Error(), "not found: engagement") {
		t.Fatalf("error lost the server's reason: %v", err)
	}
}

func TestPushTargetValidateAcceptsEitherDestination(t *testing.T) {
	base := pushTarget{server: "https://console.example", token: "tok"}
	for _, tc := range []struct {
		name    string
		target  pushTarget
		wantErr string
	}{
		{name: "project only", target: func() pushTarget { t := base; t.project = "my-app"; return t }()},
		{name: "engagement only", target: func() pushTarget { t := base; t.engagement = "eng-1"; return t }()},
		{name: "both", target: func() pushTarget { t := base; t.project, t.engagement = "my-app", "eng-1"; return t }()},
		{name: "neither", target: base, wantErr: "--project KEY, --engagement ID, or both"},
		{name: "asset without engagement", target: func() pushTarget { t := base; t.project, t.asset = "my-app", "a1"; return t }(), wantErr: "--asset"},
		{name: "push-source without project", target: func() pushTarget { t := base; t.engagement, t.source = "eng-1", true; return t }(), wantErr: "--push-source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.target.validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}

func TestEngagementIngestDecodesAnEmptyRefusalList(t *testing.T) {
	var out engagementIngest
	if err := json.Unmarshal([]byte(`{"accepted":0,"deduplicated":0,"matched_first_party":0,"refused":[],"coverage":[]}`), &out); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	reportEngagementIngest(&buf, "eng-1", out)
	if got := buf.String(); got != "Engagement eng-1: 0 finding(s) accepted\n" {
		t.Fatalf("report = %q", got)
	}
}
