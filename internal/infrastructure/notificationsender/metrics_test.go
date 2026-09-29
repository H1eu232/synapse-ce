package notificationsender

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestEventTextFallbackFlagOnlyForMissingContent(t *testing.T) {
	w := ports.NotificationWork{
		Event: notification.Event{
			Type:       notification.EventTest,
			OccurredAt: time.Unix(1_700_000_000, 0).UTC(),
			Data:       json.RawMessage(`{}`),
		},
	}
	title, summary, fallback := eventText(w)
	if !fallback || title == "" || summary == "" {
		t.Fatalf("missing content: title=%q summary=%q fallback=%v", title, summary, fallback)
	}
	w.Event.Data = json.RawMessage(`{"title":"explicit","summary":"explicit summary"}`)
	title, summary, fallback = eventText(w)
	if fallback || title != "explicit" || summary != "explicit summary" {
		t.Fatalf("explicit content: title=%q summary=%q fallback=%v", title, summary, fallback)
	}
}

func TestSlackSenderReportsActualFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	s := New(SMTPConfig{}, time.Second)
	s.http = srv.Client() // bypass network-origin restrictions only in this local transport test
	work := ports.NotificationWork{
		Channel:  notification.Channel{Type: notification.ChannelSlack},
		Delivery: notification.Delivery{ID: "delivery"},
		Event:    notification.Event{ID: "event", Type: notification.EventTest, OccurredAt: time.Now().UTC(), Data: json.RawMessage(`{}`)},
	}
	config := ports.SlackChannelConfig{URL: srv.URL}
	if got := s.Send(context.Background(), work, config); got.StatusCode != 200 || !got.TemplateFallback {
		t.Fatalf("fallback send result=%+v", got)
	}
	work.Event.Data = json.RawMessage(`{"title":"explicit","summary":"explicit summary"}`)
	if got := s.Send(context.Background(), work, config); got.StatusCode != 200 || got.TemplateFallback {
		t.Fatalf("explicit send result=%+v", got)
	}
}
