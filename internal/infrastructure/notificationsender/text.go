package notificationsender

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// eventText supplies safe built-in content when the preferred title/summary
// fields are missing. That fallback is reported by the sender, not inferred
// from the transport result or from untrusted event payload fields.
func eventText(w ports.NotificationWork) (string, string, bool) {
	var data map[string]any
	_ = json.Unmarshal(w.Event.Data, &data)
	fallback := false
	title := fmt.Sprint(data["title"])
	if title == "<nil>" || strings.TrimSpace(title) == "" {
		title = "Synapse: " + string(w.Event.Type)
		fallback = true
	}
	summary := fmt.Sprint(data["summary"])
	if summary == "<nil>" || strings.TrimSpace(summary) == "" {
		summary = "A " + string(w.Event.Type) + " event occurred at " + w.Event.OccurredAt.UTC().Format(time.RFC3339)
		fallback = true
	}
	return safeHeader(title), summary, fallback
}

func safeHeader(v string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(limit(v, 180)))
}

func limit(v string, n int) string {
	runes := []rune(v)
	if len(runes) > n {
		return string(runes[:n])
	}
	return v
}
