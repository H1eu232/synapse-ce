package notificationsender

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// webhookDriver posts the event envelope to a generic receiver, signed with HMAC-SHA256 over
// "<timestamp>.<body>" so the receiver can reject replays and forgeries.
type webhookDriver struct{ s *Sender }

func (webhookDriver) ChannelType() notification.ChannelType { return notification.ChannelWebhook }

func (d webhookDriver) Send(ctx context.Context, w ports.NotificationWork, config ports.NotificationChannelConfig) ports.NotificationSendResult {
	cfg, ok := config.(ports.WebhookChannelConfig)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	body, err := json.Marshal(w.Event)
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "encode_failed"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "request_invalid"}
	}
	timestamp := strconv.FormatInt(d.s.now().UTC().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(cfg.Secret))
	_, _ = mac.Write([]byte(timestamp + "."))
	_, _ = mac.Write(body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "synapse-notifications/1")
	req.Header.Set("X-Synapse-Timestamp", timestamp)
	req.Header.Set("X-Synapse-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Synapse-Event-ID", w.Event.ID.String())
	req.Header.Set("X-Synapse-Delivery-ID", w.Delivery.ID.String())
	return d.s.do(req)
}
