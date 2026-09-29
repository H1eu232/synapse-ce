package ports

import "github.com/KKloudTarus/synapse-ce/internal/domain/notification"

// NotificationChannelConfig is the decrypted configuration of one notification channel. Each
// channel type has its own struct, so a driver receives only the fields its type defines and a
// new type adds a struct instead of widening a shared one.
//
// The structs are sealed as JSON with the field names the single shared struct used before, so
// configurations sealed by earlier releases decode unchanged.
type NotificationChannelConfig interface {
	NotificationChannelType() notification.ChannelType
}

// WebhookChannelConfig is a generic signed webhook: the receiver URL and the HMAC signing secret.
type WebhookChannelConfig struct {
	URL    string `json:"url,omitempty"`
	Secret string `json:"secret,omitempty"`
}

// NotificationChannelType implements NotificationChannelConfig.
func (WebhookChannelConfig) NotificationChannelType() notification.ChannelType {
	return notification.ChannelWebhook
}

// SlackChannelConfig is a Slack incoming webhook. The URL is the credential.
type SlackChannelConfig struct {
	URL string `json:"url,omitempty"`
}

// NotificationChannelType implements NotificationChannelConfig.
func (SlackChannelConfig) NotificationChannelType() notification.ChannelType {
	return notification.ChannelSlack
}

// EmailChannelConfig lists the recipients of an email channel. The relay is operator
// configuration and is not part of a channel.
type EmailChannelConfig struct {
	Recipients []string `json:"recipients,omitempty"`
}

// NotificationChannelType implements NotificationChannelConfig.
func (EmailChannelConfig) NotificationChannelType() notification.ChannelType {
	return notification.ChannelEmail
}
