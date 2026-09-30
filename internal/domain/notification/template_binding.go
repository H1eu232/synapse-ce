package notification

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

// channelFamilies maps each channel type to the template family it renders (EPIC #1327 D5). A
// channel has exactly one type, so it binds at most one template: the one of its family. A new
// channel type adds an entry here; Microsoft Teams and Google Chat will join FamilyChat.
var channelFamilies = map[ChannelType]TemplateFamily{
	ChannelWebhook: FamilyWebhook,
	ChannelSlack:   FamilyChat,
	ChannelEmail:   FamilyEmail,
}

// FamilyForChannelType returns the template family a channel type renders. ok is false for a type
// without a family, which then only ever renders the built-in content.
func FamilyForChannelType(t ChannelType) (TemplateFamily, bool) {
	family, ok := channelFamilies[t]
	return family, ok
}

// TemplateBinding is the template configuration of one channel (#1371): the template it renders
// with and the language it renders in.
//
// TemplateID names a tenant template of the channel's family. Resolution uses that template's
// active version; while the template is not active (archived, or replaced by another template of
// the same key) or does not cover the event type, resolution falls through to the tenant tiers.
//
// Locale is en or vi, or empty to use the tenant's default locale.
type TemplateBinding struct {
	TemplateID shared.ID      `json:"template_id,omitempty"`
	Locale     tenancy.Locale `json:"locale,omitempty"`
}

// Validate checks the binding against the channel type. It does not look the template up; the use
// case checks that the template exists, is active, has the channel's family and covers every event
// routed to the channel.
func (b TemplateBinding) Validate(channelType ChannelType) error {
	if b.Locale != "" && !b.Locale.Valid() {
		return fmt.Errorf("%w: channel locale must be en or vi, or empty for the tenant default", shared.ErrValidation)
	}
	if !b.TemplateID.IsZero() {
		if _, ok := FamilyForChannelType(channelType); !ok {
			return fmt.Errorf("%w: %s channels do not render templates", shared.ErrValidation, channelType)
		}
		if err := ValidateTemplateID(b.TemplateID); err != nil {
			return err
		}
	}
	return nil
}

// Covers reports whether a template of this key can render eventType: its own event type, or any
// event for a "*" template.
func (k TemplateKey) Covers(eventType EventType) bool {
	return k.EventType == AnyEventType || k.EventType == eventType
}

// LocaleChain is the locale fallback applied within every resolution tier: the requested locale,
// then the "*" template, then English. Duplicates are removed, so an English request tries en then
// "*".
func LocaleChain(locale tenancy.Locale) []tenancy.Locale {
	if !locale.Valid() {
		locale = tenancy.DefaultLocale
	}
	chain := []tenancy.Locale{locale, AnyLocale}
	if locale != tenancy.LocaleEnglish {
		chain = append(chain, tenancy.LocaleEnglish)
	}
	return chain
}
