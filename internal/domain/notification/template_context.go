package notification

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TemplateContext is the snapshot of an event's template variables (EPIC #1327 D5), stored with
// the event at projection. It has the shape msgtemplate.Data renders: flat string variables and
// lists of string maps. Templates never see the raw event.
type TemplateContext struct {
	Vars  map[string]string              `json:"vars"`
	Lists map[string][]map[string]string `json:"lists,omitempty"`
}

// Data returns the context as the template engine's input.
func (c TemplateContext) Data() msgtemplate.Data {
	return msgtemplate.Data{Vars: c.Vars, Lists: c.Lists}
}

// Snapshot keeps only the variables the event type declares, drops any declared above the type's
// maximum data class, and sanitizes and bounds every value, so a snapshot never carries a variable
// the catalog does not describe or a value a template could not safely interpolate. Empty values
// are dropped: a template reads a missing variable as empty.
func (s EventSpec) Snapshot(vars map[string]string) TemplateContext {
	out := TemplateContext{Vars: map[string]string{}}
	limit := s.MaxDataClass.Rank()
	for _, v := range s.Variables {
		if v.ListCap != 0 || v.Class.Rank() > limit {
			continue
		}
		value := boundRunes(strings.TrimSpace(msgtemplate.Sanitize(vars[v.Name])), msgtemplate.DefaultMaxValueRunes)
		if value != "" {
			out.Vars[v.Name] = value
		}
	}
	return out
}

// Encode returns the snapshot as the JSON object stored with the event.
func (c TemplateContext) Encode() (json.RawMessage, error) {
	if c.Vars == nil {
		c.Vars = map[string]string{}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxContextBytes {
		return nil, fmt.Errorf("%w: notification template context is too large", shared.ErrValidation)
	}
	return raw, nil
}

// DecodeTemplateContext reads a stored snapshot. An empty or {} snapshot, which every event
// projected before its builder existed carries, decodes to an empty context.
func DecodeTemplateContext(raw json.RawMessage) (TemplateContext, error) {
	var c TemplateContext
	if len(strings.TrimSpace(string(raw))) != 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return TemplateContext{}, fmt.Errorf("%w: notification template context is not valid", shared.ErrValidation)
		}
	}
	if c.Vars == nil {
		c.Vars = map[string]string{}
	}
	return c, nil
}

func boundRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
