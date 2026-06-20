package oidc

import (
	"context"
	"fmt"
)

// Registry owns the configured OIDC providers, built once at boot. Each provider
// runs issuer discovery on construction, so an unreachable/misconfigured issuer
// fails fast.
type Registry struct {
	order     []string             // config order, for stable button rendering
	providers map[string]*Provider // keyed by provider id
}

// ButtonInfo is the {id,label} the login page renders one button per.
type ButtonInfo struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// NewRegistry builds a provider for each config (in order). IDs are assumed
// validated unique by config validation. Returns an error on the first provider
// whose discovery fails.
func NewRegistry(ctx context.Context, cfgs []Config) (*Registry, error) {
	r := &Registry{providers: make(map[string]*Provider, len(cfgs))}
	for _, cfg := range cfgs {
		p, err := New(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("oidc provider %q: %w", cfg.ID, err)
		}
		r.providers[cfg.ID] = p
		r.order = append(r.order, cfg.ID)
	}
	return r, nil
}

// Get returns the provider for id.
func (r *Registry) Get(id string) (*Provider, bool) {
	if r == nil {
		return nil, false
	}
	p, ok := r.providers[id]
	return p, ok
}

// IDs returns the configured provider ids in config order.
func (r *Registry) IDs() []string {
	if r == nil {
		return nil
	}
	return r.order
}

// Buttons returns the {id,label} list for the login page, in config order.
func (r *Registry) Buttons() []ButtonInfo {
	if r == nil {
		return nil
	}
	out := make([]ButtonInfo, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, ButtonInfo{ID: id, Label: r.providers[id].Label()})
	}
	return out
}

// Enabled reports whether any provider is configured.
func (r *Registry) Enabled() bool {
	return r != nil && len(r.order) > 0
}
