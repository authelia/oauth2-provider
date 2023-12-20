// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

// Headers is the jwt headers
type Headers struct {
	Extra map[string]any `json:"extra"`
}

func NewHeaders() *Headers {
	return &Headers{Extra: map[string]any{}}
}

// ToMap will transform the headers to a map structure
func (h *Headers) ToMap() map[string]any {
	var filter = map[string]bool{"alg": true}
	var extra = map[string]any{}

	// filter known values from extra.
	for k, v := range h.Extra {
		if _, ok := filter[k]; !ok {
			extra[k] = v
		}
	}

	return extra
}

// Add will add a key-value pair to the extra field
func (h *Headers) Add(key string, value any) {
	if h.Extra == nil {
		h.Extra = make(map[string]any)
	}
	h.Extra[key] = value
}

// Get will get a value from the extra field based on a given key
func (h *Headers) Get(key string) any {
	return h.Extra[key]
}

// ToMapClaims will return a jwt-go MapClaims representation
func (h Headers) ToMapClaims() MapClaims {
	return h.ToMap()
}
