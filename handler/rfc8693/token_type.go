// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
)

type DefaultTokenType struct {
	Name string
}

// GetName returns the name of the token type.
func (c *DefaultTokenType) GetName(ctx context.Context) string {
	return c.Name
}

// GetType returns the token type identifier, which is the same value as the name.
func (c *DefaultTokenType) GetType(ctx context.Context) string {
	return c.Name
}
