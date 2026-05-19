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

func (c *DefaultTokenType) GetName(ctx context.Context) string {
	return c.Name
}

func (c *DefaultTokenType) GetType(ctx context.Context) string {
	return c.Name
}
