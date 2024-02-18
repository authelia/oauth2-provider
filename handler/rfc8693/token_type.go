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
