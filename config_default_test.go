// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/token/jwt"
)

func TestConfig_GetIDTokenValidationStrategy(t *testing.T) {
	c := &Config{}
	assert.Nil(t, c.GetIDTokenValidationStrategy(t.Context()), "must be nil when unconfigured")

	strategy := &testTokenValidationStrategy{}
	c.IDTokenValidationStrategy = strategy

	assert.Same(t, strategy, c.GetIDTokenValidationStrategy(t.Context()))
}

type testTokenValidationStrategy struct{}

func (s *testTokenValidationStrategy) ValidateIDToken(ctx context.Context, request Requester, token string, opts ...IDTokenValidationOpt) (claims jwt.MapClaims, err error) {
	return nil, nil
}
