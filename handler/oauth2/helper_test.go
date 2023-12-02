// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/internal"
)

func TestGetExpiresIn(t *testing.T) {
	now := time.Now().UTC()
	r := goauth2.NewAccessRequest(&goauth2.DefaultSession{
		ExpiresAt: map[goauth2.TokenType]time.Time{
			goauth2.AccessToken: now.Add(time.Hour),
		},
	})
	assert.Equal(t, time.Hour, getExpiresIn(r, goauth2.AccessToken, time.Millisecond, now))
}

func TestIssueAccessToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	areq := &goauth2.AccessRequest{}
	aresp := &goauth2.AccessResponse{Extra: map[string]any{}}
	accessStrat := internal.NewMockAccessTokenStrategy(ctrl)
	accessStore := internal.NewMockAccessTokenStorage(ctrl)
	defer ctrl.Finish()

	helper := HandleHelper{
		AccessTokenStorage:  accessStore,
		AccessTokenStrategy: accessStrat,
		Config: &goauth2.Config{
			AccessTokenLifespan: time.Hour,
		},
	}

	areq.Session = &goauth2.DefaultSession{}
	for k, c := range []struct {
		mock func()
		err  error
	}{
		{
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(context.TODO(), areq).Return("", "", errors.New(""))
			},
			err: errors.New(""),
		},
		{
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(context.TODO(), areq).Return("token", "signature", nil)
				accessStore.EXPECT().CreateAccessTokenSession(context.TODO(), "signature", gomock.Eq(areq.Sanitize([]string{}))).Return(errors.New(""))
			},
			err: errors.New(""),
		},
		{
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(context.TODO(), areq).Return("token", "signature", nil)
				accessStore.EXPECT().CreateAccessTokenSession(context.TODO(), "signature", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
			err: nil,
		},
	} {
		c.mock()
		err := helper.IssueAccessToken(context.TODO(), helper.Config.GetAccessTokenLifespan(context.TODO()), areq, aresp)
		require.Equal(t, err == nil, c.err == nil)
		if c.err != nil {
			assert.EqualError(t, err, c.err.Error(), "Case %d", k)
		}
	}
}
