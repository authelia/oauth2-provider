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

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestGetExpiresIn(t *testing.T) {
	now := time.Now().UTC()
	r := oauth2.NewAccessRequest(&oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{
			oauth2.AccessToken: now.Add(time.Hour),
		},
	})
	assert.Equal(t, time.Hour, getExpiresIn(r, oauth2.AccessToken, time.Millisecond, now))
}

func TestIssueAccessToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	areq := &oauth2.AccessRequest{}
	aresp := &oauth2.AccessResponse{Extra: map[string]any{}}
	accessStrat := mock.NewMockAccessTokenStrategy(ctrl)
	accessStore := mock.NewMockAccessTokenStorage(ctrl)
	defer ctrl.Finish()

	helper := HandleHelper{
		AccessTokenStorage:  accessStore,
		AccessTokenStrategy: accessStrat,
		Config: &oauth2.Config{
			AccessTokenLifespan: time.Hour,
		},
	}

	areq.Session = &oauth2.DefaultSession{}
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
