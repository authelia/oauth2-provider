// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
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
	testCases := []struct {
		name string
		mock func()
		err  error
	}{
		{
			name: "ShouldFailWhenTheStrategyCannotGenerateTheToken",
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(t.Context(), areq).Return("", "", errors.New(""))
			},
			err: errors.New(""),
		},
		{
			name: "ShouldFailWhenTheSessionCannotBePersisted",
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(t.Context(), areq).Return("token", "signature", nil)
				accessStore.EXPECT().CreateAccessTokenSession(t.Context(), "signature", gomock.Eq(areq.Sanitize([]string{}))).Return(errors.New(""))
			},
			err: errors.New(""),
		},
		{
			name: "ShouldIssueTheToken",
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(t.Context(), areq).Return("token", "signature", nil)
				accessStore.EXPECT().CreateAccessTokenSession(t.Context(), "signature", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.mock()

			signature, err := helper.IssueAccessToken(t.Context(), helper.Config.GetAccessTokenLifespan(t.Context()), areq, aresp)

			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
				assert.Empty(t, signature)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, "signature", signature)
		})
	}
}
