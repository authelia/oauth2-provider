// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "authelia.com/provider/oauth2"
)

func TestNewCIBARequest(t *testing.T) {
	request := NewCIBARequest()

	assert.NotNil(t, request)
	assert.NotNil(t, request.RequestedScope)
	assert.NotNil(t, request.GrantedScope)
	assert.NotNil(t, request.RequestedAudience)
	assert.NotNil(t, request.Form)
	assert.False(t, request.RequestedAt.IsZero())
	assert.Equal(t, CIBAStatusNew, request.GetStatus())
	assert.Equal(t, "", request.GetAuthRequestIDSignature())
	assert.True(t, request.GetLastChecked().IsZero())
}

func TestCIBARequest_StatusAccessors(t *testing.T) {
	request := NewCIBARequest()

	request.SetStatus(CIBAStatusApproved)
	assert.Equal(t, CIBAStatusApproved, request.GetStatus())

	request.SetStatus(CIBAStatusDenied)
	assert.Equal(t, CIBAStatusDenied, request.GetStatus())
}

func TestCIBARequest_AuthRequestIDSignature(t *testing.T) {
	request := NewCIBARequest()

	request.SetAuthRequestIDSignature("abc123")
	assert.Equal(t, "abc123", request.GetAuthRequestIDSignature())
}

func TestCIBARequest_LastChecked_NormalizesToUTC(t *testing.T) {
	request := NewCIBARequest()

	loc, err := time.LoadLocation("America/New_York")
	assert.NoError(t, err)

	local := time.Date(2026, 5, 28, 10, 0, 0, 0, loc)
	request.SetLastChecked(local)

	got := request.GetLastChecked()

	assert.Equal(t, time.UTC, got.Location(), "SetLastChecked must normalize to UTC")
	assert.True(t, got.Equal(local), "underlying instant should be preserved")
}

func TestCIBARequest_Merge_FromCIBARequest(t *testing.T) {
	source := NewCIBARequest()
	source.SetID("source-id")
	source.SetStatus(CIBAStatusApproved)
	source.SetAuthRequestIDSignature("sig-123")
	source.SetLastChecked(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	source.AppendRequestedScope("openid")
	source.GrantScope("openid")

	target := NewCIBARequest()
	target.Merge(source)

	assert.Equal(t, "source-id", target.GetID())
	assert.Equal(t, CIBAStatusApproved, target.GetStatus())
	assert.Equal(t, "sig-123", target.GetAuthRequestIDSignature())
	assert.Equal(t, source.GetLastChecked(), target.GetLastChecked())
	assert.True(t, target.GetRequestedScopes().Has("openid"))
	assert.True(t, target.GetGrantedScopes().Has("openid"))
}

func TestCIBARequest_Merge_FromNonCIBARequester_LeavesCIBAFieldsUntouched(t *testing.T) {
	plain := NewRequest()
	plain.SetID("plain-id")
	plain.AppendRequestedScope("openid")

	target := NewCIBARequest()
	target.SetStatus(CIBAStatusApproved)
	target.SetAuthRequestIDSignature("existing-sig")
	original := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	target.SetLastChecked(original)

	target.Merge(plain)

	assert.Equal(t, "plain-id", target.GetID())
	assert.True(t, target.GetRequestedScopes().Has("openid"))

	// CIBA-specific fields should be untouched when merging from a non-CIBA Requester.
	assert.Equal(t, CIBAStatusApproved, target.GetStatus())
	assert.Equal(t, "existing-sig", target.GetAuthRequestIDSignature())
	assert.Equal(t, original, target.GetLastChecked())
}
