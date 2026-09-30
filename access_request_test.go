// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testRARActionRead  = "read"
	testRARActionWrite = "write"
)

func TestAccessRequest(t *testing.T) {
	ar := NewAccessRequest(nil)
	ar.GrantTypes = Arguments{"foobar"}
	ar.Client = &DefaultClient{}
	ar.GrantScope("foo")
	ar.SetRequestedAudience(Arguments{"foo", "foo", "bar"})
	ar.SetRequestedScopes(Arguments{"foo", "foo", "bar"})
	assert.True(t, ar.GetGrantedScopes().Has("foo"))
	assert.NotNil(t, ar.GetRequestedAt())
	assert.Equal(t, ar.GrantTypes, ar.GetGrantTypes())
	assert.Equal(t, Arguments{"foo", "bar"}, ar.RequestedAudience)
	assert.Equal(t, Arguments{"foo", "bar"}, ar.RequestedScope)
	assert.Equal(t, ar.Client, ar.GetClient())
}

func TestSanitizeRestoreRefreshTokenOriginalRequesterRestoresAuthorizationDetails(t *testing.T) {
	original := NewAccessRequest(nil)
	original.SetID("original")
	original.SetRequestedAuthorizationDetails(AuthorizationDetails{{Type: "a", Actions: []string{testRARActionRead, testRARActionWrite}}})
	original.SetGrantedAuthorizationDetails(AuthorizationDetails{{Type: "a", Actions: []string{testRARActionRead, testRARActionWrite}}})

	narrowed := NewAccessRequest(nil)
	narrowed.SetRequestedAuthorizationDetails(AuthorizationDetails{{Type: "a", Actions: []string{testRARActionRead}}})
	narrowed.SetGrantedAuthorizationDetails(AuthorizationDetails{{Type: "a", Actions: []string{testRARActionRead}}})

	restored := narrowed.SanitizeRestoreRefreshTokenOriginalRequester(original)

	assert.Equal(t, original.GetRequestedAuthorizationDetails(), restored.GetRequestedAuthorizationDetails())
	assert.Equal(t, original.GetGrantedAuthorizationDetails(), restored.GetGrantedAuthorizationDetails())
}
