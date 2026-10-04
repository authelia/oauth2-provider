// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestSanitizeRestoreRefreshTokenOriginalRequesterRestoresAudienceAndResource(t *testing.T) {
	original := NewAccessRequest(nil)
	original.SetID("original")
	original.SetRequestedAudience(Arguments{"https://a.example.com", "https://b.example.com"})
	original.GrantAudience("https://a.example.com")
	original.GrantAudience("https://b.example.com")
	original.SetRequestedResource(Arguments{"https://a.example.com/api", "https://b.example.com/api"})
	original.GrantResource("https://a.example.com/api")
	original.GrantResource("https://b.example.com/api")

	narrowed := NewAccessRequest(nil)
	narrowed.SetRequestedAudience(Arguments{"https://a.example.com"})
	narrowed.GrantAudience("https://a.example.com")
	narrowed.SetRequestedResource(Arguments{"https://a.example.com/api"})
	narrowed.GrantResource("https://a.example.com/api")

	restored := narrowed.SanitizeRestoreRefreshTokenOriginalRequester(original)

	assert.Equal(t, original.GetRequestedAudience(), restored.GetRequestedAudience())
	assert.Equal(t, original.GetGrantedAudience(), restored.GetGrantedAudience())
	assert.Equal(t, original.GetRequestedResource(), restored.GetRequestedResource())
	assert.Equal(t, original.GetGrantedResource(), restored.GetGrantedResource())
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

const (
	testRARActionRead  = "read"
	testRARActionWrite = "write"
)
