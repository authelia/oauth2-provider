// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	testState        = "some-foobar-state-win"
	testNonce        = "some-foobar-nonce-win"
	testSubjectPeter = "peter"
	testScopeProfile = "profile"

	testRARHintTypeNotAllowed = "The OAuth 2.0 Client is not allowed to request authorization details type 'payment_initiation'."
)

const (
	errPromptNoneIdentityNotAssured = "The Authorization Server requires End-User consent. OAuth 2.0 Client is marked public and the redirect uri does not assure the identity of the client, but 'prompt' type 'none' was requested."
	testLoopbackRedirectURI         = "http://127.0.0.1:8080/callback"
)

var key = gen.MustRSAKey()

var hmacStrategy = &hoauth2.HMACCoreStrategy{
	Enigma: &hmac.HMACStrategy{
		Config: &oauth2.Config{
			GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows-nobody-knows"),
		},
	},
}

var strategy = &DefaultStrategy{
	Strategy: &jwt.DefaultStrategy{
		Config: &oauth2.Config{
			MinParameterEntropy: oauth2.MinParameterEntropy,
		},
		Issuer: jwt.MustGenDefaultIssuer(),
	},
	Config: &oauth2.Config{
		MinParameterEntropy: oauth2.MinParameterEntropy,
	},
}

var fooErr = errors.New("foo")
