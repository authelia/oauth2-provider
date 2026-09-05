// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jose"
)

func TestDPoPIntrospectionReflectsTheBinding(t *testing.T) {
	provider, _ := newDPoPChainProvider(t)

	key := newPARProofKey(t)
	jkt := thumbprintOf(t, key)

	response, err := chainTokenRequest(t, provider, chainCodeExchangeForm(chainBoundCode(t, provider, key, "chain-introspect-1")),
		signPARProof(t, key, "chain-introspect-1-ok", rtTokenEndpoint, nil))
	require.NoError(t, err)

	accessToken := response.GetAccessToken()
	require.NotEmpty(t, accessToken)

	refreshToken, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
	require.NotEmpty(t, refreshToken)

	t.Run("ShouldReportTheAccessTokenAsBoundToTheKey", func(t *testing.T) {
		body, status := chainIntrospect(t, provider, accessToken)

		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["active"])

		bound, present := confirmationJKT(t, body)

		require.True(t, present)
		assert.Equal(t, jkt, bound)
	})

	t.Run("ShouldReportTheGrantTheChainCarried", func(t *testing.T) {
		body, _ := chainIntrospect(t, provider, accessToken)

		assert.Equal(t, chainClientID, body["client_id"])
		assert.Equal(t, consts.ScopeOffline, body["scope"])
		assert.Equal(t, "peter", body["sub"])
	})

	t.Run("ShouldReportTheRefreshTokenAsBoundToTheSameKey", func(t *testing.T) {
		body, status := chainIntrospect(t, provider, refreshToken)

		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["active"])

		bound, present := confirmationJKT(t, body)

		require.True(t, present)
		assert.Equal(t, jkt, bound)
	})

	t.Run("ShouldKeepReportingTheBindingAfterARefresh", func(t *testing.T) {
		rotated, err := chainTokenRequest(t, provider, chainRefreshForm(refreshToken),
			signPARProof(t, key, "chain-introspect-2", rtTokenEndpoint, nil))
		require.NoError(t, err)

		rotatedAccess := rotated.GetAccessToken()
		rotatedRefresh, _ := rotated.ToMap()[consts.AccessResponseRefreshToken].(string)

		rotatedTokens := []struct {
			name  string
			token string
		}{
			{name: "ShouldKeepTheBindingOnTheRotatedAccessToken", token: rotatedAccess},
			{name: "ShouldKeepTheBindingOnTheRotatedRefreshToken", token: rotatedRefresh},
		}

		for _, rotatedToken := range rotatedTokens {
			t.Run(rotatedToken.name, func(t *testing.T) {
				body, _ := chainIntrospect(t, provider, rotatedToken.token)

				assert.Equal(t, true, body["active"])

				bound, present := confirmationJKT(t, body)

				require.True(t, present)
				assert.Equal(t, jkt, bound)
			})
		}

		t.Run("ShouldReportTheSupersededRefreshTokenAsInactive", func(t *testing.T) {
			body, _ := chainIntrospect(t, provider, refreshToken)

			assert.Equal(t, false, body["active"])
		})
	})
}

func TestDPoPIntrospectionOmitsTheConfirmationWhenNotApplicable(t *testing.T) {
	t.Run("ShouldOmitItForAnUnboundGrant", func(t *testing.T) {
		provider, _ := newDPoPChainProvider(t)

		requestURI, _ := chainPushedRequestURI(t, provider, chainPARForm())

		code, session, err := chainAuthorizeCode(t, provider, requestURI, nil)
		require.NoError(t, err)
		require.Empty(t, session.GetDPoPJWKThumbprint(), "the fixture was meant to be unbound")

		response, err := chainTokenRequest(t, provider, chainCodeExchangeForm(code), "")
		require.NoError(t, err)

		body, _ := chainIntrospect(t, provider, response.GetAccessToken())

		require.Equal(t, true, body["active"])

		_, present := confirmationJKT(t, body)

		assert.False(t, present)
	})

	t.Run("ShouldOmitItOnceDPoPIsDisabled", func(t *testing.T) {
		provider, _, config := newDPoPChainProviderWithConfig(t)

		key := newPARProofKey(t)

		response, err := chainTokenRequest(t, provider, chainCodeExchangeForm(chainBoundCode(t, provider, key, "chain-introspect-3")),
			signPARProof(t, key, "chain-introspect-3-ok", rtTokenEndpoint, nil))
		require.NoError(t, err)

		accessToken := response.GetAccessToken()

		bound, present := confirmationJKT(t, mustIntrospect(t, provider, accessToken))
		require.True(t, present)
		require.Equal(t, thumbprintOf(t, key), bound)

		config.DPoPEnabled = false

		_, present = confirmationJKT(t, mustIntrospect(t, provider, accessToken))

		assert.False(t, present)
	})
}

func TestDPoPIsEnforcedWhenAnAccessTokenAuthenticatesIntrospection(t *testing.T) {
	provider, _ := newDPoPChainProvider(t)

	key := newPARProofKey(t)

	caller, _ := chainAccessToken(t, provider, key, "auth-bound")
	subject, _ := chainAccessToken(t, provider, nil, "auth-subject")

	t.Run("ShouldAcceptTheDPoPSchemeWithAValidProof", func(t *testing.T) {
		body, err := chainIntrospectAs(t, provider, subject, "DPoP", caller,
			chainProofWithATH(t, key, "auth-1", chainIntrospectEndpoint, caller))

		require.NoError(t, err)
		assert.Equal(t, true, body["active"])
	})

	t.Run("ShouldRejectABoundCredentialPresentedAsABearerToken", func(t *testing.T) {
		_, err := chainIntrospectAs(t, provider, subject, "Bearer", caller, "")

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The DPoP-bound access token was not presented using the DPoP authentication scheme. The access token must be presented via the DPoP scheme and match the introspected token (dpop scheme used: false, token matches: true).")
	})

	t.Run("ShouldRejectTheDPoPSchemeWithoutAProof", func(t *testing.T) {
		_, err := chainIntrospectAs(t, provider, subject, "DPoP", caller, "")

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The request to the protected resource requires a DPoP proof but none was provided.")
	})

	t.Run("ShouldRejectAProofFromAnotherKey", func(t *testing.T) {
		_, err := chainIntrospectAs(t, provider, subject, "DPoP", caller,
			chainProofWithATH(t, newPARProofKey(t), "auth-2", chainIntrospectEndpoint, caller))

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The DPoP proof key does not match the key the access token is bound to.")
	})

	t.Run("ShouldRejectAProofWhoseATHNamesAnotherToken", func(t *testing.T) {
		_, err := chainIntrospectAs(t, provider, subject, "DPoP", caller,
			chainProofWithATH(t, key, "auth-3", chainIntrospectEndpoint, subject))

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The DPoP proof 'ath' claim does not match the access token.")
	})

	t.Run("ShouldRejectAProofMintedForAnotherURI", func(t *testing.T) {
		_, err := chainIntrospectAs(t, provider, subject, "DPoP", caller,
			chainProofWithATH(t, key, "auth-4", rtTokenEndpoint, caller))

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The DPoP proof 'htu' claim 'https://as.example.com/token' does not match the request URI 'https://as.example.com/introspect'.")
	})

	t.Run("ShouldStillAcceptAnUnboundBearerCredential", func(t *testing.T) {
		unbound, _ := chainAccessToken(t, provider, nil, "auth-unbound")

		body, err := chainIntrospectAs(t, provider, subject, "Bearer", unbound, "")

		require.NoError(t, err)
		assert.Equal(t, true, body["active"])
	})
}

func TestIntrospectionRejectsABoundCredentialWhenTheStrategyCannotValidateResourceAccess(t *testing.T) {
	provider, _, config := newDPoPChainProviderWithConfig(t)

	key := newPARProofKey(t)

	caller, _ := chainAccessToken(t, provider, key, "auth-noresource")
	subject, _ := chainAccessToken(t, provider, nil, "auth-noresource-subject")

	proof := chainProofWithATH(t, key, "auth-5", chainIntrospectEndpoint, caller)

	config.DPoPStrategy = &proofOnlyChainDPoPStrategy{}

	_, err := chainIntrospectAs(t, provider, subject, "DPoP", caller, proof)

	require.Error(t, err)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The access token is invalid or was not presented in the manner it is bound to. The credential used to authenticate the request is bound to a DPoP key but the configured DPoP strategy cannot validate resource access.")
}

func TestMTLSIsEnforcedWhenAnAccessTokenAuthenticatesIntrospection(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})
	other := gen.MustCertificate(gen.CertificateOptions{SerialNumber: 2})

	provider, _, config := newDPoPChainProviderCertBound(t)

	caller := chainCertBoundToken(t, provider, cert, "mtls-caller")
	subject := chainCertBoundToken(t, provider, cert, "mtls-subject")

	t.Run("ShouldAcceptTheBoundCertificate", func(t *testing.T) {
		body, err := chainIntrospectAsWithCert(t, provider, subject, "Bearer", caller, "", cert)

		require.NoError(t, err)
		assert.Equal(t, true, body["active"])
	})

	t.Run("ShouldRejectWhenNoCertificateIsPresented", func(t *testing.T) {
		_, err := chainIntrospectAsWithCert(t, provider, subject, "Bearer", caller, "", nil)

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The access token is bound to a client certificate but the request was not made over a mutually authenticated TLS connection.")
	})

	t.Run("ShouldRejectADifferentCertificate", func(t *testing.T) {
		_, err := chainIntrospectAsWithCert(t, provider, subject, "Bearer", caller, "", other)

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The client certificate does not match the certificate the access token is bound to.")
	})

	t.Run("ShouldReadTheConfiguredProxyHeader", func(t *testing.T) {
		config.MTLSClientCertificateHeader = "X-Forwarded-Tls-Client-Cert"
		defer func() { config.MTLSClientCertificateHeader = "" }()

		body, err := chainIntrospectAsWithCert(t, provider, subject, "Bearer", caller, "", nil, func(r *http.Request) {
			r.Header.Set("X-Forwarded-Tls-Client-Cert", base64.StdEncoding.EncodeToString(cert.Raw))
		})

		require.NoError(t, err)
		assert.Equal(t, true, body["active"])
	})

	t.Run("ShouldRejectAWrongCertificateInTheConfiguredProxyHeader", func(t *testing.T) {
		config.MTLSClientCertificateHeader = "X-Forwarded-Tls-Client-Cert"
		defer func() { config.MTLSClientCertificateHeader = "" }()

		_, err := chainIntrospectAsWithCert(t, provider, subject, "Bearer", caller, "", nil, func(r *http.Request) {
			r.Header.Set("X-Forwarded-Tls-Client-Cert", base64.StdEncoding.EncodeToString(other.Raw))
		})

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The client certificate does not match the certificate the access token is bound to.")
	})

	t.Run("ShouldSkipOnceMTLSIsDisabled", func(t *testing.T) {
		config.MTLSEnabled = false
		defer func() { config.MTLSEnabled = true }()

		body, err := chainIntrospectAsWithCert(t, provider, subject, "Bearer", caller, "", nil)

		require.NoError(t, err)
		assert.Equal(t, true, body["active"])
	})
}

func TestBothBindingsAreEnforcedIndependentlyAtIntrospection(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})
	other := gen.MustCertificate(gen.CertificateOptions{SerialNumber: 2})

	provider, _, _ := newDPoPChainProviderCertBound(t)

	key := newPARProofKey(t)

	caller := chainBothBoundToken(t, provider, key, cert, "both-caller")
	subject := chainCertBoundToken(t, provider, cert, "both-subject")

	t.Run("ShouldAcceptWhenBothAreSatisfied", func(t *testing.T) {
		body, err := chainIntrospectAsWithCert(t, provider, subject, "DPoP", caller,
			chainProofWithATH(t, key, "both-1", chainIntrospectEndpoint, caller), cert)

		require.NoError(t, err)
		assert.Equal(t, true, body["active"])
	})

	t.Run("ShouldRejectAValidProofWithTheWrongCertificate", func(t *testing.T) {
		_, err := chainIntrospectAsWithCert(t, provider, subject, "DPoP", caller,
			chainProofWithATH(t, key, "both-2", chainIntrospectEndpoint, caller), other)

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The client certificate does not match the certificate the access token is bound to.")
	})

	t.Run("ShouldRejectTheCorrectCertificateWithAProofFromAnotherKey", func(t *testing.T) {
		_, err := chainIntrospectAsWithCert(t, provider, subject, "DPoP", caller,
			chainProofWithATH(t, newPARProofKey(t), "both-3", chainIntrospectEndpoint, caller), cert)

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The DPoP proof key does not match the key the access token is bound to.")
	})
}

func TestIntrospectionDoesNotDemandAProofForTheIntrospectedToken(t *testing.T) {
	provider, _ := newDPoPChainProvider(t)

	key := newPARProofKey(t)

	subject, subjectRefresh := chainAccessToken(t, provider, key, "subject-bound")
	caller, _ := chainAccessToken(t, provider, nil, "subject-caller")

	t.Run("ShouldIntrospectABoundAccessTokenWithoutAProofForIt", func(t *testing.T) {
		body, err := chainIntrospectAs(t, provider, subject, "Bearer", caller, "")

		require.NoError(t, err)
		assert.Equal(t, true, body["active"])

		bound, present := confirmationJKT(t, body)

		require.True(t, present)
		assert.Equal(t, thumbprintOf(t, key), bound)
	})

	t.Run("ShouldIntrospectABoundRefreshTokenWithoutAProofForIt", func(t *testing.T) {
		body, err := chainIntrospectAs(t, provider, subjectRefresh, "Bearer", caller, "")

		require.NoError(t, err)
		assert.Equal(t, true, body["active"])
	})

	t.Run("ShouldIntrospectABoundTokenUnderClientCredentials", func(t *testing.T) {
		body, status := chainIntrospect(t, provider, subject)

		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["active"])
	})
}

func TestTokenEndpointEnforcementRequiresBinding(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	newExchange := func(t *testing.T, provider oauth2.Provider) url.Values {
		t.Helper()

		requestURI, _ := chainPushedRequestURI(t, provider, chainPARForm())

		code, _, err := chainAuthorizeCode(t, provider, requestURI, nil)
		require.NoError(t, err)

		return chainCodeExchangeForm(code)
	}

	t.Run("DPoP", func(t *testing.T) {
		provider, store, config := newDPoPChainProviderWithConfig(t)
		config.DPoPEnforce = true

		t.Run("ShouldRejectACodeExchangeWithNoProof", func(t *testing.T) {
			_, err := chainTokenRequest(t, provider, newExchange(t, provider), "")

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The request requires a DPoP proof but none was provided.")
		})

		t.Run("ShouldAcceptACodeExchangeWithAProofAndBindTheToken", func(t *testing.T) {
			key := newPARProofKey(t)

			response, err := chainTokenRequest(t, provider, newExchange(t, provider),
				signPARProof(t, key, "enforce-tok-1", rtTokenEndpoint, nil))
			require.NoError(t, err)

			assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType())

			bound, present := confirmationJKT(t, mustIntrospect(t, provider, response.GetAccessToken()))

			require.True(t, present)
			assert.Equal(t, thumbprintOf(t, key), bound)

			refresh, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)

			_, err = chainTokenRequest(t, provider, chainRefreshForm(refresh), "")

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The request requires a DPoP proof but none was provided.")
		})

		t.Run("ShouldRejectClientCredentialsWithNoProof", func(t *testing.T) {
			_, err := chainTokenRequest(t, provider, chainClientCredentialsForm(t, store), "")

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The request requires a DPoP proof but none was provided.")
		})
	})

	t.Run("MTLS", func(t *testing.T) {
		provider, store, config := newDPoPChainProviderWithConfig(t)
		config.MTLSEnforce = true

		t.Run("ShouldRejectACodeExchangeWithNoCertificate", func(t *testing.T) {
			_, err := chainTokenRequestWithCert(t, provider, newExchange(t, provider), "", nil)

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The request requires a mutual-TLS client certificate but none was presented.")
		})

		t.Run("ShouldAcceptACodeExchangeWithACertificateAndBindTheToken", func(t *testing.T) {
			response, err := chainTokenRequestWithCert(t, provider, newExchange(t, provider), "", cert)
			require.NoError(t, err)

			assert.Equal(t, oauth2.BearerAccessToken, response.GetTokenType())

			requireCertBound(t, provider, response.GetAccessToken(), cert)

			refresh, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)

			_, err = chainTokenRequestWithCert(t, provider, chainRefreshForm(refresh), "", nil)

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The request requires a mutual-TLS client certificate but none was presented.")
		})

		t.Run("ShouldRejectClientCredentialsWithNoCertificate", func(t *testing.T) {
			_, err := chainTokenRequestWithCert(t, provider, chainClientCredentialsForm(t, store), "", nil)

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The request requires a mutual-TLS client certificate but none was presented.")
		})
	})

	t.Run("NeitherEnforced", func(t *testing.T) {
		provider, store, _ := newDPoPChainProviderWithConfig(t)

		response, err := chainTokenRequest(t, provider, newExchange(t, provider), "")
		require.NoError(t, err)

		assert.Equal(t, oauth2.BearerAccessToken, response.GetTokenType())
		assert.Nil(t, mustIntrospect(t, provider, response.GetAccessToken())["cnf"])

		_, err = chainTokenRequest(t, provider, chainClientCredentialsForm(t, store), "")
		require.NoError(t, err)
	})
}

func TestRefreshRequiresTheMTLSBindingTheGrantCarries(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})
	other := gen.MustCertificate(gen.CertificateOptions{SerialNumber: 2})

	provider, store, config := newDPoPChainProviderWithConfig(t)

	client := store.Clients[chainClientID].(*oauth2.DefaultClient)
	client.TLSClientCertificateBoundAccessTokens = true

	requestURI, _ := chainPushedRequestURI(t, provider, chainPARForm())

	code, _, err := chainAuthorizeCode(t, provider, requestURI, nil)
	require.NoError(t, err)

	response, err := chainTokenRequestWithCert(t, provider, chainCodeExchangeForm(code), "", cert)
	require.NoError(t, err)

	requireCertBound(t, provider, response.GetAccessToken(), cert)

	refresh, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
	require.NotEmpty(t, refresh)

	client.TLSClientCertificateBoundAccessTokens = false

	t.Run("ShouldRejectTheRefreshWithNoCertificate", func(t *testing.T) {
		_, err := chainTokenRequestWithCert(t, provider, chainRefreshForm(refresh), "", nil)

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The request requires a mutual-TLS client certificate but none was presented.")
	})

	t.Run("ShouldRejectTheRefreshWithAnotherCertificate", func(t *testing.T) {
		_, err := chainTokenRequestWithCert(t, provider, chainRefreshForm(refresh), "", other)

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The mutual-TLS client certificate does not match the certificate the grant is bound to.")
	})

	t.Run("ShouldAcceptTheBoundCertificateAndStayBound", func(t *testing.T) {
		response, err := chainTokenRequestWithCert(t, provider, chainRefreshForm(refresh), "", cert)
		require.NoError(t, err)

		requireCertBound(t, provider, response.GetAccessToken(), cert)

		rotated, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
		require.NotEmpty(t, rotated)

		_, err = chainTokenRequestWithCert(t, provider, chainRefreshForm(rotated), "", nil)

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The request requires a mutual-TLS client certificate but none was presented.")
	})

	t.Run("ShouldGoDormantOnceMTLSIsDisabled", func(t *testing.T) {
		client.TLSClientCertificateBoundAccessTokens = true
		defer func() { client.TLSClientCertificateBoundAccessTokens = false }()

		requestURI, _ := chainPushedRequestURI(t, provider, chainPARForm())

		code, _, err := chainAuthorizeCode(t, provider, requestURI, nil)
		require.NoError(t, err)

		response, err := chainTokenRequestWithCert(t, provider, chainCodeExchangeForm(code), "", cert)
		require.NoError(t, err)

		dormant, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
		require.NotEmpty(t, dormant)

		config.MTLSEnabled = false
		defer func() { config.MTLSEnabled = true }()

		_, err = chainTokenRequestWithCert(t, provider, chainRefreshForm(dormant), "", nil)

		assert.NoError(t, err)
	})
}

func TestBindingIsRequiredAtIntrospectionWhenEnforced(t *testing.T) {
	t.Run("DPoP", func(t *testing.T) {
		provider, _, config := newDPoPChainProviderWithConfig(t)

		key := newPARProofKey(t)

		bound, _ := chainAccessToken(t, provider, key, "enforce-bound")
		unbound, _ := chainAccessToken(t, provider, nil, "enforce-unbound")
		subject, _ := chainAccessToken(t, provider, nil, "enforce-subject")

		config.DPoPEnforce = true

		t.Run("ShouldRejectAnUnboundCredential", func(t *testing.T) {
			_, err := chainIntrospectAs(t, provider, subject, "Bearer", unbound, "")

			require.Error(t, err)

			assert.Equal(t, http.StatusUnauthorized, oauth2.ErrorToRFC6749Error(err).CodeField)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a DPoP key. DPoP is enforced, so every credential presented to authenticate a request must be bound to a DPoP key, but this credential records no binding.")
		})

		t.Run("ShouldAcceptABoundCredentialWithAValidProof", func(t *testing.T) {
			body, err := chainIntrospectAs(t, provider, subject, "DPoP", bound,
				chainProofWithATH(t, key, "enforce-1", chainIntrospectEndpoint, bound))

			require.NoError(t, err)
			assert.Equal(t, true, body["active"])
		})

		t.Run("ShouldStillIntrospectAnUnboundSubjectToken", func(t *testing.T) {
			body, err := chainIntrospectAs(t, provider, subject, "DPoP", bound,
				chainProofWithATH(t, key, "enforce-2", chainIntrospectEndpoint, bound))

			require.NoError(t, err)
			assert.Equal(t, true, body["active"])
			assert.Nil(t, body["cnf"])
		})

		t.Run("ShouldNotAffectClientCredentials", func(t *testing.T) {
			body, status := chainIntrospect(t, provider, subject)

			require.Equal(t, http.StatusOK, status)
			assert.Equal(t, true, body["active"])
		})
	})

	t.Run("MTLS", func(t *testing.T) {
		cert := gen.MustCertificate(gen.CertificateOptions{})

		provider, store, config := newDPoPChainProviderWithConfig(t)

		unbound, _ := chainAccessToken(t, provider, nil, "enforce-cert-unbound")
		subject, _ := chainAccessToken(t, provider, nil, "enforce-cert-subject")

		store.Clients[chainClientID].(*oauth2.DefaultClient).TLSClientCertificateBoundAccessTokens = true

		bound := chainCertBoundToken(t, provider, cert, "enforce-cert-bound")

		config.MTLSEnforce = true

		t.Run("ShouldRejectAnUnboundCredential", func(t *testing.T) {
			_, err := chainIntrospectAs(t, provider, subject, "Bearer", unbound, "")

			require.Error(t, err)

			assert.Equal(t, http.StatusUnauthorized, oauth2.ErrorToRFC6749Error(err).CodeField)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a client certificate. Mutual-TLS client certificate bound access tokens are enforced, so every credential presented to authenticate a request must be bound to a client certificate, but this credential records no binding.")
		})

		t.Run("ShouldRejectAnUnboundCredentialEvenWithACertificate", func(t *testing.T) {
			_, err := chainIntrospectAsWithCert(t, provider, subject, "Bearer", unbound, "", cert)

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a client certificate. Mutual-TLS client certificate bound access tokens are enforced, so every credential presented to authenticate a request must be bound to a client certificate, but this credential records no binding.")
		})

		t.Run("ShouldAcceptABoundCredentialWithTheCertificate", func(t *testing.T) {
			body, err := chainIntrospectAsWithCert(t, provider, subject, "Bearer", bound, "", cert)

			require.NoError(t, err)
			assert.Equal(t, true, body["active"])
		})

		t.Run("ShouldStillIntrospectAnUnboundSubjectToken", func(t *testing.T) {
			body, err := chainIntrospectAsWithCert(t, provider, subject, "Bearer", bound, "", cert)

			require.NoError(t, err)
			assert.Equal(t, true, body["active"])
			assert.Nil(t, body["cnf"])
		})
	})
}

func TestDPoPPARStepEnforcement(t *testing.T) {
	t.Run("ShouldRecordTheProofThumbprintAsDPoPJKT", func(t *testing.T) {
		provider, _ := newDPoPChainProvider(t)

		key := newPARProofKey(t)

		_, requester := chainPushedRequestURI(t, provider, chainPARForm(), signPARProof(t, key, "chain-par-1", parEndpoint, nil))

		assert.Equal(t, thumbprintOf(t, key), requester.GetRequestForm().Get(consts.FormParameterDPoPJKT))
	})

	t.Run("ShouldAcceptABareDPoPJKTWithoutAProof", func(t *testing.T) {
		provider, _ := newDPoPChainProvider(t)

		jkt := thumbprintOf(t, newPARProofKey(t))

		form := chainPARForm()
		form.Set(consts.FormParameterDPoPJKT, jkt)

		_, requester := chainPushedRequestURI(t, provider, form)

		assert.Equal(t, jkt, requester.GetRequestForm().Get(consts.FormParameterDPoPJKT))
	})

	t.Run("ShouldRejectADPoPJKTThatDisagreesWithTheProof", func(t *testing.T) {
		provider, _ := newDPoPChainProvider(t)

		form := chainPARForm()
		form.Set(consts.FormParameterDPoPJKT, thumbprintOf(t, newPARProofKey(t)))

		_, err := provider.NewPushedAuthorizeRequest(context.Background(),
			chainPARRequest(form, signPARProof(t, newPARProofKey(t), "chain-par-2", parEndpoint, nil)))

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'dpop_jkt' parameter does not match the thumbprint of the public key in the DPoP proof.")
	})

	t.Run("ShouldRejectAMalformedDPoPJKT", func(t *testing.T) {
		provider, _ := newDPoPChainProvider(t)

		form := chainPARForm()
		form.Set(consts.FormParameterDPoPJKT, "not-a-thumbprint")

		_, err := provider.NewPushedAuthorizeRequest(context.Background(), chainPARRequest(form))

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'dpop_jkt' parameter must be the base64url encoded SHA-256 JWK Thumbprint of the DPoP proof-of-possession public key, which is 43 characters long.")
	})
}

func TestDPoPAuthorizeStepEnforcement(t *testing.T) {
	t.Run("ShouldCarryThePARBindingOntoTheAuthorizationCode", func(t *testing.T) {
		provider, store := newDPoPChainProvider(t)

		key := newPARProofKey(t)

		requestURI, _ := chainPushedRequestURI(t, provider, chainPARForm(), signPARProof(t, key, "chain-auth-1", parEndpoint, nil))

		code, session, err := chainAuthorizeCode(t, provider, requestURI, nil)
		require.NoError(t, err)
		require.NotEmpty(t, code)

		assert.Equal(t, thumbprintOf(t, key), session.GetDPoPJWKThumbprint())

		require.Len(t, store.AuthorizeCodes, 1)

		for _, stored := range store.AuthorizeCodes {
			bound, ok := stored.Requester.GetSession().(oauth2.DPoPBoundSession)
			require.True(t, ok)

			assert.Equal(t, thumbprintOf(t, key), bound.GetDPoPJWKThumbprint(),
				"the persisted authorization code was not bound to the PAR key")
		}
	})

	t.Run("ShouldNotLetTheAuthorizationRequestOverrideThePARBinding", func(t *testing.T) {
		provider, _ := newDPoPChainProvider(t)

		key := newPARProofKey(t)
		attacker := newPARProofKey(t)

		requestURI, _ := chainPushedRequestURI(t, provider, chainPARForm(), signPARProof(t, key, "chain-auth-2", parEndpoint, nil))

		_, session, err := chainAuthorizeCode(t, provider, requestURI, url.Values{
			consts.FormParameterDPoPJKT: []string{thumbprintOf(t, attacker)},
		})
		require.NoError(t, err)

		assert.Equal(t, thumbprintOf(t, key), session.GetDPoPJWKThumbprint(),
			"the authorization request replaced the key the pushed request committed to")
		assert.NotEqual(t, thumbprintOf(t, attacker), session.GetDPoPJWKThumbprint())
	})

	t.Run("ShouldRejectAMalformedDPoPJKTAtTheAuthorizationEndpoint", func(t *testing.T) {
		provider, _ := newDPoPChainProvider(t)

		form := url.Values{
			consts.FormParameterClientID:     []string{chainClientID},
			consts.FormParameterResponseType: []string{consts.ResponseTypeAuthorizationCodeFlow},
			consts.FormParameterRedirectURI:  []string{parRedirectURI},
			consts.FormParameterScope:        []string{consts.ScopeOffline},
			consts.FormParameterState:        []string{"abcdefghijklmnop"},
			consts.FormParameterDPoPJKT:      []string{"not-a-thumbprint"},
		}

		r := httptest.NewRequest(http.MethodGet, "https://as.example.com/authorize?"+form.Encode(), nil)

		ctx := context.Background()

		requester, err := provider.NewAuthorizeRequest(ctx, r)
		require.NoError(t, err)

		requester.GrantScope(consts.ScopeOffline)
		requester.GrantAudience(chainIntrospectEndpoint)

		_, err = provider.NewAuthorizeResponse(ctx, requester, &oauth2.DefaultSession{Subject: "peter"})
		require.Error(t, err)

		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'dpop_jkt' parameter must be the base64url encoded SHA-256 JWK Thumbprint of the DPoP proof-of-possession public key, which is 43 characters long.")
	})
}

func TestDPoPCodeExchangeStepEnforcement(t *testing.T) {
	t.Run("ShouldRejectTheCodeExchangeWithoutAProof", func(t *testing.T) {
		provider, _ := newDPoPChainProvider(t)

		key := newPARProofKey(t)

		_, err := chainTokenRequest(t, provider, chainCodeExchangeForm(chainBoundCode(t, provider, key, "chain-code-1")), "")

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The request requires a DPoP proof but none was provided.")
	})

	t.Run("ShouldRejectTheCodeExchangeWithAnotherKey", func(t *testing.T) {
		provider, _ := newDPoPChainProvider(t)

		key := newPARProofKey(t)

		_, err := chainTokenRequest(t, provider, chainCodeExchangeForm(chainBoundCode(t, provider, key, "chain-code-2")),
			signPARProof(t, newPARProofKey(t), "chain-code-2-other", rtTokenEndpoint, nil))

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The DPoP proof key does not match the key the grant is bound to.")
	})

	t.Run("ShouldAcceptTheCodeExchangeWithTheBoundKey", func(t *testing.T) {
		provider, _ := newDPoPChainProvider(t)

		key := newPARProofKey(t)

		response, err := chainTokenRequest(t, provider, chainCodeExchangeForm(chainBoundCode(t, provider, key, "chain-code-3")),
			signPARProof(t, key, "chain-code-3-ok", rtTokenEndpoint, nil))
		require.NoError(t, err)

		assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType(),
			"the access token issued from a bound code was not of type DPoP")

		refreshToken, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
		assert.NotEmpty(t, refreshToken)
	})
}

func TestRefreshValidatesTheDPoPProofItself(t *testing.T) {
	provider, _ := newDPoPChainProvider(t)

	key := newPARProofKey(t)

	exchangeProof := signPARProof(t, key, "refresh-proof-exchange", rtTokenEndpoint, nil)

	exchanged, err := chainTokenRequest(t, provider, chainCodeExchangeForm(chainBoundCode(t, provider, key, "refresh-proof-code")), exchangeProof)
	require.NoError(t, err)

	refresh, _ := exchanged.ToMap()[consts.AccessResponseRefreshToken].(string)
	require.NotEmpty(t, refresh)

	testCases := []struct {
		name     string
		proof    func(t *testing.T) string
		expected string
		pattern  string
	}{
		{
			name:     "ShouldRejectTheProofAlreadySpentAtTheCodeExchange",
			proof:    func(t *testing.T) string { return exchangeProof },
			expected: "The DPoP proof is missing or invalid. The DPoP proof has already been used.",
		},
		{
			name:     "ShouldRejectAProofMintedForAnotherEndpoint",
			proof:    func(t *testing.T) string { return signPARProof(t, key, "refresh-proof-htu", parEndpoint, nil) },
			expected: "The DPoP proof is missing or invalid. The DPoP proof 'htu' claim 'https://as.example.com/par' does not match the request URI 'https://as.example.com/token'.",
		},
		{
			name: "ShouldRejectAProofForAnotherMethod",
			proof: func(t *testing.T) string {
				return signPARProof(t, key, "refresh-proof-htm", rtTokenEndpoint, map[string]any{consts.ClaimHTTPMethod: http.MethodGet})
			},
			expected: "The DPoP proof is missing or invalid. The DPoP proof 'htm' claim 'GET' does not match the request method 'POST'.",
		},
		{
			name: "ShouldRejectAProofOutsideTheIssuedAtWindow",
			proof: func(t *testing.T) string {
				return signPARProof(t, key, "refresh-proof-iat", rtTokenEndpoint, map[string]any{consts.ClaimIssuedAt: time.Now().Add(-time.Hour).Unix()})
			},
			pattern: `^The DPoP proof is missing or invalid\. The DPoP proof 'iat' claim is outside of the acceptable time window\. The proof was issued at '[^']+' and expired at '[^']+', being its lifespan of 10s plus the permitted clock skew of 10s\.$`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := chainTokenRequest(t, provider, chainRefreshForm(refresh), tc.proof(t))

			require.Error(t, err)

			if tc.pattern != "" {
				assert.Regexp(t, tc.pattern, oauth2.ErrorToDebugRFC6749Error(err).Error())

				return
			}

			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
		})
	}

	t.Run("ShouldAcceptAFreshProofAndRejectItsReuseOnTheRotatedToken", func(t *testing.T) {
		fresh := signPARProof(t, key, "refresh-proof-fresh", rtTokenEndpoint, nil)

		rotatedResponse, err := chainTokenRequest(t, provider, chainRefreshForm(refresh), fresh)
		require.NoError(t, err)

		assert.Equal(t, oauth2.DPoPAccessToken, rotatedResponse.GetTokenType())

		rotated, _ := rotatedResponse.ToMap()[consts.AccessResponseRefreshToken].(string)
		require.NotEmpty(t, rotated)

		_, err = chainTokenRequest(t, provider, chainRefreshForm(rotated), fresh)
		require.Error(t, err)

		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The DPoP proof has already been used.")
	})
}

func TestDPoPRefreshStepEnforcement(t *testing.T) {
	provider, _ := newDPoPChainProvider(t)

	key := newPARProofKey(t)

	response, err := chainTokenRequest(t, provider, chainCodeExchangeForm(chainBoundCode(t, provider, key, "chain-refresh-1")),
		signPARProof(t, key, "chain-refresh-1-ok", rtTokenEndpoint, nil))
	require.NoError(t, err)

	refreshToken, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
	require.NotEmpty(t, refreshToken)

	t.Run("ShouldRejectTheRefreshWithoutAProof", func(t *testing.T) {
		_, err := chainTokenRequest(t, provider, chainRefreshForm(refreshToken), "")

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The request requires a DPoP proof but none was provided.")
	})

	t.Run("ShouldRejectTheRefreshWithAnotherKey", func(t *testing.T) {
		_, err := chainTokenRequest(t, provider, chainRefreshForm(refreshToken),
			signPARProof(t, newPARProofKey(t), "chain-refresh-other", rtTokenEndpoint, nil))

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The DPoP proof key does not match the key the grant is bound to.")
	})

	t.Run("ShouldAcceptTheRefreshWithTheBoundKeyAndStayBound", func(t *testing.T) {
		response, err := chainTokenRequest(t, provider, chainRefreshForm(refreshToken),
			signPARProof(t, key, "chain-refresh-2", rtTokenEndpoint, nil))
		require.NoError(t, err)

		assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType())

		rotated, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
		require.NotEmpty(t, rotated)

		_, err = chainTokenRequest(t, provider, chainRefreshForm(rotated), "")

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The request requires a DPoP proof but none was provided.")

		_, err = chainTokenRequest(t, provider, chainRefreshForm(rotated),
			signPARProof(t, newPARProofKey(t), "chain-refresh-rotated-other", rtTokenEndpoint, nil))

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The DPoP proof key does not match the key the grant is bound to.")

		response, err = chainTokenRequest(t, provider, chainRefreshForm(rotated),
			signPARProof(t, key, "chain-refresh-3", rtTokenEndpoint, nil))
		require.NoError(t, err)

		assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType())
	})
}

func TestIntrospectionClientAuthCanBeDisabled(t *testing.T) {
	provider, _, config := newDPoPChainProviderWithConfig(t)

	caller, _ := chainAccessToken(t, provider, nil, "clientauth-caller")
	subject, _ := chainAccessToken(t, provider, nil, "clientauth-subject")

	t.Run("ShouldAcceptClientCredentialsByDefault", func(t *testing.T) {
		body, status := chainIntrospect(t, provider, subject)

		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["active"])
	})

	config.IntrospectionEndpointClientAuthDisabled = true

	t.Run("ShouldRejectClientCredentialsOnceDisabled", func(t *testing.T) {
		body, status, header := chainIntrospectRecorded(t, provider, subject, nil)

		require.Equal(t, http.StatusUnauthorized, status)
		assert.Equal(t, "invalid_token", body["error"])
		assert.NotContains(t, body, "active")

		challenge := header.Get(consts.HeaderWWWAuthenticate)
		require.NotEmpty(t, challenge)
		assert.Contains(t, challenge, "Bearer")
		assert.Contains(t, challenge, "DPoP")
	})

	t.Run("ShouldStillAcceptABearerCredential", func(t *testing.T) {
		body, err := chainIntrospectAs(t, provider, subject, "Bearer", caller, "")

		require.NoError(t, err)
		assert.Equal(t, true, body["active"])
	})

	t.Run("ShouldStillRequireTheCredentialBeAuthorized", func(t *testing.T) {
		config.AllowedIntrospectionScopes = []string{"urn:not:granted"}
		defer func() { config.AllowedIntrospectionScopes = []string{consts.ScopeOffline} }()

		_, err := chainIntrospectAs(t, provider, subject, "Bearer", caller, "")

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request requires higher privileges than provided by the Access Token. The credential used to authenticate the request is not granted any of the scopes 'urn:not:granted', at least one of which is required.")
	})
}

func chainIntrospectRecorded(t *testing.T, provider oauth2.Provider, token string, opt func(r *http.Request)) (body map[string]any, status int, header http.Header) {
	t.Helper()

	form := url.Values{
		"token":                          []string{token},
		consts.FormParameterClientID:     []string{chainClientID},
		consts.FormParameterClientSecret: []string{chainSecret},
	}

	r := httptest.NewRequest(http.MethodPost, chainIntrospectEndpoint, strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	if opt != nil {
		opt(r)
	}

	ctx := context.Background()

	rw := httptest.NewRecorder()

	responder, err := provider.NewIntrospectionRequest(ctx, r, &oauth2.DefaultSession{})
	if err != nil {
		provider.WriteIntrospectionError(ctx, rw, err)
	} else {
		provider.WriteIntrospectionResponse(ctx, rw, responder)
	}

	body = map[string]any{}
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))

	return body, rw.Code, rw.Header()
}

func chainIntrospect(t *testing.T, provider oauth2.Provider, token string) (body map[string]any, status int) {
	t.Helper()

	form := url.Values{
		"token":                          []string{token},
		consts.FormParameterClientID:     []string{chainClientID},
		consts.FormParameterClientSecret: []string{chainSecret},
	}

	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	ctx := context.Background()

	rw := httptest.NewRecorder()

	responder, err := provider.NewIntrospectionRequest(ctx, r, &oauth2.DefaultSession{})
	if err != nil {
		provider.WriteIntrospectionError(ctx, rw, err)
	} else {
		provider.WriteIntrospectionResponse(ctx, rw, responder)
	}

	body = map[string]any{}
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))

	return body, rw.Code
}

func confirmationJKT(t *testing.T, body map[string]any) (jkt string, present bool) {
	t.Helper()

	cnf, ok := body["cnf"].(map[string]any)
	if !ok {
		return "", false
	}

	jkt, _ = cnf["jkt"].(string)

	return jkt, true
}

func chainCertBoundToken(t *testing.T, provider oauth2.Provider, cert *x509.Certificate, jti string) (token string) {
	t.Helper()

	requestURI, _ := chainPushedRequestURI(t, provider, chainPARForm())

	code, _, err := chainAuthorizeCode(t, provider, requestURI, nil)
	require.NoError(t, err)

	response, err := chainTokenRequestWithCert(t, provider, chainCodeExchangeForm(code), "", cert)
	require.NoError(t, err)

	token = response.GetAccessToken()

	requireCertBound(t, provider, token, cert)

	return token
}

func chainBothBoundToken(t *testing.T, provider oauth2.Provider, key *jose.JSONWebKey, cert *x509.Certificate, jti string) (token string) {
	t.Helper()

	response, err := chainTokenRequestWithCert(t, provider, chainCodeExchangeForm(chainBoundCode(t, provider, key, jti)),
		signPARProof(t, key, jti+"-tok", rtTokenEndpoint, nil), cert)
	require.NoError(t, err)

	token = response.GetAccessToken()

	requireCertBound(t, provider, token, cert)

	bound, _ := confirmationJKT(t, mustIntrospect(t, provider, token))
	require.Equal(t, thumbprintOf(t, key), bound, "the fixture was meant to be DPoP bound as well")

	return token
}

func requireCertBound(t *testing.T, provider oauth2.Provider, token string, cert *x509.Certificate) {
	t.Helper()

	cnf, ok := mustIntrospect(t, provider, token)["cnf"].(map[string]any)
	require.True(t, ok, "the fixture issued a token with no confirmation claim")

	assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(cert), cnf["x5t#S256"],
		"the token the fixture issued is not bound to the certificate it presented")
}

func mustIntrospect(t *testing.T, provider oauth2.Provider, token string) map[string]any {
	t.Helper()

	body, status := chainIntrospect(t, provider, token)
	require.Equal(t, http.StatusOK, status)

	return body
}

func chainProofWithATH(t *testing.T, key *jose.JSONWebKey, jti, url, token string) string {
	t.Helper()

	sum := sha256.Sum256([]byte(token))

	return signPARProof(t, key, jti, url, map[string]any{"ath": base64.RawURLEncoding.EncodeToString(sum[:])})
}

func chainIntrospectAs(t *testing.T, provider oauth2.Provider, subject, scheme, caller, proof string) (body map[string]any, err error) {
	t.Helper()

	return chainIntrospectAsWithCert(t, provider, subject, scheme, caller, proof, nil)
}

func chainIntrospectAsWithCert(t *testing.T, provider oauth2.Provider, subject, scheme, caller, proof string, cert *x509.Certificate, opts ...func(r *http.Request)) (body map[string]any, err error) {
	t.Helper()

	form := url.Values{"token": []string{subject}}

	r := httptest.NewRequest(http.MethodPost, chainIntrospectEndpoint, strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	r.Header.Set(consts.HeaderAuthorization, scheme+" "+caller)

	if proof != "" {
		r.Header.Set(consts.HeaderDPoP, proof)
	}

	if cert != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}

	for _, opt := range opts {
		opt(r)
	}

	ctx := context.Background()

	rw := httptest.NewRecorder()

	responder, err := provider.NewIntrospectionRequest(ctx, r, &oauth2.DefaultSession{})
	if err != nil {
		provider.WriteIntrospectionError(ctx, rw, err)
	} else {
		provider.WriteIntrospectionResponse(ctx, rw, responder)
	}

	body = map[string]any{}
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))

	return body, err
}

func chainAccessToken(t *testing.T, provider oauth2.Provider, key *jose.JSONWebKey, jti string) (token, refresh string) {
	t.Helper()

	var (
		response oauth2.AccessResponder
		err      error
	)

	if key != nil {
		response, err = chainTokenRequest(t, provider, chainCodeExchangeForm(chainBoundCode(t, provider, key, jti)),
			signPARProof(t, key, jti+"-tok", rtTokenEndpoint, nil))
	} else {
		requestURI, _ := chainPushedRequestURI(t, provider, chainPARForm())

		code, _, cerr := chainAuthorizeCode(t, provider, requestURI, nil)
		require.NoError(t, cerr)

		response, err = chainTokenRequest(t, provider, chainCodeExchangeForm(code), "")
	}

	require.NoError(t, err)

	refresh, _ = response.ToMap()[consts.AccessResponseRefreshToken].(string)

	return response.GetAccessToken(), refresh
}

func chainClientCredentialsForm(t *testing.T, store *storage.MemoryStore) url.Values {
	t.Helper()

	client := store.Clients[chainClientID].(*oauth2.DefaultClient)

	if !oauth2.Arguments(client.GrantTypes).Has(consts.GrantTypeClientCredentials) {
		client.GrantTypes = append(client.GrantTypes, consts.GrantTypeClientCredentials)
	}

	return url.Values{
		consts.FormParameterGrantType: []string{consts.GrantTypeClientCredentials},
		consts.FormParameterScope:     []string{consts.ScopeOffline},
	}
}

func newDPoPChainProvider(t *testing.T) (provider oauth2.Provider, store *storage.MemoryStore) {
	t.Helper()

	provider, store, _ = newDPoPChainProviderWithConfig(t)

	return provider, store
}

func newDPoPChainProviderWithConfig(t *testing.T) (provider oauth2.Provider, store *storage.MemoryStore, config *oauth2.Config) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	store = storage.NewMemoryStore()

	config = &oauth2.Config{
		DPoPEnabled:                           true,
		MTLSEnabled:                           true,
		GlobalSecret:                          []byte("some-cool-secret-that-is-32bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		AllowedIntrospectionScopes:            []string{consts.ScopeOffline},
	}

	provider = ComposeAllEnabled(config, store, key)

	store.Clients[chainClientID] = &oauth2.DefaultClient{
		ID:            chainClientID,
		ClientSecret:  oauth2.NewPlainTextClientSecret(chainSecret),
		RedirectURIs:  []string{parRedirectURI},
		ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
		GrantTypes:    []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		Scopes:        []string{consts.ScopeOffline},
		Audience:      []string{chainIntrospectEndpoint},
	}

	return provider, store, config
}

func newDPoPChainProviderCertBound(t *testing.T) (provider oauth2.Provider, store *storage.MemoryStore, config *oauth2.Config) {
	t.Helper()

	provider, store, config = newDPoPChainProviderWithConfig(t)

	store.Clients[chainClientID].(*oauth2.DefaultClient).TLSClientCertificateBoundAccessTokens = true

	return provider, store, config
}

func chainPARForm() url.Values {
	return url.Values{
		consts.FormParameterResponseType: []string{consts.ResponseTypeAuthorizationCodeFlow},
		consts.FormParameterRedirectURI:  []string{parRedirectURI},
		consts.FormParameterScope:        []string{consts.ScopeOffline},
		consts.FormParameterState:        []string{"abcdefghijklmnop"},
	}
}

func chainPARRequest(form url.Values, proofs ...string) *http.Request {
	form.Set(consts.FormParameterClientID, chainClientID)
	form.Set(consts.FormParameterClientSecret, chainSecret)

	r := httptest.NewRequest(http.MethodPost, parEndpoint, strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	for _, proof := range proofs {
		r.Header.Add(consts.HeaderDPoP, proof)
	}

	return r
}

func chainPushedRequestURI(t *testing.T, provider oauth2.Provider, form url.Values, proofs ...string) (requestURI string, requester oauth2.AuthorizeRequester) {
	t.Helper()

	ctx := context.Background()

	requester, err := provider.NewPushedAuthorizeRequest(ctx, chainPARRequest(form, proofs...))
	require.NoError(t, err)

	responder, err := provider.NewPushedAuthorizeResponse(ctx, requester, &oauth2.DefaultSession{Subject: "peter"})
	require.NoError(t, err)

	requestURI = responder.GetRequestURI()
	require.NotEmpty(t, requestURI)

	return requestURI, requester
}

func chainAuthorizeCode(t *testing.T, provider oauth2.Provider, requestURI string, extra url.Values) (code string, session *oauth2.DefaultSession, err error) {
	t.Helper()

	ctx := context.Background()

	form := url.Values{
		consts.FormParameterClientID:   []string{chainClientID},
		consts.FormParameterRequestURI: []string{requestURI},
	}

	maps.Copy(form, extra)

	r := httptest.NewRequest(http.MethodGet, "https://as.example.com/authorize?"+form.Encode(), nil)

	requester, err := provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		return "", nil, err
	}

	requester.GrantScope(consts.ScopeOffline)
	requester.GrantAudience(chainIntrospectEndpoint)

	session = &oauth2.DefaultSession{Subject: "peter"}

	responder, err := provider.NewAuthorizeResponse(ctx, requester, session)
	if err != nil {
		return "", nil, err
	}

	return responder.GetParameters().Get(consts.FormParameterAuthorizationCode), session, nil
}

func chainTokenRequest(t *testing.T, provider oauth2.Provider, form url.Values, proof string) (responder oauth2.AccessResponder, err error) {
	t.Helper()

	return chainTokenRequestWithCert(t, provider, form, proof, nil)
}

func chainTokenRequestWithCert(t *testing.T, provider oauth2.Provider, form url.Values, proof string, cert *x509.Certificate) (responder oauth2.AccessResponder, err error) {
	t.Helper()

	form.Set(consts.FormParameterClientID, chainClientID)
	form.Set(consts.FormParameterClientSecret, chainSecret)

	r := httptest.NewRequest(http.MethodPost, rtTokenEndpoint, strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	if proof != "" {
		r.Header.Set(consts.HeaderDPoP, proof)
	}

	if cert != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}

	ctx := context.Background()

	requester, err := provider.NewAccessRequest(ctx, r, &oauth2.DefaultSession{})
	if err != nil {
		return nil, err
	}

	return provider.NewAccessResponse(ctx, requester)
}

func chainBoundCode(t *testing.T, provider oauth2.Provider, key *jose.JSONWebKey, jti string) (code string) {
	t.Helper()

	requestURI, _ := chainPushedRequestURI(t, provider, chainPARForm(), signPARProof(t, key, jti, parEndpoint, nil))

	code, session, err := chainAuthorizeCode(t, provider, requestURI, nil)
	require.NoError(t, err)
	require.NotEmpty(t, code)

	require.Equal(t, thumbprintOf(t, key), session.GetDPoPJWKThumbprint(),
		"the PAR binding did not reach the session the authorization code was issued from")

	return code
}

func chainCodeExchangeForm(code string) url.Values {
	return url.Values{
		consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
		consts.FormParameterAuthorizationCode: []string{code},
		consts.FormParameterRedirectURI:       []string{parRedirectURI},
	}
}

func chainRefreshForm(refreshToken string) url.Values {
	return url.Values{
		consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
		consts.FormParameterRefreshToken: []string{refreshToken},
	}
}

type proofOnlyChainDPoPStrategy struct{}

func (proofOnlyChainDPoPStrategy) ValidateDPoPProof(_ context.Context, _, _, _ string, _ bool) (parsed *oauth2.DPoPProof, err error) {
	return &oauth2.DPoPProof{}, nil
}

func (proofOnlyChainDPoPStrategy) NewDPoPNonce(_ context.Context) (nonce string, err error) {
	return "", nil
}

func (proofOnlyChainDPoPStrategy) ValidateDPoPNonce(_ context.Context, _ string) (err error) {
	return nil
}

const (
	chainClientID           = "dpop-chain-client"
	chainSecret             = "dpop-chain-client-secret"
	chainIntrospectEndpoint = "https://as.example.com/introspect"
)
