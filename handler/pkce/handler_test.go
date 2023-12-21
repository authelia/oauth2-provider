// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

type mockCodeStrategy struct {
	signature string
}

func (m *mockCodeStrategy) AuthorizeCodeSignature(ctx context.Context, token string) string {
	return m.signature
}

func (m *mockCodeStrategy) GenerateAuthorizeCode(ctx context.Context, requester oauth2.Requester) (token string, signature string, err error) {
	return "", "", nil
}

func (m *mockCodeStrategy) ValidateAuthorizeCode(ctx context.Context, requester oauth2.Requester, token string) (err error) {
	return nil
}

func TestPKCEHandleAuthorizeEndpointRequest(t *testing.T) {
	var config oauth2.Config
	h := &Handler{
		Storage:               storage.NewMemoryStore(),
		AuthorizeCodeStrategy: new(hoauth2.HMACSHAStrategy),
		Config:                &config,
	}
	w := oauth2.NewAuthorizeResponse()
	r := oauth2.NewAuthorizeRequest()
	c := &oauth2.DefaultClient{}
	r.Client = c

	w.AddParameter(consts.FormParameterAuthorizationCode, "foo")

	r.Form.Set(consts.FormParameterCodeChallenge, "challenge")
	r.Form.Set(consts.FormParameterCodeChallengeMethod, consts.PKCEChallengeMethodPlain)

	r.ResponseTypes = oauth2.Arguments{}
	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	r.ResponseTypes = oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow}
	require.Error(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	r.ResponseTypes = oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken}
	require.Error(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	c.Public = true
	config.EnablePKCEPlainChallengeMethod = true
	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	c.Public = false
	config.EnablePKCEPlainChallengeMethod = true
	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	config.EnablePKCEPlainChallengeMethod = false
	require.Error(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	r.Form.Set(consts.FormParameterCodeChallenge, "")
	r.Form.Set(consts.FormParameterCodeChallengeMethod, consts.PKCEChallengeMethodSHA256)

	config.EnforcePKCE = true
	require.Error(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	r.Form.Set(consts.FormParameterCodeChallenge, "challenge")
	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))
}

func TestPKCEHandlerValidate(t *testing.T) {
	s := storage.NewMemoryStore()
	ms := &mockCodeStrategy{}
	config := &oauth2.Config{}
	h := &Handler{Storage: s, AuthorizeCodeStrategy: ms, Config: config}
	pc := &oauth2.DefaultClient{Public: true}

	s256verifier := "KGCt4m8AmjUvIR5ArTByrmehjtbxn1A49YpTZhsH8N7fhDr7LQayn9xx6mck"
	hash := sha256.New()
	hash.Write([]byte(s256verifier))
	s256challenge := base64.RawURLEncoding.EncodeToString(hash.Sum([]byte{}))

	for k, tc := range []struct {
		d             string
		grant         string
		force         bool
		enablePlain   bool
		challenge     string
		method        string
		verifier      string
		code          string
		expectErr     error
		expectErrDesc string
		client        *oauth2.DefaultClient
	}{
		{
			d:             "fails because not auth code flow",
			grant:         "not_authorization_code",
			expectErr:     oauth2.ErrUnknownRequest,
			expectErrDesc: "The handler is not responsible for this request.",
		},
		{
			d:           "passes with private client",
			grant:       consts.GrantTypeAuthorizationCode,
			challenge:   "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			verifier:    "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			method:      consts.PKCEChallengeMethodPlain,
			client:      &oauth2.DefaultClient{Public: false},
			enablePlain: true,
			force:       true,
			code:        "valid-code-1",
		},
		{
			d:             "fails because invalid code",
			grant:         consts.GrantTypeAuthorizationCode,
			client:        pc,
			code:          "invalid-code-2",
			verifier:      "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			expectErr:     oauth2.ErrInvalidGrant,
			expectErrDesc: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. Unable to find initial PKCE data tied to this request. Could not find the requested resource(s).",
		},
		{
			d:      "passes because auth code flow but pkce is not forced and no challenge given",
			grant:  consts.GrantTypeAuthorizationCode,
			client: pc,
			code:   "valid-code-3",
		},
		{
			d:             "fails because auth code flow and pkce challenge given but plain is disabled",
			grant:         consts.GrantTypeAuthorizationCode,
			challenge:     "foo",
			client:        pc,
			code:          "valid-code-4",
			expectErr:     oauth2.ErrInvalidRequest,
			expectErrDesc: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must use code_challenge_method=S256, plain is not allowed. The server is configured in a way that enforces PKCE S256 as challenge method for clients.",
		},
		{
			d:           "passes",
			grant:       consts.GrantTypeAuthorizationCode,
			challenge:   "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			verifier:    "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			client:      pc,
			enablePlain: true,
			force:       true,
			code:        "valid-code-5",
		},
		{
			d:           "passes",
			grant:       consts.GrantTypeAuthorizationCode,
			challenge:   "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			verifier:    "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			method:      consts.PKCEChallengeMethodPlain,
			client:      pc,
			enablePlain: true,
			force:       true,
			code:        "valid-code-6",
		},
		{
			d:             "fails because challenge and verifier do not match",
			grant:         consts.GrantTypeAuthorizationCode,
			challenge:     "not-foo",
			verifier:      "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			method:        consts.PKCEChallengeMethodPlain,
			client:        pc,
			enablePlain:   true,
			code:          "valid-code-7",
			expectErr:     oauth2.ErrInvalidGrant,
			expectErrDesc: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code challenge did not match the code verifier.",
		},
		{
			d:             "fails because challenge and verifier do not match",
			grant:         consts.GrantTypeAuthorizationCode,
			challenge:     "not-foonot-foonot-foonot-foonot-foonot-foonot-foonot-foo",
			verifier:      "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			client:        pc,
			enablePlain:   true,
			code:          "valid-code-8",
			expectErr:     oauth2.ErrInvalidGrant,
			expectErrDesc: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code challenge did not match the code verifier.",
		},
		{
			d:             "fails because verifier is too short",
			grant:         consts.GrantTypeAuthorizationCode,
			challenge:     "foo",
			verifier:      "foo",
			method:        consts.PKCEChallengeMethodSHA256,
			client:        pc,
			force:         true,
			code:          "valid-code-9",
			expectErr:     oauth2.ErrInvalidGrant,
			expectErrDesc: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code verifier must be at least 43 characters.",
		},
		{
			d:             "fails because verifier is too long",
			grant:         consts.GrantTypeAuthorizationCode,
			challenge:     "foo",
			verifier:      "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			method:        consts.PKCEChallengeMethodSHA256,
			client:        pc,
			force:         true,
			code:          "valid-code-10",
			expectErr:     oauth2.ErrInvalidGrant,
			expectErrDesc: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code verifier can not be longer than 128 characters.",
		},
		{
			d:             "fails because verifier is malformed",
			grant:         consts.GrantTypeAuthorizationCode,
			challenge:     "foo",
			verifier:      `(!"/$%Z&$T()/)OUZI>$"&=/T(PUOI>"%/)TUOI&/(O/()RGTE>=/(%"/()="$/)(=()=/R/()=))`,
			method:        consts.PKCEChallengeMethodSHA256,
			client:        pc,
			force:         true,
			code:          "valid-code-11",
			expectErr:     oauth2.ErrInvalidGrant,
			expectErrDesc: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code verifier must only contain [a-Z], [0-9], '-', '.', '_', '~'.",
		},
		{
			d:             "fails because challenge and verifier do not match",
			grant:         consts.GrantTypeAuthorizationCode,
			challenge:     "Zm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9v",
			verifier:      "Zm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9v",
			method:        consts.PKCEChallengeMethodSHA256,
			client:        pc,
			force:         true,
			code:          "valid-code-12",
			expectErr:     oauth2.ErrInvalidGrant,
			expectErrDesc: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code challenge did not match the code verifier.",
		},
		{
			d:         "passes because challenge and verifier match",
			grant:     consts.GrantTypeAuthorizationCode,
			challenge: s256challenge,
			verifier:  s256verifier,
			method:    consts.PKCEChallengeMethodSHA256,
			client:    pc,
			force:     true,
			code:      "valid-code-13",
		},
		{
			d:      "passes when not forced because no challenge or verifier",
			grant:  consts.GrantTypeAuthorizationCode,
			client: pc,
			code:   "valid-code-14",
		},
		{
			d:             "fails when not forced because verifier provided when no challenge",
			grant:         consts.GrantTypeAuthorizationCode,
			client:        pc,
			code:          "valid-code-15",
			verifier:      "Zm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9v",
			expectErr:     oauth2.ErrInvalidGrant,
			expectErrDesc: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code verifier was provided but the code challenge was absent from the authorization request.",
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
			config.EnablePKCEPlainChallengeMethod = tc.enablePlain
			config.EnforcePKCE = tc.force
			ms.signature = tc.code
			ar := oauth2.NewAuthorizeRequest()

			if len(tc.challenge) != 0 {
				ar.Form.Set(consts.FormParameterCodeChallenge, tc.challenge)
			}

			if len(tc.method) != 0 {
				ar.Form.Set(consts.FormParameterCodeChallengeMethod, tc.method)
			}

			ar.Client = tc.client

			require.NoError(t, s.CreatePKCERequestSession(context.TODO(), fmt.Sprintf("valid-code-%d", k), ar))

			r := oauth2.NewAccessRequest(nil)
			r.Client = tc.client
			r.GrantTypes = oauth2.Arguments{tc.grant}

			if len(tc.verifier) != 0 {
				r.Form.Set(consts.FormParameterCodeVerifier, tc.verifier)
			}

			err := h.HandleTokenEndpointRequest(context.Background(), r)

			if tc.expectErr == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectErr.Error(), "%+v", err)

				if len(tc.expectErrDesc) != 0 {
					assert.EqualError(t, newtesterr(err), tc.expectErrDesc)
				}
			}
		})
	}
}

func TestPKCEHandleTokenEndpointRequest(t *testing.T) {
	for k, tc := range []struct {
		d           string
		force       bool
		forcePublic bool
		enablePlain bool
		challenge   string
		method      string
		expectErr   bool
		client      oauth2.Client
	}{
		{
			d: "should pass because pkce is not enforced",
		},
		{
			d:           "ShouldHandleNilClient",
			forcePublic: true,
			expectErr:   true,
		},
		{
			d:         "should fail because plain is not enabled and method is empty which defaults to plain",
			expectErr: true,
			force:     true,
		},
		{
			d:           "should fail because force is enabled and no challenge was given",
			force:       true,
			enablePlain: true,
			expectErr:   true,
			method:      consts.PKCEChallengeMethodSHA256,
		},
		{
			d:           "should fail because forcePublic is enabled, the client is public, and no challenge was given",
			forcePublic: true,
			client:      &oauth2.DefaultClient{Public: true},
			expectErr:   true,
			method:      consts.PKCEChallengeMethodSHA256,
		},
		{
			d:         "should fail because although force is enabled and a challenge was given, plain is disabled",
			force:     true,
			expectErr: true,
			method:    consts.PKCEChallengeMethodPlain,
			challenge: "challenge",
		},
		{
			d:         "should fail because although force is enabled and a challenge was given, plain is disabled and method is empty",
			force:     true,
			expectErr: true,
			challenge: "challenge",
		},
		{
			d:         "should fail because invalid challenge method",
			force:     true,
			expectErr: true,
			method:    "invalid",
			challenge: "challenge",
		},
		{
			d:         "should pass because force is enabled with challenge given and method is S256",
			force:     true,
			method:    consts.PKCEChallengeMethodSHA256,
			challenge: "challenge",
		},
		{
			d:           "should pass because forcePublic is enabled with challenge given and method is S256",
			forcePublic: true,
			client:      &oauth2.DefaultClient{Public: true},
			method:      consts.PKCEChallengeMethodSHA256,
			challenge:   "challenge",
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
			h := &Handler{
				Config: &oauth2.Config{
					EnforcePKCE:                    tc.force,
					EnforcePKCEForPublicClients:    tc.forcePublic,
					EnablePKCEPlainChallengeMethod: tc.enablePlain,
				},
			}

			if tc.expectErr {
				assert.Error(t, h.validate(context.Background(), tc.challenge, tc.method, tc.client))
			} else {
				assert.NoError(t, h.validate(context.Background(), tc.challenge, tc.method, tc.client))
			}
		})
	}
}

func newtesterr(err error) error {
	if err == nil {
		return nil
	}

	var e *oauth2.RFC6749Error
	if errors.As(err, &e) {
		return &testerr{e}
	}

	return err
}

type testerr struct {
	*oauth2.RFC6749Error
}

func (e *testerr) Error() string {
	return e.RFC6749Error.WithExposeDebug(true).GetDescription()
}
