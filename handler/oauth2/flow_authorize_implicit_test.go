// SPDX-FileCopyrightText: 2026 Authelia
//
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
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestAuthorizeImplicit_EndpointHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	areq := oauth2.NewAuthorizeRequest()
	areq.Session = new(oauth2.DefaultSession)
	h, store, chgen, aresp := makeAuthorizeImplicitGrantTypeHandler(ctrl)

	testCases := []struct {
		name     string
		setup    func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder)
		err      string
		errField string
	}{
		{
			name: "ShouldPassNotResponsibleForResponseType",
			setup: func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder) {
				areq.ResponseTypes = oauth2.Arguments{"a"}
			},
		},
		{
			name: "ShouldRejectClientWithoutImplicitGrant",
			setup: func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder) {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
				}
			},
			err:      "The client is not authorized to request a token using this method. The OAuth 2.0 Client is not allowed to use the authorization grant 'implicit'.",
			errField: oauth2.ErrUnauthorizedClient.ErrorField,
		},
		{
			name: "ShouldFailAccessTokenGenerationFailed",
			setup: func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder) {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
				}
				chgen.EXPECT().GenerateAccessToken(t.Context(), areq).Return("", "", errors.New(""))
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldFailScopeInvalid",
			setup: func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder) {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken}
				areq.RequestedScope = oauth2.Arguments{"scope"}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
				}
			},
			err: "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'scope'.",
		},
		{
			name: "ShouldFailAudienceInvalid",
			setup: func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder) {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken}
				areq.RequestedScope = oauth2.Arguments{"scope"}
				areq.RequestedAudience = oauth2.Arguments{"https://www.authelia.com/not-api"}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
					Scopes:        []string{"scope"},
					Audience:      []string{"https://www.authelia.com/api"},
				}
			},
			err: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://www.authelia.com/not-api' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name: "ShouldFailPersistenceFailed",
			setup: func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder) {
				areq.RequestedAudience = oauth2.Arguments{"https://www.authelia.com/api"}
				chgen.EXPECT().GenerateAccessToken(t.Context(), areq).AnyTimes().Return("access.ats", "ats", nil)
				store.EXPECT().CreateAccessTokenSession(t.Context(), "ats", gomock.Eq(areq.Sanitize([]string{}))).Return(errors.New(""))
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldPass",
			setup: func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder) {
				areq.State = "state"
				areq.GrantedScope = oauth2.Arguments{"scope"}

				store.EXPECT().CreateAccessTokenSession(t.Context(), "ats", gomock.Eq(areq.Sanitize([]string{}))).AnyTimes().Return(nil)

				aresp.EXPECT().AddParameter(consts.AccessResponseAccessToken, "access.ats")
				aresp.EXPECT().AddParameter(consts.AccessResponseExpiresIn, gomock.Any())
				aresp.EXPECT().AddParameter(consts.AccessResponseTokenType, oauth2.BearerAccessToken)
				aresp.EXPECT().AddParameter(consts.FormParameterState, "state")
				aresp.EXPECT().AddParameter(consts.FormParameterScope, "scope")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(areq, store, chgen, aresp)
			err := h.HandleAuthorizeEndpointRequest(t.Context(), areq, aresp)
			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)

				if tc.errField != "" {
					assert.Equal(t, tc.errField, oauth2.ErrorToRFC6749Error(err).ErrorField)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDefaultResponseMode_AuthorizeImplicit_EndpointHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	areq := oauth2.NewAuthorizeRequest()
	areq.Session = new(oauth2.DefaultSession)
	h, store, chgen, aresp := makeAuthorizeImplicitGrantTypeHandler(ctrl)

	areq.State = "state"
	areq.GrantedScope = oauth2.Arguments{"scope"}
	areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken}
	areq.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
		DefaultClient: &oauth2.DefaultClient{
			GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
			ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
		},
		TokenLifespans: &internal.TestLifespans,
	}

	store.EXPECT().CreateAccessTokenSession(t.Context(), "ats", gomock.Eq(areq.Sanitize([]string{}))).AnyTimes().Return(nil)
	aresp.EXPECT().AddParameter(consts.AccessResponseAccessToken, "access.ats")
	aresp.EXPECT().AddParameter(consts.AccessResponseExpiresIn, gomock.Any())
	aresp.EXPECT().AddParameter(consts.AccessResponseTokenType, oauth2.BearerAccessToken)
	aresp.EXPECT().AddParameter(consts.FormParameterState, "state")
	aresp.EXPECT().AddParameter(consts.FormParameterScope, "scope")
	chgen.EXPECT().GenerateAccessToken(t.Context(), areq).AnyTimes().Return("access.ats", "ats", nil)

	err := h.HandleAuthorizeEndpointRequest(t.Context(), areq, aresp)
	assert.NoError(t, err)
	assert.Equal(t, oauth2.ResponseModeFragment, areq.GetResponseMode())

	internal.RequireEqualTime(t, time.Now().UTC().Add(*internal.TestLifespans.ImplicitGrantAccessTokenLifespan), areq.Session.GetExpiresAt(oauth2.AccessToken), time.Minute)
}

func TestAuthorizeImplicit_AuthorizationDetails(t *testing.T) {
	granted := oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}}

	testCases := []struct {
		name     string
		handlers []oauth2.AuthorizationDetailsTypeHandler
		allowed  []string
		hint     string
	}{
		{name: "ShouldIssueGrantedDetails", handlers: []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}}},
		{name: "ShouldIssueGrantedDetailsAllowedForClient", handlers: []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}}, allowed: []string{internal.AuthorizationDetailsTypePaymentInitiation}},
		{name: "ShouldRejectGrantedTypeNotAllowedForClient", handlers: []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}}, allowed: []string{}, hint: testRARHintTypeNotAllowed},
		{name: "ShouldRejectGrantedTypeWithoutHandler", hint: testRARHintTypeNotSupported},
	}

	entrypoints := []struct {
		name string
		call func(ctx context.Context, h *AuthorizeImplicitGrantTypeHandler, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) error
	}{
		{"HandleAuthorizeEndpointRequest", func(ctx context.Context, h *AuthorizeImplicitGrantTypeHandler, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) error {
			return h.HandleAuthorizeEndpointRequest(ctx, request, response)
		}},
		{"IssueImplicitAccessToken", func(ctx context.Context, h *AuthorizeImplicitGrantTypeHandler, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) error {
			return h.IssueImplicitAccessToken(ctx, request, response)
		}},
	}

	for _, entrypoint := range entrypoints {
		for _, tc := range testCases {
			t.Run(entrypoint.name+"/"+tc.name, func(t *testing.T) {
				store := storage.NewMemoryStore()

				h := &AuthorizeImplicitGrantTypeHandler{
					AccessTokenStorage:  store,
					AccessTokenStrategy: &hmacshaStrategy,
					Config: &oauth2.Config{
						AccessTokenLifespan:              time.Hour,
						ScopeStrategy:                    oauth2.HierarchicScopeStrategy,
						AudienceStrategy:                 oauth2.DefaultAudienceStrategy,
						AuthorizationDetailsTypeHandlers: tc.handlers,
					},
				}

				areq := oauth2.NewAuthorizeRequest()
				areq.Session = new(oauth2.DefaultSession)
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken}
				areq.Client = &internal.AuthorizationDetailsClient{
					DefaultClient: &oauth2.DefaultClient{
						GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
					},
					AuthorizationDetailsTypes: tc.allowed,
				}
				areq.SetGrantedAuthorizationDetails(granted)

				aresp := oauth2.NewAuthorizeResponse()

				err := entrypoint.call(t.Context(), h, areq, aresp)

				if tc.hint == "" {
					require.NoError(t, err)

					token := aresp.GetParameters().Get(consts.AccessResponseAccessToken)
					require.NotEmpty(t, token)

					stored, err := store.GetAccessTokenSession(t.Context(), hmacshaStrategy.AccessTokenSignature(t.Context(), token), new(oauth2.DefaultSession))
					require.NoError(t, err)

					assert.Equal(t, granted, stored.GetGrantedAuthorizationDetails())

					return
				}

				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrInvalidAuthorizationDetails)
				assert.Equal(t, tc.hint, oauth2.ErrorToRFC6749Error(err).HintField)
				assert.Empty(t, aresp.GetParameters().Get(consts.AccessResponseAccessToken))
				assert.Empty(t, store.AccessTokens)
			})
		}
	}
}

func makeAuthorizeImplicitGrantTypeHandler(ctrl *gomock.Controller) (AuthorizeImplicitGrantTypeHandler,
	*mock.MockAccessTokenStorage, *mock.MockAccessTokenStrategy, *mock.MockAuthorizeResponder) {
	store := mock.NewMockAccessTokenStorage(ctrl)
	chgen := mock.NewMockAccessTokenStrategy(ctrl)
	aresp := mock.NewMockAuthorizeResponder(ctrl)

	h := AuthorizeImplicitGrantTypeHandler{
		AccessTokenStorage:  store,
		AccessTokenStrategy: chgen,
		Config: &oauth2.Config{
			AccessTokenLifespan: time.Hour,
			ScopeStrategy:       oauth2.HierarchicScopeStrategy,
			AudienceStrategy:    oauth2.DefaultAudienceStrategy,
		},
	}

	return h, store, chgen, aresp
}
