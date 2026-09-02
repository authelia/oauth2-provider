// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestBindingHandlerListsDeduplicateOnType(t *testing.T) {
	var authorize oauth2.AuthorizeEndpointBindingHandlers

	authorize.Append(&stubAuthorizeBinder{})
	authorize.Append(&stubAuthorizeBinder{})

	assert.Len(t, authorize, 1)

	var token oauth2.TokenEndpointBindingHandlers

	token.Append(&stubTokenBinder{})
	token.Append(&stubTokenBinder{})

	assert.Len(t, token, 1)
}

func TestConfigReturnsBindingHandlers(t *testing.T) {
	authorize := &stubAuthorizeBinder{}
	token := &stubTokenBinder{}

	config := &oauth2.Config{}
	config.AuthorizeEndpointBindingHandlers.Append(authorize)
	config.TokenEndpointBindingHandlers.Append(token)

	assert.Equal(t, oauth2.AuthorizeEndpointBindingHandlers{authorize}, config.GetAuthorizeEndpointBindingHandlers(context.Background()))
	assert.Equal(t, oauth2.TokenEndpointBindingHandlers{token}, config.GetTokenEndpointBindingHandlers(context.Background()))
}

func TestAuthorizeBindingHandlersRunBeforeTheAuthorizeHandlers(t *testing.T) {
	recorder := &recordingAuthorizeHandler{}

	config := &oauth2.Config{}
	config.AuthorizeEndpointBindingHandlers.Append(&subjectSettingBinder{})
	config.AuthorizeEndpointHandlers.Append(recorder)

	provider := oauth2.New(storage.NewMemoryStore(), config)

	request := oauth2.NewAuthorizeRequest()
	request.ResponseTypes = oauth2.Arguments{"code"}

	_, err := provider.NewAuthorizeResponse(context.Background(), request, &oauth2.DefaultSession{})
	require.NoError(t, err)

	assert.Equal(t, 1, recorder.calls)
	assert.Equal(t, "bound-before-handlers", recorder.sawSubject)
}

func TestAuthorizeBindingHandlerErrorAbortsTheRequest(t *testing.T) {
	recorder := &recordingAuthorizeHandler{}

	config := &oauth2.Config{}
	config.AuthorizeEndpointBindingHandlers.Append(&stubAuthorizeBinder{err: oauth2.ErrInvalidRequest})
	config.AuthorizeEndpointHandlers.Append(recorder)

	provider := oauth2.New(storage.NewMemoryStore(), config)

	request := oauth2.NewAuthorizeRequest()
	request.ResponseTypes = oauth2.Arguments{"code"}

	responder, err := provider.NewAuthorizeResponse(context.Background(), request, &oauth2.DefaultSession{})

	require.Error(t, err)
	assert.Nil(t, responder)
	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	assert.Zero(t, recorder.calls)
}

func TestTokenBindingHandlerRunsOnlyForAnAcceptedGrant(t *testing.T) {
	t.Run("ShouldRunWhenAGrantHandlerAccepted", func(t *testing.T) {
		binder := &countingTokenBinder{}

		config := &oauth2.Config{}
		config.TokenEndpointHandlers.Append(&grantHandler{handles: true})
		config.TokenEndpointBindingHandlers.Append(binder)

		provider := oauth2.New(storage.NewMemoryStore(), config)

		_, err := provider.NewAccessRequest(context.Background(), newBindingAccessRequest(t), &oauth2.DefaultSession{})

		require.NoError(t, err)
		assert.Equal(t, 1, binder.calls)
	})

	t.Run("ShouldNotRunWhenNoGrantHandlerAccepted", func(t *testing.T) {
		binder := &countingTokenBinder{}

		config := &oauth2.Config{}
		config.TokenEndpointHandlers.Append(&grantHandler{handles: false})
		config.TokenEndpointBindingHandlers.Append(binder)

		provider := oauth2.New(storage.NewMemoryStore(), config)

		_, err := provider.NewAccessRequest(context.Background(), newBindingAccessRequest(t), &oauth2.DefaultSession{})

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Zero(t, binder.calls, "a binding handler ran for a request no grant handler accepted")
	})
}

func TestTokenBindingHandlerErrorAbortsTheRequest(t *testing.T) {
	config := &oauth2.Config{}
	config.TokenEndpointHandlers.Append(&grantHandler{handles: true})
	config.TokenEndpointBindingHandlers.Append(&countingTokenBinder{err: oauth2.ErrInvalidGrant})

	provider := oauth2.New(storage.NewMemoryStore(), config)

	_, err := provider.NewAccessRequest(context.Background(), newBindingAccessRequest(t), &oauth2.DefaultSession{})

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
}

func TestTokenBindingPopulateRunsAfterTheGrantHandlers(t *testing.T) {
	config := &oauth2.Config{}
	config.TokenEndpointHandlers.Append(&grantHandler{handles: true})
	config.TokenEndpointBindingHandlers.Append(&tokenTypeOverridingBinder{})

	provider := oauth2.New(storage.NewMemoryStore(), config)

	request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
	request.Client = &oauth2.DefaultClient{}

	response, err := provider.NewAccessResponse(context.Background(), request)
	require.NoError(t, err)

	assert.Equal(t, "OverriddenType", response.GetTokenType())
}

func TestTokenBindingPopulateErrorAbortsTheResponse(t *testing.T) {
	config := &oauth2.Config{}
	config.TokenEndpointHandlers.Append(&grantHandler{handles: true})
	config.TokenEndpointBindingHandlers.Append(&stubTokenBinder{populateErr: oauth2.ErrServerError})

	provider := oauth2.New(storage.NewMemoryStore(), config)

	request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
	request.Client = &oauth2.DefaultClient{}

	response, err := provider.NewAccessResponse(context.Background(), request)

	require.Error(t, err)
	assert.Nil(t, response)
	assert.ErrorIs(t, err, oauth2.ErrServerError)
}

func TestTokenBindingHandlersShareAPublishedDPoPProof(t *testing.T) {
	reader := &proofReadingBinder{}

	config := &oauth2.Config{}
	config.TokenEndpointHandlers.Append(&grantHandler{handles: true})
	config.TokenEndpointBindingHandlers.Append(&proofPublishingBinder{})
	config.TokenEndpointBindingHandlers.Append(reader)

	provider := oauth2.New(storage.NewMemoryStore(), config)

	_, err := provider.NewAccessRequest(context.Background(), newBindingAccessRequest(t), &oauth2.DefaultSession{})
	require.NoError(t, err)

	assert.Equal(t, "published", reader.saw)
}

type stubAuthorizeBinder struct {
	err error
}

func (s *stubAuthorizeBinder) BindAuthorizeRequest(context.Context, oauth2.AuthorizeRequester) error {
	return s.err
}

type stubTokenBinder struct {
	bindErr, populateErr error
}

func (s *stubTokenBinder) BindAccessRequest(context.Context, oauth2.AccessRequester) error {
	return s.bindErr
}

func (s *stubTokenBinder) PopulateBoundTokenEndpointResponse(context.Context, oauth2.AccessRequester, oauth2.AccessResponder) error {
	return s.populateErr
}

type tokenTypeOverridingBinder struct{}

func (t *tokenTypeOverridingBinder) BindAccessRequest(context.Context, oauth2.AccessRequester) error {
	return nil
}

func (t *tokenTypeOverridingBinder) PopulateBoundTokenEndpointResponse(_ context.Context, _ oauth2.AccessRequester, response oauth2.AccessResponder) error {
	response.SetTokenType("OverriddenType")

	return nil
}

type grantHandler struct {
	handles bool
}

func (g *grantHandler) HandleTokenEndpointRequest(context.Context, oauth2.AccessRequester) error {
	if !g.handles {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	return nil
}

func (g *grantHandler) PopulateTokenEndpointResponse(_ context.Context, _ oauth2.AccessRequester, response oauth2.AccessResponder) error {
	response.SetAccessToken("a-token")
	response.SetTokenType(oauth2.BearerAccessToken)

	return nil
}

func (g *grantHandler) CanSkipClientAuth(context.Context, oauth2.AccessRequester) bool { return true }

func (g *grantHandler) CanHandleTokenEndpointRequest(context.Context, oauth2.AccessRequester) bool {
	return true
}

type countingTokenBinder struct {
	calls int
	err   error
}

func (c *countingTokenBinder) BindAccessRequest(context.Context, oauth2.AccessRequester) error {
	c.calls++

	return c.err
}

func (c *countingTokenBinder) PopulateBoundTokenEndpointResponse(context.Context, oauth2.AccessRequester, oauth2.AccessResponder) error {
	return nil
}

type recordingAuthorizeHandler struct {
	calls      int
	sawSubject string
}

func (h *recordingAuthorizeHandler) HandleAuthorizeEndpointRequest(_ context.Context, request oauth2.AuthorizeRequester, _ oauth2.AuthorizeResponder) error {
	h.calls++
	h.sawSubject = request.GetSession().GetSubject()

	request.SetResponseTypeHandled("code")

	return nil
}

type subjectSettingBinder struct{}

func (s *subjectSettingBinder) BindAuthorizeRequest(_ context.Context, request oauth2.AuthorizeRequester) error {
	request.GetSession().(*oauth2.DefaultSession).Subject = "bound-before-handlers"

	return nil
}

type proofPublishingBinder struct{}

func (b *proofPublishingBinder) BindAccessRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	oauth2.PublishDPoPProof(ctx, &oauth2.DPoPProof{Thumbprint: "published"})

	return nil
}

func (b *proofPublishingBinder) PopulateBoundTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	return nil
}

type proofReadingBinder struct {
	saw string
}

func (b *proofReadingBinder) BindAccessRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if proof := oauth2.GetDPoPProof(ctx); proof != nil {
		b.saw = proof.Thumbprint
	}

	return nil
}

func (b *proofReadingBinder) PopulateBoundTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	return nil
}

func newBindingAccessRequest(t *testing.T) *http.Request {
	t.Helper()

	form := url.Values{"grant_type": []string{"client_credentials"}}

	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return r
}
