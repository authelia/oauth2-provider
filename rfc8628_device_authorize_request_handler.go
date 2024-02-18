package oauth2

import (
	"context"
	"net/http"
	"strings"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
)

func (f *Fosite) NewRFC862DeviceAuthorizeRequest(ctx context.Context, req *http.Request) (DeviceAuthorizeRequester, error) {
	request := NewDeviceAuthorizeRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), req)

	if err := req.ParseForm(); err != nil {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}
	request.Form = req.PostForm

	client, err := f.Store.GetClient(ctx, request.GetRequestForm().Get(consts.FormParameterClientID))
	if err != nil {
		return nil, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 Client does not exist.").WithWrap(err).WithDebugError(err))
	}
	request.Client = client

	if !client.GetGrantTypes().Has(string(GrantTypeDeviceCode)) {
		return nil, errorsx.WithStack(ErrInvalidGrant.WithHint("The requested OAuth 2.0 Client does not have the 'urn:ietf:params:oauth:grant-type:device_code' grant."))
	}

	if err := f.validateDeviceScope(ctx, req, request); err != nil {
		return nil, err
	}

	return request, nil
}

func (f *Fosite) validateDeviceScope(ctx context.Context, _ *http.Request, request *DeviceAuthorizeRequest) error {
	scope := RemoveEmpty(strings.Split(request.Form.Get(consts.FormParameterScope), " "))
	for _, permission := range scope {
		if !f.Config.GetScopeStrategy(ctx)(request.Client.GetScopes(), permission) {
			return errorsx.WithStack(ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", permission))
		}
	}
	request.SetRequestedScopes(scope)
	return nil
}
