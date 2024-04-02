package oauth2

import (
	"context"
	"errors"
	"net/http"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/x/errorsx"
)

func (f *Fosite) NewRFC8628UserAuthorizeRequest(ctx context.Context, req *http.Request) (DeviceAuthorizeRequester, error) {
	request := NewDeviceAuthorizeRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), req)

	if err := req.ParseForm(); err != nil {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}
	request.Form = req.Form

	for _, h := range f.Config.GetRFC8628UserAuthorizeEndpointHandlers(ctx) {
		if err := h.HandleRFC8628UserAuthorizeEndpointRequest(ctx, request); err != nil && !errors.Is(err, ErrUnknownRequest) {
			return nil, err
		}
	}

	return request, nil
}
