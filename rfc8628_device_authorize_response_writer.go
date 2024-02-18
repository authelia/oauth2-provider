package oauth2

import (
	"context"
)

func (f *Fosite) NewRFC862DeviceAuthorizeResponse(ctx context.Context, r DeviceAuthorizeRequester, session Session) (DeviceAuthorizeResponder, error) {
	r.SetSession(session)
	var resp = NewDeviceAuthorizeResponse()

	for _, h := range f.Config.GetDeviceAuthorizeEndpointHandlers(ctx) {
		if err := h.HandleRFC8628DeviceAuthorizeEndpointRequest(ctx, r, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}
