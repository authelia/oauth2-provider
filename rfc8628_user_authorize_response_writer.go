package oauth2

import "context"

func (f *Fosite) NewRFC8628UserAuthorizeResponse(ctx context.Context, requester DeviceAuthorizeRequester, session Session) (DeviceUserAuthorizeResponder, error) {
	requester.SetSession(session)
	var resp = NewRFC8628UserAuthorizeResponse()

	for _, h := range f.Config.GetRFC8628UserAuthorizeEndpointHandlers(ctx) {
		if err := h.PopulateRFC8628UserAuthorizeEndpointResponse(ctx, requester, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}
