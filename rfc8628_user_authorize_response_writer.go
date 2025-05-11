package oauth2

import "context"

func (f *Fosite) NewRFC8628UserAuthorizeResponse(ctx context.Context, requester DeviceAuthorizeRequester, session Session) (responder DeviceUserAuthorizeResponder, err error) {
	requester.SetSession(session)
	responder = NewRFC8628UserAuthorizeResponse()

	for _, h := range f.Config.GetRFC8628UserAuthorizeEndpointHandlers(ctx) {
		if err = h.PopulateRFC8628UserAuthorizeEndpointResponse(ctx, requester, responder); err != nil {
			return nil, err
		}
	}

	return responder, nil
}
