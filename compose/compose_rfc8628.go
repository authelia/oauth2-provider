package compose

import (
	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc8628"
)

// RFC8628DeviceAuthorizeFactory creates an OAuth2 device grant authorization handler.
func RFC8628DeviceAuthorizeFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &rfc8628.DeviceAuthorizeHandler{
		Strategy: strategy.(rfc8628.RFC8628CodeStrategy),
		Storage:  storage.(rfc8628.RFC8628Storage),
		Config:   config,
	}
}

// RFC8628UserAuthorizeFactory creates an OAuth2 device grant user interaction handler.
func RFC8628UserAuthorizeFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &rfc8628.UserAuthorizeHandler{
		Strategy: strategy.(rfc8628.RFC8628CodeStrategy),
		Storage:  storage.(rfc8628.RFC8628Storage),
		Config:   config,
	}
}

// RFC8628DeviceAuthorizeTokenFactory creates an OAuth2 device authorization grant ("device authorization flow") handler and registers
// an access token, refresh token and authorize code validator.
func RFC8628DeviceAuthorizeTokenFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &rfc8628.DeviceAuthorizeTokenEndpointHandler{
		GenericCodeTokenEndpointHandler: hoauth2.GenericCodeTokenEndpointHandler{
			CodeTokenEndpointHandler: &rfc8628.DeviceCodeTokenHandler{
				Strategy: strategy.(rfc8628.RFC8628CodeStrategy),
				Storage:  storage.(rfc8628.RFC8628Storage),
				Config:   config,
			},
			AccessTokenStrategy:    strategy.(hoauth2.AccessTokenStrategy),
			RefreshTokenStrategy:   strategy.(hoauth2.RefreshTokenStrategy),
			CoreStorage:            storage.(hoauth2.CoreStorage),
			TokenRevocationStorage: storage.(hoauth2.TokenRevocationStorage),
			Config:                 config,
		},
	}
}
