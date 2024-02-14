// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/hash.go authelia.com/provider/oauth2 Hasher
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/storage.go authelia.com/provider/oauth2 Storage
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/transactional.go authelia.com/provider/oauth2/storage Transactional
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/oauth2_storage.go authelia.com/provider/oauth2/handler/oauth2 CoreStorage
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/oauth2_strategy.go authelia.com/provider/oauth2/handler/oauth2 CoreStrategy
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/authorize_code_storage.go authelia.com/provider/oauth2/handler/oauth2 AuthorizeCodeStorage
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/oauth2_auth_jwt_storage.go authelia.com/provider/oauth2/handler/rfc7523 RFC7523KeyStorage
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/access_token_storage.go authelia.com/provider/oauth2/handler/oauth2 AccessTokenStorage
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/refresh_token_strategy.go authelia.com/provider/oauth2/handler/oauth2 RefreshTokenStorage
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/oauth2_client_storage.go authelia.com/provider/oauth2/handler/oauth2 ClientCredentialsGrantStorage
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/oauth2_owner_storage.go authelia.com/provider/oauth2/handler/oauth2 ResourceOwnerPasswordCredentialsGrantStorage
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/oauth2_revoke_storage.go authelia.com/provider/oauth2/handler/oauth2 TokenRevocationStorage
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/openid_id_token_storage.go authelia.com/provider/oauth2/handler/openid OpenIDConnectRequestStorage
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/access_token_strategy.go authelia.com/provider/oauth2/handler/oauth2 AccessTokenStrategy
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/refresh_token_strategy.go authelia.com/provider/oauth2/handler/oauth2 ReyfreshTokenStrategy
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/authorize_code_strategy.go authelia.com/provider/oauth2/handler/oauth2 AuthorizeCodeStrategy
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/id_token_strategy.go authelia.com/provider/oauth2/handler/openid OpenIDConnectTokenStrategy
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/pkce_storage_strategy.go authelia.com/provider/oauth2/handler/pkce PKCERequestStorage
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/authorize_handler.go authelia.com/provider/oauth2 AuthorizeEndpointHandler
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/revoke_handler.go authelia.com/provider/oauth2 RevocationHandler
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/token_handler.go authelia.com/provider/oauth2 TokenEndpointHandler
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/introspector.go authelia.com/provider/oauth2 TokenIntrospector
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/client.go authelia.com/provider/oauth2 Client
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/request.go authelia.com/provider/oauth2 Requester
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/access_request.go authelia.com/provider/oauth2 AccessRequester
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/access_response.go authelia.com/provider/oauth2 AccessResponder
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/authorize_request.go authelia.com/provider/oauth2 AuthorizeRequester
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/authorize_response.go authelia.com/provider/oauth2 AuthorizeResponder
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/device_oauth2_handler.go authelia.com/provider/oauth2/handler/oauth2 CodeTokenEndpointHandler
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/device_handler.go authelia.com/provider/oauth2 DeviceAuthorizeEndpointHandler,RFC8628UserAuthorizeEndpointHandler
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/oauth2_device_auth_storage.go authelia.com/provider/oauth2/handler/rfc8628 RFC8628CodeStorage
//go:generate go run go.uber.org/mock/mockgen -package internal -destination internal/device_authorization_request.go authelia.com/provider/oauth2 DeviceAuthorizeRequester
