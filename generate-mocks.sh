#!/bin/bash

${MOCKGEN:-mockgen} -package mock -destination testing/mock/rw.go net/http ResponseWriter

${MOCKGEN:-mockgen} -package mock -destination testing/mock/introspector.go authelia.com/provider/oauth2 TokenIntrospector
${MOCKGEN:-mockgen} -package mock -destination testing/mock/client.go authelia.com/provider/oauth2 Client
${MOCKGEN:-mockgen} -package mock -destination testing/mock/client_secret.go authelia.com/provider/oauth2 ClientSecret

${MOCKGEN:-mockgen} -package mock -destination testing/mock/oauth2_strategy.go authelia.com/provider/oauth2/handler/oauth2 CoreStrategy
${MOCKGEN:-mockgen} -package mock -destination testing/mock/access_token_strategy.go authelia.com/provider/oauth2/handler/oauth2 AccessTokenStrategy
${MOCKGEN:-mockgen} -package mock -destination testing/mock/refresh_token_strategy.go authelia.com/provider/oauth2/handler/oauth2 RefreshTokenStrategy
${MOCKGEN:-mockgen} -package mock -destination testing/mock/authorize_code_strategy.go authelia.com/provider/oauth2/handler/oauth2 AuthorizeCodeStrategy
${MOCKGEN:-mockgen} -package mock -destination testing/mock/id_token_strategy.go authelia.com/provider/oauth2/handler/openid OpenIDConnectTokenStrategy

${MOCKGEN:-mockgen} -package mock -destination testing/mock/storage.go authelia.com/provider/oauth2 Storage
${MOCKGEN:-mockgen} -package mock -destination testing/mock/transactional.go authelia.com/provider/oauth2/storage Transactional
${MOCKGEN:-mockgen} -package mock -destination testing/mock/oauth2_storage.go authelia.com/provider/oauth2/handler/oauth2 CoreStorage
${MOCKGEN:-mockgen} -package mock -destination testing/mock/oauth2_device_auth_storage.go -mock_names Storage=MockRFC8628Storage authelia.com/provider/oauth2/handler/rfc8628 Storage
${MOCKGEN:-mockgen} -package mock -destination testing/mock/openid_id_token_storage.go authelia.com/provider/oauth2/handler/openid OpenIDConnectRequestStorage
${MOCKGEN:-mockgen} -package mock -destination testing/mock/pkce_storage.go -mock_names Storage=MockPKCERequestStorage authelia.com/provider/oauth2/handler/pkce Storage
${MOCKGEN:-mockgen} -package mock -destination testing/mock/authorize_code_storage.go authelia.com/provider/oauth2/handler/oauth2 AuthorizeCodeStorage
${MOCKGEN:-mockgen} -package mock -destination testing/mock/oauth2_auth_jwt_storage.go authelia.com/provider/oauth2/handler/rfc7523 RFC7523KeyStorage
${MOCKGEN:-mockgen} -package mock -destination testing/mock/access_token_storage.go authelia.com/provider/oauth2/handler/oauth2 AccessTokenStorage
${MOCKGEN:-mockgen} -package mock -destination testing/mock/refresh_token_storage.go authelia.com/provider/oauth2/handler/oauth2 RefreshTokenStorage
${MOCKGEN:-mockgen} -package mock -destination testing/mock/oauth2_client_storage.go authelia.com/provider/oauth2/handler/oauth2 ClientCredentialsGrantStorage
${MOCKGEN:-mockgen} -package mock -destination testing/mock/oauth2_owner_storage.go authelia.com/provider/oauth2/handler/oauth2 ResourceOwnerPasswordCredentialsGrantStorage
${MOCKGEN:-mockgen} -package mock -destination testing/mock/oauth2_revoke_storage.go authelia.com/provider/oauth2/handler/oauth2 TokenRevocationStorage

${MOCKGEN:-mockgen} -package mock -destination testing/mock/request.go authelia.com/provider/oauth2 Requester
${MOCKGEN:-mockgen} -package mock -destination testing/mock/access_request.go authelia.com/provider/oauth2 AccessRequester
${MOCKGEN:-mockgen} -package mock -destination testing/mock/access_response.go authelia.com/provider/oauth2 AccessResponder
${MOCKGEN:-mockgen} -package mock -destination testing/mock/authorize_request.go authelia.com/provider/oauth2 AuthorizeRequester
${MOCKGEN:-mockgen} -package mock -destination testing/mock/authorize_response.go authelia.com/provider/oauth2 AuthorizeResponder
${MOCKGEN:-mockgen} -package mock -destination testing/mock/device_authorization_request.go authelia.com/provider/oauth2 DeviceAuthorizeRequester

${MOCKGEN:-mockgen} -package mock -destination testing/mock/authorize_handler.go authelia.com/provider/oauth2 AuthorizeEndpointHandler
${MOCKGEN:-mockgen} -package mock -destination testing/mock/revoke_handler.go authelia.com/provider/oauth2 RevocationHandler
${MOCKGEN:-mockgen} -package mock -destination testing/mock/token_handler.go authelia.com/provider/oauth2 TokenEndpointHandler
${MOCKGEN:-mockgen} -package mock -destination testing/mock/device_oauth2_handler.go authelia.com/provider/oauth2/handler/oauth2 CodeTokenEndpointHandler
${MOCKGEN:-mockgen} -package mock -destination testing/mock/pushed_authorize_handler.go authelia.com/provider/oauth2 PushedAuthorizeEndpointHandler
${MOCKGEN:-mockgen} -package mock -destination testing/mock/device_handler.go authelia.com/provider/oauth2 RFC8628DeviceAuthorizeEndpointHandler,RFC8628UserAuthorizeEndpointHandler
