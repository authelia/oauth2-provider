// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

// Registered Claim strings. See https://www.iana.org/assignments/jwt/jwt.xhtml.
const (
	ClaimJWTID                               = "jti"
	ClaimSessionID                           = "sid"
	ClaimIssuedAt                            = "iat"
	ClaimNotBefore                           = "nbf"
	ClaimRequestedAt                         = "rat"
	ClaimExpirationTime                      = "exp"
	ClaimAuthenticationTime                  = "auth_time"
	ClaimIssuer                              = valueIss
	ClaimSubject                             = "sub"
	ClaimAudience                            = "aud"
	ClaimGroups                              = "groups"
	ClaimFullName                            = "name"
	ClaimPreferredUsername                   = "preferred_username"
	ClaimPreferredEmail                      = "email"
	ClaimEmailVerified                       = "email_verified"
	ClaimAuthorizedParty                     = "azp"
	ClaimAuthenticationContextClassReference = "acr"
	ClaimAuthenticationMethodsReference      = "amr"
	ClaimClientIdentifier                    = valueClientID
	ClaimScope                               = valueScope
	ClaimScopeNonStandard                    = "scp"
	ClaimExtra                               = "ext"
	ClaimActive                              = "active"
	ClaimTransaction                         = "txn"
	ClaimRequestingWorkload                  = "req_wl"
	ClaimRequestingWorkloadChain             = "req_wl_chain"
	ClaimRequestContext                      = "rctx"
	ClaimTransactionContext                  = "tctx"
	ClaimUsername                            = "username"
	ClaimTokenIntrospection                  = "token_introspection"
	ClaimAccessTokenHash                     = "at_hash"
	ClaimCIBAAuthReqID                       = "urn:openid:params:jwt:claim:auth_req_id"
	ClaimRefreshTokenHash                    = "urn:openid:params:jwt:claim:rt_hash"
	ClaimCodeHash                            = "c_hash"
	ClaimStateHash                           = "s_hash"
	ClaimNonce                               = valueNonce
	ClaimAuthorizedActor                     = "may_act"
	ClaimActor                               = "act"
	ClaimEvents                              = "events"
	ClaimConfirmation                        = "cnf"
	ClaimAuthorizationDetails                = valueAuthorizationDetails
	ClaimConfirmationJWKThumbprint           = "jkt"
	ClaimConfirmationX509SHA256Thumbprint    = "x5t#S256"
	ClaimHTTPMethod                          = "htm"
	ClaimHTTPURI                             = "htu"
	ClaimDPoPAccessTokenHash                 = "ath"
	ClaimConfirmationJWK                     = "jwk"
	ClaimDPoPCodeHash                        = "c_s256"
	ClaimResource                            = "resource"
	ClaimTenant                              = "tenant"
	ClaimAudienceTenant                      = "aud_tenant"
	ClaimAudienceSubject                     = "aud_sub"
	ClaimSubjectIdentifier                   = "sub_id"
)

// Standard Claim strings. See https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims.
const (
	ClaimGivenName           = "given_name"
	ClaimFamilyName          = "family_name"
	ClaimMiddleName          = "middle_name"
	ClaimNickname            = "nickname"
	ClaimProfile             = "profile"
	ClaimPicture             = "picture"
	ClaimWebsite             = "website"
	ClaimGender              = "gender"
	ClaimBirthdate           = "birthdate"
	ClaimZoneinfo            = "zoneinfo"
	ClaimLocale              = "locale"
	ClaimPhoneNumber         = "phone_number"
	ClaimPhoneNumberVerified = "phone_number_verified"
	ClaimAddress             = "address"
	ClaimUpdatedAt           = "updated_at"
)

// Address Claim member strings. See https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim.
const (
	ClaimAddressFormatted     = "formatted"
	ClaimAddressStreetAddress = "street_address"
	ClaimAddressLocality      = "locality"
	ClaimAddressRegion        = "region"
	ClaimAddressPostalCode    = "postal_code"
	ClaimAddressCountry       = "country"
)

const (
	// ClaimEventBackChannelLogout is the back-channel logout event identifier from OpenID Connect Back-Channel Logout 1.0.
	ClaimEventBackChannelLogout = "http://schemas.openid.net/event/backchannel-logout"
)
