package jwt

import (
	"github.com/go-jose/go-jose/v4"
)

func NewJARClient(client any) Client {
	switch c := client.(type) {
	case JARClient:
		return &decoratedJARClient{JARClient: c}
	default:
		return nil
	}
}

func NewIDTokenClient(client any) Client {
	switch c := client.(type) {
	case IDTokenClient:
		return &decoratedIDTokenClient{IDTokenClient: c}
	default:
		return nil
	}
}

func NewJARMClient(client any) Client {
	switch c := client.(type) {
	case JARMClient:
		return &decoratedJARMClient{JARMClient: c}
	default:
		return nil
	}
}

func NewUserInfoClient(client any) Client {
	switch c := client.(type) {
	case UserInfoClient:
		return &decoratedUserInfoClient{UserInfoClient: c}
	default:
		return nil
	}
}

func NewJWTProfileAccessTokenClient(client any) Client {
	switch c := client.(type) {
	case JWTProfileAccessTokenClient:
		return &decoratedJWTProfileAccessTokenClient{JWTProfileAccessTokenClient: c}
	default:
		return nil
	}
}

func NewIntrospectionClient(client any) Client {
	switch c := client.(type) {
	case IntrospectionClient:
		return &decoratedIntrospectionClient{IntrospectionClient: c}
	default:
		return nil
	}
}

func NewStatelessJWTProfileIntrospectionClient(client any) Client {
	switch c := client.(type) {
	case IntrospectionClient:
		return &decoratedIntrospectionClient{IntrospectionClient: c}
	case JWTProfileAccessTokenClient:
		return &decoratedJWTProfileAccessTokenClient{JWTProfileAccessTokenClient: c}
	default:
		return nil
	}
}

type Client interface {
	GetSigningKeyID() (kid string)
	GetSigningAlg() (alg string)
	GetEncryptionKeyID() (kid string)
	GetEncryptionAlg() (alg string)
	GetEncryptionEnc() (enc string)

	IsClientSigned() (is bool)

	BaseClient
}

type BaseClient interface {
	// GetID returns the client ID.
	GetID() string

	// GetClientSecretPlainText returns the ClientSecret as plaintext if available. The semantics of this function
	// return values are important.
	// If the client is not configured with a secret the return should be:
	//   - secret with value nil, ok with value false, and err with value of nil
	// If the client is configured with a secret but is hashed or otherwise not a plaintext value:
	//   - secret with value nil, ok with value true, and err with value of nil
	// If an error occurs retrieving the secret other than this:
	//   - secret with value nil, ok with value true, and err with value of the error
	// If the plaintext secret is successful:
	//   - secret with value of the bytes of the plaintext secret, ok with value true, and err with value of nil
	GetClientSecretPlainText() (secret []byte, ok bool, err error)

	// GetJSONWebKeys returns the JSON Web Key Set containing the public key used by the client to authenticate.
	GetJSONWebKeys() (jwks *jose.JSONWebKeySet)

	// GetJSONWebKeysURI returns the URL for lookup of JSON Web Key Set containing the
	// public key used by the client to authenticate.
	GetJSONWebKeysURI() (uri string)
}

type JARClient interface {
	// GetRequestObjectSigningKeyID returns the specific key identifier used to satisfy JWS requirements of the request
	// object specifications. If unspecified the other available parameters will be utilized to select an appropriate
	// key.
	GetRequestObjectSigningKeyID() (kid string)

	// GetRequestObjectSigningAlg is equivalent to the 'request_object_signing_alg' client metadata
	// value which determines the JWS alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP.
	// All Request Objects from this Client MUST be rejected, if not signed with this algorithm. Request Objects are
	// described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. This algorithm MUST be used both when the
	// Request Object is passed by value (using the request parameter) and when it is passed by reference (using the
	// request_uri parameter). Servers SHOULD support RS256. The value none MAY be used. The default, if omitted, is
	// that any algorithm supported by the OP and the RP MAY be used.
	GetRequestObjectSigningAlg() (alg string)

	// GetRequestObjectEncryptionKeyID returns the specific key identifier used to satisfy JWE requirements of the
	// request object specifications. If unspecified the other available parameters will be utilized to select an
	// appropriate key.
	GetRequestObjectEncryptionKeyID() (kid string)

	// GetRequestObjectEncryptionAlg is equivalent to the 'request_object_encryption_alg' client metadata value which
	// determines the JWE alg algorithm [JWA] the RP is declaring that it may use for encrypting Request Objects sent to
	// the OP. This parameter SHOULD be included when symmetric encryption will be used, since this signals to the OP
	// that a client_secret value needs to be returned from which the symmetric key will be derived, that might not
	// otherwise be returned. The RP MAY still use other supported encryption algorithms or send unencrypted Request
	// Objects, even when this parameter is present. If both signing and encryption are requested, the Request Object
	// will be signed then encrypted, with the result being a Nested JWT, as defined in [JWT]. The default, if omitted,
	// is that the RP is not declaring whether it might encrypt any Request Objects.
	GetRequestObjectEncryptionAlg() (alg string)

	// GetRequestObjectEncryptionEnc is equivalent to the 'request_object_encryption_enc' client metadata value which
	// determines the JWE enc algorithm [JWA] the RP is declaring that it may use for encrypting Request Objects sent to
	// the OP. If request_object_encryption_alg is specified, the default request_object_encryption_enc value is
	// A128CBC-HS256. When request_object_encryption_enc is included, request_object_encryption_alg MUST also be
	// provided.
	GetRequestObjectEncryptionEnc() (enc string)

	BaseClient
}

type decoratedJARClient struct {
	JARClient
}

func (r *decoratedJARClient) GetSigningKeyID() (kid string) {
	return r.GetRequestObjectSigningKeyID()
}

func (r *decoratedJARClient) GetSigningAlg() (alg string) {
	return r.GetRequestObjectSigningAlg()
}

func (r *decoratedJARClient) GetEncryptionKeyID() (kid string) {
	return r.GetRequestObjectEncryptionKeyID()
}

func (r *decoratedJARClient) GetEncryptionAlg() (alg string) {
	return r.GetRequestObjectEncryptionAlg()
}

func (r *decoratedJARClient) GetEncryptionEnc() (enc string) {
	return r.GetRequestObjectEncryptionEnc()
}

func (r *decoratedJARClient) IsClientSigned() (is bool) {
	return true
}

type IDTokenClient interface {
	// GetIDTokenSignedResponseKeyID returns the specific key identifier used to satisfy JWS requirements of the ID
	// Token specifications. If unspecified the other available parameters will be utilized to select an appropriate
	// key.
	GetIDTokenSignedResponseKeyID() (kid string)

	// GetIDTokenSignedResponseAlg is equivalent to the 'id_token_signed_response_alg' client metadata value which
	// determines the JWS alg algorithm [JWA] REQUIRED for signing the ID Token issued to this Client. The value none
	// MUST NOT be used as the ID Token alg value unless the Client uses only Response Types that return no ID Token
	// from the Authorization Endpoint (such as when only using the Authorization Code Flow). The default, if omitted,
	// is RS256. The public key for validating the signature is provided by retrieving the JWK Set referenced by the
	// jwks_uri element from OpenID Connect Discovery 1.0 [OpenID.Discovery].
	GetIDTokenSignedResponseAlg() (alg string)

	// GetIDTokenEncryptedResponseKeyID returns the specific key identifier used to satisfy JWE requirements of the ID
	// Token specifications. If unspecified the other available parameters will be utilized to select an appropriate
	// key.
	GetIDTokenEncryptedResponseKeyID() (kid string)

	// GetIDTokenEncryptedResponseAlg is equivalent to the 'id_token_encrypted_response_alg' client metadata value which
	// determines the JWE alg algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client. If this is
	// requested, the response will be signed then encrypted, with the result being a Nested JWT, as defined in [JWT].
	// The default, if omitted, is that no encryption is performed.
	GetIDTokenEncryptedResponseAlg() (alg string)

	// GetIDTokenEncryptedResponseEnc is equivalent to the 'id_token_encrypted_response_enc' client metadata value which
	// determines the JWE enc algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client. If
	// id_token_encrypted_response_alg is specified, the default id_token_encrypted_response_enc value is A128CBC-HS256.
	// When id_token_encrypted_response_enc is included, id_token_encrypted_response_alg MUST also be provided.
	GetIDTokenEncryptedResponseEnc() (enc string)

	BaseClient
}

type decoratedIDTokenClient struct {
	IDTokenClient
}

func (r *decoratedIDTokenClient) GetSigningKeyID() (kid string) {
	return r.GetIDTokenSignedResponseKeyID()
}

func (r *decoratedIDTokenClient) GetSigningAlg() (alg string) {
	return r.GetIDTokenSignedResponseAlg()
}

func (r *decoratedIDTokenClient) GetEncryptionKeyID() (kid string) {
	return r.GetIDTokenEncryptedResponseKeyID()
}

func (r *decoratedIDTokenClient) GetEncryptionAlg() (alg string) {
	return r.GetIDTokenEncryptedResponseAlg()
}

func (r *decoratedIDTokenClient) GetEncryptionEnc() (enc string) {
	return r.GetIDTokenEncryptedResponseEnc()
}

func (r *decoratedIDTokenClient) IsClientSigned() (is bool) {
	return false
}

type JARMClient interface {
	// GetAuthorizationSignedResponseKeyID returns the specific key identifier used to satisfy JWS requirements of the
	// JWT-secured Authorization Response Method (JARM) specifications. If unspecified the other available parameters
	// will be utilized to select an appropriate key.
	GetAuthorizationSignedResponseKeyID() (kid string)

	// GetAuthorizationSignedResponseAlg is equivalent to the 'authorization_signed_response_alg' client metadata
	// value which determines the JWS [RFC7515] alg algorithm JWA [RFC7518] REQUIRED for signing authorization
	// responses. If this is specified, the response will be signed using JWS and the configured algorithm. The
	// algorithm none is not allowed. The default, if omitted, is RS256.
	GetAuthorizationSignedResponseAlg() (alg string)

	// GetAuthorizationEncryptedResponseKeyID returns the specific key identifier used to satisfy JWE requirements of
	// the JWT-secured Authorization Response Method (JARM) specifications. If unspecified the other available parameters will be
	// utilized to select an appropriate key.
	GetAuthorizationEncryptedResponseKeyID() (kid string)

	// GetAuthorizationEncryptedResponseAlg is equivalent to the 'authorization_encrypted_response_alg' client metadata
	// value which determines the JWE [RFC7516] alg algorithm JWA [RFC7518] REQUIRED for encrypting authorization
	// responses. If both signing and encryption are requested, the response will be signed then encrypted, with the
	// result being a Nested JWT, as defined in JWT [RFC7519]. The default, if omitted, is that no encryption is
	// performed.
	GetAuthorizationEncryptedResponseAlg() (alg string)

	// GetAuthorizationEncryptedResponseEnc is equivalent to the 'authorization_encrypted_response_enc' client
	// metadata value which determines the JWE [RFC7516] enc algorithm JWA [RFC7518] REQUIRED for encrypting
	// authorization responses. If authorization_encrypted_response_alg is specified, the default for this value is
	// A128CBC-HS256. When authorization_encrypted_response_enc is included, authorization_encrypted_response_alg MUST
	// also be provided.
	GetAuthorizationEncryptedResponseEnc() (alg string)

	BaseClient
}

type decoratedJARMClient struct {
	JARMClient
}

func (r *decoratedJARMClient) GetSigningKeyID() (kid string) {
	return r.GetAuthorizationSignedResponseKeyID()
}

func (r *decoratedJARMClient) GetSigningAlg() (alg string) {
	return r.GetAuthorizationSignedResponseAlg()
}

func (r *decoratedJARMClient) GetEncryptionKeyID() (kid string) {
	return r.GetAuthorizationEncryptedResponseKeyID()
}

func (r *decoratedJARMClient) GetEncryptionAlg() (alg string) {
	return r.GetAuthorizationEncryptedResponseAlg()
}

func (r *decoratedJARMClient) GetEncryptionEnc() (enc string) {
	return r.GetAuthorizationEncryptedResponseEnc()
}

func (r *decoratedJARMClient) IsClientSigned() (is bool) {
	return false
}

type UserInfoClient interface {
	// GetUserinfoSignedResponseKeyID returns the specific key identifier used to satisfy JWS requirements of the User
	// Info specifications. If unspecified the other available parameters will be utilized to select an appropriate
	// key.
	GetUserinfoSignedResponseKeyID() (kid string)

	// GetUserinfoSignedResponseAlg is equivalent to the 'userinfo_signed_response_alg' client metadata value which
	// determines the JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses. If this is specified, the
	// response will be JWT [JWT] serialized, and signed using JWS. The default, if omitted, is for the UserInfo
	// Response to return the Claims as a UTF-8 [RFC3629] encoded JSON object using the application/json content-type.
	GetUserinfoSignedResponseAlg() (alg string)

	// GetUserinfoEncryptedResponseKeyID returns the specific key identifier used to satisfy JWE requirements of the
	// User Info specifications. If unspecified the other available parameters will be utilized to select an appropriate
	// key.
	GetUserinfoEncryptedResponseKeyID() (kid string)

	// GetUserinfoEncryptedResponseAlg is equivalent to the 'userinfo_encrypted_response_alg' client metadata value
	// which determines the JWE alg algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client. If
	// this is requested, the response will be signed then encrypted, with the result being a Nested JWT, as defined in
	// [JWT]. The default, if omitted, is that no encryption is performed.
	GetUserinfoEncryptedResponseAlg() (alg string)

	// GetUserinfoEncryptedResponseEnc is equivalent to the 'userinfo_encrypted_response_enc' client metadata value
	// which determines the JWE enc algorithm [JWA] REQUIRED for encrypting UserInfo Responses. If
	// userinfo_encrypted_response_alg is specified, the default userinfo_encrypted_response_enc value is A128CBC-HS256.
	// When userinfo_encrypted_response_enc is included, userinfo_encrypted_response_alg MUST also be provided.
	GetUserinfoEncryptedResponseEnc() (enc string)

	BaseClient
}

type decoratedUserInfoClient struct {
	UserInfoClient
}

func (r *decoratedUserInfoClient) GetSigningKeyID() (kid string) {
	return r.GetUserinfoSignedResponseKeyID()
}

func (r *decoratedUserInfoClient) GetSigningAlg() (alg string) {
	return r.GetUserinfoSignedResponseAlg()
}

func (r *decoratedUserInfoClient) GetEncryptionKeyID() (kid string) {
	return r.GetUserinfoEncryptedResponseKeyID()
}

func (r *decoratedUserInfoClient) GetEncryptionAlg() (alg string) {
	return r.GetUserinfoEncryptedResponseAlg()
}

func (r *decoratedUserInfoClient) GetEncryptionEnc() (enc string) {
	return r.GetUserinfoEncryptedResponseEnc()
}

func (r *decoratedUserInfoClient) IsClientSigned() (is bool) {
	return false
}

type JWTProfileAccessTokenClient interface {
	// GetAccessTokenSignedResponseKeyID returns the specific key identifier used to satisfy JWS requirements for
	// JWT Profile for OAuth 2.0 Access Tokens specifications. If unspecified the other available parameters will be
	// utilized to select an appropriate key.
	GetAccessTokenSignedResponseKeyID() (kid string)

	// GetAccessTokenSignedResponseAlg determines the JWS [RFC7515] algorithm (alg value) as defined in JWA [RFC7518]
	// for signing JWT Profile Access Token responses. If this is specified, the response will be signed using JWS and
	// the configured algorithm. The default, if omitted, is none; i.e. unsigned responses unless the
	// GetEnableJWTProfileOAuthAccessTokens receiver returns true in which case the default is RS256.
	GetAccessTokenSignedResponseAlg() (alg string)

	// GetAccessTokenEncryptedResponseKeyID returns the specific key identifier used to satisfy JWE requirements for
	// JWT Profile for OAuth 2.0 Access Tokens specifications. If unspecified the other available parameters will be
	// utilized to select an appropriate key.
	GetAccessTokenEncryptedResponseKeyID() (kid string)

	// GetAccessTokenEncryptedResponseAlg determines the JWE [RFC7516] algorithm (alg value) as defined in JWA [RFC7518]
	// for content key encryption. If this is specified, the response will be encrypted using JWE and the configured
	// content encryption algorithm (access_token_encrypted_response_enc). The default, if omitted, is that no
	// encryption is performed. If both signing and encryption are requested, the response will be signed then
	// encrypted, with the result being a Nested JWT, as defined in JWT [RFC7519].
	GetAccessTokenEncryptedResponseAlg() (alg string)

	// GetAccessTokenEncryptedResponseEnc determines the JWE [RFC7516] algorithm (enc value) as defined in JWA [RFC7518]
	// for content encryption of access token responses. The default, if omitted, is A128CBC-HS256. Note: This parameter
	// MUST NOT be specified without setting access_token_encrypted_response_alg.
	GetAccessTokenEncryptedResponseEnc() (alg string)

	BaseClient
}

type decoratedJWTProfileAccessTokenClient struct {
	JWTProfileAccessTokenClient
}

func (r *decoratedJWTProfileAccessTokenClient) GetSigningKeyID() (kid string) {
	return r.GetAccessTokenSignedResponseKeyID()
}

func (r *decoratedJWTProfileAccessTokenClient) GetSigningAlg() (alg string) {
	return r.GetAccessTokenSignedResponseAlg()
}

func (r *decoratedJWTProfileAccessTokenClient) GetEncryptionKeyID() (kid string) {
	return r.GetAccessTokenEncryptedResponseKeyID()
}

func (r *decoratedJWTProfileAccessTokenClient) GetEncryptionAlg() (alg string) {
	return r.GetAccessTokenEncryptedResponseAlg()
}

func (r *decoratedJWTProfileAccessTokenClient) GetEncryptionEnc() (enc string) {
	return r.GetAccessTokenEncryptedResponseEnc()
}

func (r *decoratedJWTProfileAccessTokenClient) IsClientSigned() (is bool) {
	return false
}

type IntrospectionClient interface {
	// GetIntrospectionSignedResponseKeyID returns the specific key identifier used to satisfy JWS requirements for
	// OAuth 2.0 JWT introspection response specifications. If unspecified the other available parameters will be
	//	// utilized to select an appropriate key.
	GetIntrospectionSignedResponseKeyID() (kid string)

	// GetIntrospectionSignedResponseAlg is equivalent to the 'introspection_signed_response_alg' client metadata
	// value which determines the JWS [RFC7515] algorithm (alg value) as defined in JWA [RFC7518] for signing
	// introspection responses. If this is specified, the response will be signed using JWS and the configured
	// algorithm. The default, if omitted, is RS256.
	GetIntrospectionSignedResponseAlg() (alg string)

	// GetIntrospectionEncryptedResponseKeyID returns the specific key identifier used to satisfy JWE requirements for
	// OAuth 2.0 JWT introspection response specifications. If unspecified the other available parameters will be
	//	// utilized to select an appropriate key.
	GetIntrospectionEncryptedResponseKeyID() (kid string)

	// GetIntrospectionEncryptedResponseAlg is equivalent to the 'introspection_encrypted_response_alg' client metadata
	// value which determines the JWE [RFC7516] algorithm (alg value) as defined in JWA [RFC7518] for content key
	// encryption. If this is specified, the response will be encrypted using JWE and the configured content encryption
	// algorithm (introspection_encrypted_response_enc). The default, if omitted, is that no encryption is performed.
	// If both signing and encryption are requested, the response will be signed then encrypted, with the result being
	// a Nested JWT, as defined in JWT [RFC7519].
	GetIntrospectionEncryptedResponseAlg() (alg string)

	// GetIntrospectionEncryptedResponseEnc is equivalent to the 'introspection_encrypted_response_enc' client metadata
	// value which determines the  JWE [RFC7516] algorithm (enc value) as defined in JWA [RFC7518] for content
	// encryption of introspection responses. The default, if omitted, is A128CBC-HS256. Note: This parameter MUST NOT
	// be specified without setting introspection_encrypted_response_alg.
	GetIntrospectionEncryptedResponseEnc() (enc string)

	BaseClient
}

type decoratedIntrospectionClient struct {
	IntrospectionClient
}

func (r *decoratedIntrospectionClient) GetSigningKeyID() (kid string) {
	return r.GetIntrospectionSignedResponseKeyID()
}

func (r *decoratedIntrospectionClient) GetSigningAlg() (alg string) {
	return r.GetIntrospectionSignedResponseAlg()
}

func (r *decoratedIntrospectionClient) GetEncryptionKeyID() (kid string) {
	return r.GetIntrospectionEncryptedResponseKeyID()
}

func (r *decoratedIntrospectionClient) GetEncryptionAlg() (alg string) {
	return r.GetIntrospectionEncryptedResponseAlg()
}

func (r *decoratedIntrospectionClient) GetEncryptionEnc() (enc string) {
	return r.GetIntrospectionEncryptedResponseEnc()
}

func (r *decoratedIntrospectionClient) IsClientSigned() (is bool) {
	return false
}
