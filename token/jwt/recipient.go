package jwt

import "github.com/go-jose/go-jose/v4"

func NewRecipientJARClient(client JARClient) *RecipientRequestObjectClient {
	return &RecipientRequestObjectClient{client: client}
}

func NewRecipientIDTokenClient(client IDTokenClient) *RecipientIDTokenClient {
	return &RecipientIDTokenClient{client: client}
}

func NewRecipientJARMClient(client JARMClient) *RecipientJARMClient {
	return &RecipientJARMClient{client: client}
}

func NewRecipientUserInfoClient(client UserInfoClient) *RecipientUserInfoClient {
	return &RecipientUserInfoClient{client: client}
}

func NewRecipientJWTProfileAccessTokenClient(client JWTProfileAccessTokenClient) *RecipientJWTProfileAccessTokenClient {
	return &RecipientJWTProfileAccessTokenClient{client: client}
}

func NewRecipientIntrospectionClient(client IntrospectionClient) *RecipientIntrospectionClient {
	return &RecipientIntrospectionClient{client: client}
}

type Recipient interface {
	GetSignatureKeyID() (kid string)
	GetSignatureAlg() (alg string)
	GetEncryptionKeyID() (kid string)
	GetEncryptionAlg() (alg string)
	GetEncryptionEnc() (enc string)
	GetJSONWebKeySet() (jwks *jose.JSONWebKeySet)
	GetHaveSignaturePrivateKey() (have bool)
	GetHaveEncryptionPrivateKey() (have bool)
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

	KeyProvider
}

type RecipientRequestObjectClient struct {
	client JARClient
}

func (r *RecipientRequestObjectClient) GetSignatureKeyID() (kid string) {
	return r.client.GetRequestObjectSigningKeyID()
}

func (r *RecipientRequestObjectClient) GetSignatureAlg() (alg string) {
	return r.client.GetRequestObjectSigningAlg()
}

func (r *RecipientRequestObjectClient) GetEncryptionKeyID() (kid string) {
	return r.client.GetRequestObjectEncryptionKeyID()
}

func (r *RecipientRequestObjectClient) GetEncryptionAlg() (alg string) {
	return r.client.GetRequestObjectEncryptionAlg()
}

func (r *RecipientRequestObjectClient) GetEncryptionEnc() (enc string) {
	return r.client.GetRequestObjectEncryptionEnc()
}

func (r *RecipientRequestObjectClient) GetJSONWebKeySet() (jwks *jose.JSONWebKeySet) {
	return r.client.GetJSONWebKeys()
}

func (r *RecipientRequestObjectClient) GetHaveSignaturePrivateKey() (have bool) {
	return true
}

func (r *RecipientRequestObjectClient) GetHaveEncryptionPrivateKey() (have bool) {
	return false
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

	KeyProvider
}

type RecipientIDTokenClient struct {
	client IDTokenClient
}

func (r *RecipientIDTokenClient) GetSignatureKeyID() (kid string) {
	return r.client.GetIDTokenSignedResponseKeyID()
}

func (r *RecipientIDTokenClient) GetSignatureAlg() (alg string) {
	return r.client.GetIDTokenSignedResponseAlg()
}

func (r *RecipientIDTokenClient) GetEncryptionKeyID() (kid string) {
	return r.client.GetIDTokenEncryptedResponseKeyID()
}

func (r *RecipientIDTokenClient) GetEncryptionAlg() (alg string) {
	return r.client.GetIDTokenEncryptedResponseAlg()
}

func (r *RecipientIDTokenClient) GetEncryptionEnc() (enc string) {
	return r.client.GetIDTokenEncryptedResponseEnc()
}

func (r *RecipientIDTokenClient) GetJSONWebKeySet() (jwks *jose.JSONWebKeySet) {
	return r.client.GetJSONWebKeys()
}

func (r *RecipientIDTokenClient) GetHaveSignaturePrivateKey() (have bool) {
	return true
}

func (r *RecipientIDTokenClient) GetHaveEncryptionPrivateKey() (have bool) {
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

	KeyProvider
}

type RecipientJARMClient struct {
	client JARMClient
}

func (r *RecipientJARMClient) GetSignatureKeyID() (kid string) {
	return r.client.GetAuthorizationSignedResponseKeyID()
}

func (r *RecipientJARMClient) GetSignatureAlg() (alg string) {
	return r.client.GetAuthorizationSignedResponseAlg()
}

func (r *RecipientJARMClient) GetEncryptionKeyID() (kid string) {
	return r.client.GetAuthorizationEncryptedResponseKeyID()
}

func (r *RecipientJARMClient) GetEncryptionAlg() (alg string) {
	return r.client.GetAuthorizationEncryptedResponseAlg()
}

func (r *RecipientJARMClient) GetEncryptionEnc() (enc string) {
	return r.client.GetAuthorizationEncryptedResponseEnc()
}

func (r *RecipientJARMClient) GetJSONWebKeySet() (jwks *jose.JSONWebKeySet) {
	return r.client.GetJSONWebKeys()
}

func (r *RecipientJARMClient) GetHaveSignaturePrivateKey() (have bool) {
	return true
}

func (r *RecipientJARMClient) GetHaveEncryptionPrivateKey() (have bool) {
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

	KeyProvider
}

type RecipientUserInfoClient struct {
	client UserInfoClient
}

func (r *RecipientUserInfoClient) GetSignatureKeyID() (kid string) {
	return r.client.GetUserinfoSignedResponseKeyID()
}

func (r *RecipientUserInfoClient) GetSignatureAlg() (alg string) {
	return r.client.GetUserinfoSignedResponseAlg()
}

func (r *RecipientUserInfoClient) GetEncryptionKeyID() (kid string) {
	return r.client.GetUserinfoEncryptedResponseKeyID()
}

func (r *RecipientUserInfoClient) GetEncryptionAlg() (alg string) {
	return r.client.GetUserinfoEncryptedResponseAlg()
}

func (r *RecipientUserInfoClient) GetEncryptionEnc() (enc string) {
	return r.client.GetUserinfoEncryptedResponseEnc()
}

func (r *RecipientUserInfoClient) GetJSONWebKeySet() (jwks *jose.JSONWebKeySet) {
	return r.client.GetJSONWebKeys()
}

func (r *RecipientUserInfoClient) GetHaveSignaturePrivateKey() (have bool) {
	return true
}

func (r *RecipientUserInfoClient) GetHaveEncryptionPrivateKey() (have bool) {
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

	KeyProvider
}

type RecipientJWTProfileAccessTokenClient struct {
	client JWTProfileAccessTokenClient
}

func (r *RecipientJWTProfileAccessTokenClient) GetSignatureKeyID() (kid string) {
	return r.client.GetAccessTokenSignedResponseKeyID()
}

func (r *RecipientJWTProfileAccessTokenClient) GetSignatureAlg() (alg string) {
	return r.client.GetAccessTokenSignedResponseAlg()
}

func (r *RecipientJWTProfileAccessTokenClient) GetEncryptionKeyID() (kid string) {
	return r.client.GetAccessTokenEncryptedResponseKeyID()
}

func (r *RecipientJWTProfileAccessTokenClient) GetEncryptionAlg() (alg string) {
	return r.client.GetAccessTokenEncryptedResponseAlg()
}

func (r *RecipientJWTProfileAccessTokenClient) GetEncryptionEnc() (enc string) {
	return r.client.GetAccessTokenEncryptedResponseEnc()
}

func (r *RecipientJWTProfileAccessTokenClient) GetJSONWebKeySet() (jwks *jose.JSONWebKeySet) {
	return r.client.GetJSONWebKeys()
}

func (r *RecipientJWTProfileAccessTokenClient) GetHaveSignaturePrivateKey() (have bool) {
	return true
}

func (r *RecipientJWTProfileAccessTokenClient) GetHaveEncryptionPrivateKey() (have bool) {
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

	KeyProvider
}

type RecipientIntrospectionClient struct {
	client IntrospectionClient
}

func (r *RecipientIntrospectionClient) GetSignatureKeyID() (kid string) {
	return r.client.GetIntrospectionSignedResponseKeyID()
}

func (r *RecipientIntrospectionClient) GetSignatureAlg() (alg string) {
	return r.client.GetIntrospectionSignedResponseAlg()
}

func (r *RecipientIntrospectionClient) GetEncryptionKeyID() (kid string) {
	return r.client.GetIntrospectionEncryptedResponseKeyID()
}

func (r *RecipientIntrospectionClient) GetEncryptionAlg() (alg string) {
	return r.client.GetIntrospectionEncryptedResponseAlg()
}

func (r *RecipientIntrospectionClient) GetEncryptionEnc() (enc string) {
	return r.client.GetIntrospectionEncryptedResponseEnc()
}

func (r *RecipientIntrospectionClient) GetJSONWebKeySet() (jwks *jose.JSONWebKeySet) {
	return r.client.GetJSONWebKeys()
}

func (r *RecipientIntrospectionClient) GetHaveSignaturePrivateKey() (have bool) {
	return true
}

func (r *RecipientIntrospectionClient) GetHaveEncryptionPrivateKey() (have bool) {
	return true
}

type KeyType int

const (
	Private KeyType = iota
	Ingress
)

type KeyProvider interface {
	// GetJSONWebKeys returns the JSON Web Key Set containing the public key used by the client to authenticate.
	GetJSONWebKeys() (jwks *jose.JSONWebKeySet)
}
