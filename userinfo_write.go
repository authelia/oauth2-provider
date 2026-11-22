// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/reflection"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// WriteUserinfoError writes an error response for the UserInfo endpoint. A rejected Access Token is answered with the
// RFC 6750 Section 3 'WWW-Authenticate' challenge and a JSON body. A request which included no Access Token is answered
// with HTTP 401 and the challenge alone, without a body or error information (RFC 6750 Section 3.1). Every other error
// is answered with a JSON body. requester may be nil.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError
// See: https://www.rfc-editor.org/rfc/rfc6750#section-3
func (f *Fosite) WriteUserinfoError(ctx context.Context, rw http.ResponseWriter, requester UserinfoRequester, err error) {
	rfc := ErrorToRFC6749Error(err)

	var r *http.Request

	if !reflection.IsNil(requester) {
		rfc = rfc.WithLocalizer(f.Config.GetMessageCatalog(ctx), requester.GetLang())

		if request, ok := requester.(*UserinfoRequest); ok {
			r = request.request
		}
	}

	if r == nil {
		r = RequestFromContext(ctx)
	}

	if IsBearerCredentialError(rfc) {
		var bare bool

		if rfc, bare = f.writeBearerAuthorizationChallenge(ctx, rw, r, rfc); bare {
			writeBareAuthorizationChallenge(rw)

			return
		}
	}

	f.writeErrorJSONRFC(ctx, rw, rfc)
}

// WriteUserinfoResponse writes the UserInfo Response. It is a JWT when the client registered a
// 'userinfo_signed_response_alg' or 'userinfo_encrypted_response_alg', carrying the 'iss' and 'aud' claims, and JSON
// otherwise. The 'sub' claim is required. Use WriteUserinfoError to send error responses.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
func (f *Fosite) WriteUserinfoResponse(ctx context.Context, rw http.ResponseWriter, requester UserinfoRequester, claims *UserinfoClaims) {
	if reflection.IsNil(requester) || reflection.IsNil(requester.GetClient()) {
		f.WriteUserinfoError(ctx, rw, requester, errorsx.WithStack(ErrServerError.WithDebug("The UserInfo Response could not be written as the request was not resolved.")))

		return
	}

	if claims == nil || claims.Subject == "" {
		f.WriteUserinfoError(ctx, rw, requester, errorsx.WithStack(ErrServerError.WithDebug("The UserInfo Response could not be written as it has no 'sub' claim.")))

		return
	}

	client := requester.GetClient()
	values := claims.ToMap()

	var (
		data        []byte
		contentType string
		err         error
	)

	if userinfoJWTResponse(client) {
		if data, err = f.encodeUserinfoJWT(ctx, client, values); err != nil {
			f.WriteUserinfoError(ctx, rw, requester, err)

			return
		}

		contentType = consts.ContentTypeApplicationJWT
	} else {
		if data, err = json.Marshal(values); err != nil {
			f.WriteUserinfoError(ctx, rw, requester, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugf("The UserInfo Response could not be encoded with error %+v.", err)))

			return
		}

		contentType = consts.ContentTypeApplicationJSON
	}

	rw.Header().Set(consts.HeaderContentType, contentType)
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	if ar := requester.GetAccessRequester(); !reflection.IsNil(ar) {
		f.writeDPoPNonceOnSuccess(ctx, rw, ar)
	}

	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(data)
}

func userinfoJWTResponse(client Client) bool {
	c, ok := client.(jwt.UserInfoClient)

	return ok && (!jwt.IsNoneAlg(c.GetUserinfoSignedResponseAlg()) || !jwt.IsNoneAlg(c.GetUserinfoEncryptedResponseAlg()))
}

// encodeUserinfoJWT encodes the claims as a JWT signed, encrypted, or both, as the client registered.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
func (f *Fosite) encodeUserinfoJWT(ctx context.Context, client Client, values map[string]any) (data []byte, err error) {
	strategy := f.Config.GetJWTStrategy(ctx)

	if strategy == nil {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The UserInfo JWT could not be generated as the server is misconfigured. The jwt.Strategy was not configured."))
	}

	issuer := f.Config.GetIssuer(ctx)

	if issuer == "" {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The UserInfo JWT could not be generated as the server is misconfigured. The issuer was not configured."))
	}

	var jti uuid.UUID

	if jti, err = uuid.NewRandom(); err != nil {
		return nil, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugf("The JTI could not be generated for the UserInfo JWT with error %+v.", err))
	}

	values[consts.ClaimIssuer] = issuer
	values[consts.ClaimAudience] = []string{client.GetID()}
	values[consts.ClaimIssuedAt] = time.Now().UTC().Unix()
	values[consts.ClaimJWTID] = jti.String()

	var token string

	if token, _, err = strategy.Encode(ctx, jwt.MapClaims(values), append(FAPI2SecurityProfileEncodeOptions(client), jwt.WithUserInfoClient(&userinfoUnsignedClient{UserInfoClient: client.(jwt.UserInfoClient)}), jwt.WithAllowUnsignedEncrypted())...); err != nil {
		return nil, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugf("The UserInfo JWT could not be generated with error %+v.", err))
	}

	return []byte(token), nil
}

// userinfoUnsignedClient reports 'none' for an omitted 'userinfo_signed_response_alg', which OpenID Connect Dynamic
// Client Registration defines as an unsigned UserInfo Response.
//
// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
type userinfoUnsignedClient struct {
	jwt.UserInfoClient
}

func (c *userinfoUnsignedClient) GetUserinfoSignedResponseAlg() (alg string) {
	if alg = c.UserInfoClient.GetUserinfoSignedResponseAlg(); alg == "" {
		return jwt.JSONWebTokenAlgNone
	}

	return alg
}

func (c *userinfoUnsignedClient) IsClientIDMetadataDocumentClient() (is bool) {
	return jwt.IsClientIDMetadataDocumentClient(c.UserInfoClient)
}

func (c *userinfoUnsignedClient) GetClientSecretExpiresAt() (expires time.Time) {
	if client, ok := c.UserInfoClient.(jwt.ExpiringClientSecretClient); ok {
		return client.GetClientSecretExpiresAt()
	}

	return time.Time{}
}
