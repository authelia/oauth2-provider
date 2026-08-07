// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
)

// WriteBearerAuthorizationChallenge sets the RFC 6750 Section 3 / RFC 9449 Section 7.1 'WWW-Authenticate' challenge
// for an endpoint acting as an OAuth 2.0 protected resource, and returns the error with its status corrected for that
// context. The caller writes the response body.
//
// r may be nil. The response writers calling this take only a context, and the request is not reliably on it: the
// handlers store it under RequestContextKey on their own derived context. A nil request means the scheme used cannot
// be established, which RFC 9449 Section 7.2 Figure 19 covers: "otherwise, both Bearer and DPoP challenges MAY be
// used to deliver error information". The challenge stays conformant either way; supplying the request only buys the
// more precise placement of Figures 16 and 18.
//
// ErrInvalidDPoPProof and ErrUseDPoPNonce are HTTP 400, which is correct at the token endpoint per RFC 9449
// Section 5, but Section 7.1 Figure 16 and Section 9 Figure 24 both require 401 at a protected resource. They are
// promoted here rather than by forking the error variables, which would change public API.
func (f *Fosite) WriteBearerAuthorizationChallenge(ctx context.Context, rw http.ResponseWriter, r *http.Request, err error) (rfc *RFC6749Error) {
	rfc = ErrorToRFC6749Error(err)

	switch rfc.ErrorField {
	case errInvalidDPoPProofName, errUseDPoPNonceName:
		rfc = rfc.WithCode(http.StatusUnauthorized)
	}

	rw.Header().Set(consts.HeaderWWWAuthenticate, f.bearerAuthorizationChallenge(ctx, r, rfc))

	// RFC 9449 Section 9: a resource server signalling that it requires a nonce must supply one, or the client has
	// nothing to retry with and the handshake cannot complete.
	if rfc.ErrorField == errUseDPoPNonceName && f.Config.GetDPoPEnabled(ctx) {
		if strategy := f.Config.GetDPoPStrategy(ctx); strategy != nil {
			if nonce, nerr := strategy.NewDPoPNonce(ctx); nerr == nil {
				rw.Header().Set(consts.HeaderDPoPNonce, nonce)
			}
		}
	}

	return rfc
}

// bearerAuthorizationChallenge composes the 'WWW-Authenticate' value per RFC 9449 Section 7.2:
//
//   - A request that carried no authentication information gets challenges with no error parameters at all
//     (Figure 17), which RFC 6750 Section 3.1 also requires. The nonce challenge is the sole exception, because a
//     client bootstrapping a nonce needs the code to know what to retry.
//   - When the scheme used can be established unambiguously, only the corresponding challenge carries the error
//     information (Figure 18 for Bearer, Figure 16 for DPoP).
//   - When it cannot, because r is nil, both carry it (Figure 19).
//   - The 'algs' parameter is always offered on the DPoP challenge (SHOULD, Section 7.1).
//   - A 'scope' parameter is offered on an insufficient_scope challenge (MAY, RFC 6750 Section 3.1).
func (f *Fosite) bearerAuthorizationChallenge(ctx context.Context, r *http.Request, rfc *RFC6749Error) (value string) {
	var scheme string

	// A nil request means the scheme is unknown rather than absent, so the error information is delivered on every
	// challenge below rather than suppressed.
	ambiguous := r == nil

	if !ambiguous {
		scheme, _, _ = strings.Cut(r.Header.Get(consts.HeaderAuthorization), " ")
	}

	var params []string

	if ambiguous || scheme != "" || rfc.ErrorField == errUseDPoPNonceName {
		params = append(params, fmt.Sprintf("error=%q", rfc.ErrorField))

		if rfc.DescriptionField != "" {
			params = append(params, fmt.Sprintf("error_description=%q", rfc.DescriptionField))
		}

		if rfc.ErrorField == errInsufficientScopeName && rfc.ScopeField != "" {
			params = append(params, fmt.Sprintf("scope=%q", rfc.ScopeField))
		}
	}

	if !f.Config.GetDPoPEnabled(ctx) {
		return challengeScheme(consts.AuthSchemeBearer, params...)
	}

	var algs string

	if a := f.Config.GetDPoPAllowedJWSAlgorithms(ctx); len(a) != 0 {
		algs = fmt.Sprintf("algs=%q", strings.Join(a, " "))
	}

	// RFC 9449 Section 9 Figure 24: a nonce challenge names the DPoP scheme only. A nonce is meaningless under the
	// Bearer scheme, so advertising Bearer alongside it would invite a retry that can never succeed.
	if rfc.ErrorField == errUseDPoPNonceName {
		return challengeScheme(consts.AuthSchemeDPoP, append(params, algs)...)
	}

	// RFC 9449 Section 7.2 Figure 19: with the scheme unestablished, both challenges deliver the error information.
	if ambiguous {
		return challengeScheme(consts.AuthSchemeBearer, params...) + ", " + challengeScheme(consts.AuthSchemeDPoP, append(params, algs)...)
	}

	if strings.EqualFold(scheme, DPoPAccessToken) {
		return challengeScheme(consts.AuthSchemeBearer) + ", " + challengeScheme(consts.AuthSchemeDPoP, append(params, algs)...)
	}

	return challengeScheme(consts.AuthSchemeBearer, params...) + ", " + challengeScheme(consts.AuthSchemeDPoP, algs)
}

// challengeScheme renders one authentication scheme and its parameters for a 'WWW-Authenticate' value, skipping any
// empty parameter so callers can pass optional ones unconditionally.
func challengeScheme(scheme string, params ...string) (value string) {
	set := make([]string, 0, len(params))

	for _, param := range params {
		if param != "" {
			set = append(set, param)
		}
	}

	if len(set) == 0 {
		return scheme
	}

	return scheme + " " + strings.Join(set, ", ")
}

// IsBearerCredentialError reports whether err is a rejection of a bearer credential presented to authorize a call,
// and so warrants a RFC 6750 Section 3 'WWW-Authenticate' challenge naming the Bearer and DPoP schemes. It is the
// predicate both protected-resource error writers use to decide whether to emit one.
//
// ErrRequestUnauthorized is excluded even though it is also an authorization failure: it is what a client
// authentication branch returns, and RFC 6749 Section 5.2 calls for a challenge matching the scheme actually
// attempted, so answering a failed Basic authentication with 'WWW-Authenticate: Bearer' would advertise the wrong
// one.
//
// ErrInvalidRequest is excluded because it is mostly a malformed method or body, which says nothing about how the
// caller authenticated.
func IsBearerCredentialError(err error) (is bool) {
	return errors.Is(err, ErrInvalidToken) ||
		errors.Is(err, ErrInsufficientScope) ||
		errors.Is(err, ErrInvalidDPoPProof) ||
		errors.Is(err, ErrUseDPoPNonce)
}
