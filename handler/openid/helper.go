// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"strconv"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

type IDTokenHandleHelper struct {
	IDTokenStrategy OpenIDConnectTokenStrategy
}

func (i *IDTokenHandleHelper) GetAccessTokenHash(ctx context.Context, requester oauth2.AccessRequester, responder oauth2.AccessResponder) (sum string) {
	var err error

	token := responder.GetAccessToken()
	if session, ok := requester.GetSession().(Session); ok {
		if sum, err = i.ComputeHash(ctx, session, token); err != nil {
			// The Digest function Write always returns nil for err, the panic should never happen.
			panic(err)
		}

		return sum
	}

	buffer := bytes.NewBufferString(token)
	h := sha256.New()

	if _, err = h.Write(buffer.Bytes()); err != nil {
		// The sha256.Digest function Write always returns nil for err, the panic should never happen.
		panic(err)
	}

	hashBuf := bytes.NewBuffer(h.Sum([]byte{}))

	return base64.RawURLEncoding.EncodeToString(hashBuf.Bytes()[:hashBuf.Len()/2])
}

func (i *IDTokenHandleHelper) generateIDToken(ctx context.Context, lifespan time.Duration, requester oauth2.Requester) (token string, err error) {
	if token, err = i.IDTokenStrategy.GenerateIDToken(ctx, lifespan, requester); err != nil {
		return "", err
	}

	return token, nil
}

func (i *IDTokenHandleHelper) IssueImplicitIDToken(ctx context.Context, lifespan time.Duration, requester oauth2.Requester, responder oauth2.AuthorizeResponder) (err error) {
	var token string

	if token, err = i.generateIDToken(ctx, lifespan, requester); err != nil {
		return err
	}

	responder.AddParameter(consts.AccessResponseIDToken, token)

	return nil
}

func (i *IDTokenHandleHelper) IssueExplicitIDToken(ctx context.Context, lifespan time.Duration, requester oauth2.Requester, responder oauth2.AccessResponder) (err error) {
	var token string

	if token, err = i.generateIDToken(ctx, lifespan, requester); err != nil {
		return err
	}

	responder.SetExtra(consts.AccessResponseIDToken, token)

	return nil
}

// ComputeHash computes the hash using the alg defined in the id_token header
func (i *IDTokenHandleHelper) ComputeHash(_ context.Context, session Session, token string) (sum string, err error) {
	var h hash.Hash

	if alg, ok := session.IDTokenHeaders().Get(consts.JSONWebTokenHeaderAlgorithm).(string); ok && len(alg) > 2 {
		var bits int

		if bits, err = strconv.Atoi(alg[2:]); err == nil {
			switch bits / 8 {
			case sha512.Size:
				h = sha512.New()
			case sha512.Size384:
				h = sha512.New384()
			case sha512.Size256:
				h = sha256.New()
			}
		}
	}

	if h == nil {
		h = sha256.New()
	}

	buffer := bytes.NewBufferString(token)

	if _, err = h.Write(buffer.Bytes()); err != nil {
		return "", err
	}

	hashBuf := bytes.NewBuffer(h.Sum([]byte{}))

	return base64.RawURLEncoding.EncodeToString(hashBuf.Bytes()[:hashBuf.Len()/2]), nil
}
