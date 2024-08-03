package jwt

import (
	"context"
	"errors"

	"github.com/go-jose/go-jose/v4"

	"authelia.com/provider/oauth2/internal/consts"
)

func NewDefaultIssuer(keys ...jose.JSONWebKey) (issuer *DefaultIssuer, err error) {
	jwks := &jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, len(keys)),
	}

	hasRS256 := false

	for i, key := range keys {
		jwks.Keys[i] = key

		if key.Use != consts.JSONWebTokenUseSignature {
			continue
		}

		if key.Algorithm != string(jose.RS256) {
			continue
		}

		hasRS256 = true
	}

	if !hasRS256 {
		return nil, errors.New("no RS256 signature algorithm found")
	}

	return issuer, nil
}

type DefaultIssuer struct {
	jwks *jose.JSONWebKeySet
}

func (i *DefaultIssuer) GetJSONWebKeys(ctx context.Context) (jwks *jose.JSONWebKeySet, err error) {
	return i.jwks, nil
}

type Issuer interface {
	GetJSONWebKeys(ctx context.Context) (jwks *jose.JSONWebKeySet, err error)
}
