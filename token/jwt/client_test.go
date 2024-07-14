package jwt

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

type testClient struct {
	secret              []byte
	kid, alg            string
	encKID, encAlg, enc string
	csigned             bool
	jwks                *jose.JSONWebKeySet
	jwksURI             string
}

func (r *testClient) GetClientSecretPlainText() (secret []byte, err error) {
	if r.secret != nil {
		return r.secret, nil
	}

	return nil, fmt.Errorf("not supported")
}

func (r *testClient) GetSignatureKeyID() (kid string) {
	return r.kid
}

func (r *testClient) GetSignatureAlg() (alg string) {
	return r.alg
}

func (r *testClient) GetEncryptionKeyID() (kid string) {
	return r.encKID
}

func (r *testClient) GetEncryptionAlg() (alg string) {
	return r.encAlg
}

func (r *testClient) GetEncryptionEnc() (enc string) {
	return r.enc
}

func (r *testClient) IsClientSigned() (is bool) {
	return r.csigned
}

func (r *testClient) GetJSONWebKeys() (jwks *jose.JSONWebKeySet) {
	return r.jwks
}

func (r *testClient) GetJSONWebKeysURI() (uri string) {
	return r.jwksURI
}
