package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"github.com/go-jose/go-jose/v4"

	"authelia.com/provider/oauth2/internal/consts"
)

type Strategy interface {
	Signer

	// GenerateWithSettings signs and optionally encrypts the token based on the context provided
	GenerateWithSettings(ctx context.Context, settings *StrategySettings, claims MapClaims, header Mapper) (tokenString, signature string, err error)

	// DecryptWithSettings decrypts the token provided. If the token is not encrypted, the function should return an error.
	DecryptWithSettings(ctx context.Context, settings *StrategySettings, token string) (tokenString string, err error)

	// ValidateWithSettings validates the signed token. If the token is not signed, the function should return an error.
	ValidateWithSettings(ctx context.Context, settings *StrategySettings, token string) (signature string, err error)
}

// StrategySettings contains context that is used to sign, validation, encrypt and decrypt tokens.
// It is populated in different ways depending on the operation. For example -
//
// 1. Validate	: the SigningKeyID and SigningAlgorithm is based on the JWT header of the incoming token
// 2. Decrypt	: the EncryptionKeyID, EncryptionAlgorithm and EncryptionContentAlgorithm is based on the JWT header of the incoming token
// 3. Generate  : all the properties may be populated. The JWT strategy implementation may sign the token, then optionally encrypt it
type StrategySettings struct {
	SigningKeyID               string
	SigningAlgorithm           string
	EncryptionKeyID            string
	EncryptionAlgorithm        string
	EncryptionContentAlgorithm string
	Extra                      map[string]any
}

type GetPrivateKeyWithSettingsFunc func(ctx context.Context, context *StrategySettings) (key any, err error)

type DefaultStrategy struct {
	Signer

	GetPrivateKey GetPrivateKeyWithSettingsFunc
}

func NewDefaultStrategy(GetPrivateKey GetPrivateKeyWithSettingsFunc) Strategy {
	return &DefaultStrategy{
		Signer: &DefaultSigner{
			GetPrivateKey: func(ctx context.Context) (key any, err error) {
				return GetPrivateKey(ctx, nil)
			},
		},
		GetPrivateKey: GetPrivateKey,
	}
}

// GenerateWithSettings signs and optionally encrypts the token based on the context provided
func (s *DefaultStrategy) GenerateWithSettings(ctx context.Context, settings *StrategySettings, claims MapClaims, header Mapper) (tokenString, signature string, err error) {
	// ignoring the signing alg and kid for this implementation and just using the DefaultSigner implementation
	rawToken, sig, err := s.Signer.Generate(ctx, claims, header)
	if err != nil {
		return "", "", err
	}

	if settings.EncryptionAlgorithm == "" {
		return rawToken, sig, err
	}

	key, err := s.GetPrivateKey(ctx, settings)
	if err != nil {
		return "", "", err
	}

	if t, ok := key.(*jose.JSONWebKey); ok {
		key = t.Key
	}

	var pubKey any
	switch t := key.(type) {
	case *rsa.PrivateKey:
		pubKey = &t.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &t.PublicKey
	case jose.OpaqueSigner:
		pubKey = t.Public()
	default:
		return "", "", fmt.Errorf("unable to decode token. Invalid PrivateKey type %T", key)
	}

	cty := consts.JSONWebTokenTypeJWT

	if typ := header.Get(consts.JSONWebTokenHeaderType); typ != nil {
		if value, ok := typ.(string); ok && value != "" {
			cty = value
		}
	}

	opts := &jose.EncrypterOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			consts.JSONWebTokenHeaderType:        jose.ContentType(consts.JSONWebTokenTypeJWT),
			consts.JSONWebTokenHeaderContentType: jose.ContentType(cty),
		},
	}

	var (
		encrypter jose.Encrypter
		jwe       *jose.JSONWebEncryption
	)

	enc := jose.ContentEncryption(settings.EncryptionContentAlgorithm)

	recipient := jose.Recipient{
		Algorithm: jose.KeyAlgorithm(settings.EncryptionAlgorithm),
		Key:       pubKey,
		KeyID:     settings.EncryptionKeyID,
	}

	if encrypter, err = jose.NewEncrypter(enc, recipient, opts); err != nil {
		return "", "", fmt.Errorf("unable to build encrypter; err=%v", err)
	}

	if jwe, err = encrypter.Encrypt([]byte(rawToken)); err != nil {
		return "", "", fmt.Errorf("encrypting the token failed. err=%v", err)
	}

	if rawToken, err = jwe.CompactSerialize(); err != nil {
		return "", "", fmt.Errorf("serializing the encrypted token failed. err=%v", err)
	}

	return rawToken, sig, err
}

// DecryptWithSettings decrypts the token provided. If the token is not encrypted, the function should return an error.
func (s *DefaultStrategy) DecryptWithSettings(ctx context.Context, settings *StrategySettings, token string) (tokenString string, err error) {
	parsedToken, err := jose.ParseEncrypted(token, []jose.KeyAlgorithm{jose.RSA1_5, jose.RSA_OAEP_256, jose.A128KW, jose.A192KW, jose.A256KW, jose.DIRECT, jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW, jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW}, []jose.ContentEncryption{jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512, jose.A128GCM, jose.A192GCM, jose.A256GCM})
	if err != nil {
		return "", fmt.Errorf("unable to parse the token")
	}

	if settings == nil {
		h := parsedToken.Header
		enc, _ := h.ExtraHeaders[consts.JSONWebTokenHeaderEncryptionAlgorithm].(string)
		settings = &StrategySettings{
			EncryptionKeyID:            h.KeyID,
			EncryptionAlgorithm:        h.Algorithm,
			EncryptionContentAlgorithm: enc,
		}
	}

	var privateKey any

	key, err := s.GetPrivateKey(ctx, settings)
	switch t := key.(type) {
	case *jose.JSONWebKey:
		privateKey = t.Key
	case jose.JSONWebKey:
		privateKey = t.Key
	case *rsa.PrivateKey:
		privateKey = t
	case *ecdsa.PrivateKey:
		privateKey = t
	case jose.OpaqueSigner:
		switch tt := t.Public().Key.(type) {
		case *rsa.PrivateKey:
			privateKey = t
		case *ecdsa.PrivateKey:
			privateKey = t
		default:
			return "", fmt.Errorf("unsupported private / public key pairs: %T, %T", t, tt)
		}
	default:
		return "", fmt.Errorf("unsupported private key type: %T", t)
	}

	decrypted, err := parsedToken.Decrypt(privateKey)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

// ValidateWithSettings validates the signed token. If the token is not signed, the function should return an error.
func (s *DefaultStrategy) ValidateWithSettings(ctx context.Context, settings *StrategySettings, token string) (string, error) {
	// ignoring the signing alg and kid for this implementation and just using the DefaultSigner implementation
	return s.Signer.Validate(ctx, token)
}
