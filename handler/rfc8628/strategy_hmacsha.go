package rfc8628

import (
	"context"
	"fmt"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/internal/randx"
	enigma "authelia.com/provider/oauth2/token/hmac"
)

func NewRFC8628HMACSHAStrategy(enigma *enigma.HMACStrategy, config oauth2.DeviceAuthorizeConfigProvider, prefix string) *RFC8628HMACSHAStrategy {
	return &RFC8628HMACSHAStrategy{
		Enigma: enigma,
		Config: config,
		prefix: prefix,
	}
}

type RFC8628HMACSHAStrategy struct {
	Enigma *enigma.HMACStrategy
	Config interface {
		oauth2.DeviceAuthorizeConfigProvider
	}

	prefix string
}

func (h *RFC8628HMACSHAStrategy) GenerateUserCode(ctx context.Context) (token string, signature string, err error) {
	seq, err := randx.RuneSequence(8, []rune("BCDFGHJKLMNPQRSTVWXZ"))
	if err != nil {
		return "", "", err
	}

	userCode := string(seq)

	signUserCode, err := h.UserCodeSignature(ctx, userCode)
	if err != nil {
		return "", "", err
	}

	return userCode, signUserCode, nil
}

func (h *RFC8628HMACSHAStrategy) UserCodeSignature(ctx context.Context, token string) (signature string, err error) {
	return h.Enigma.GenerateHMACForString(ctx, token)
}

func (h *RFC8628HMACSHAStrategy) ValidateUserCode(ctx context.Context, r oauth2.Requester, code string) (err error) {
	var exp = r.GetSession().GetExpiresAt(oauth2.UserCode)

	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHintf("User code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHintf("User code expired at '%s'.", exp))
	}

	return nil
}

func (h *RFC8628HMACSHAStrategy) GenerateDeviceCode(ctx context.Context) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return h.getPrefix("dc") + token, sig, nil
}

func (h *RFC8628HMACSHAStrategy) DeviceCodeSignature(ctx context.Context, token string) (signature string, err error) {
	return h.Enigma.Signature(token), nil
}

func (h *RFC8628HMACSHAStrategy) ValidateDeviceCode(ctx context.Context, r oauth2.Requester, code string) (err error) {
	var exp = r.GetSession().GetExpiresAt(oauth2.DeviceCode)

	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHintf("Device code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHintf("Device code expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, strings.TrimPrefix(code, h.getPrefix("dc")))
}

func (h *RFC8628HMACSHAStrategy) getPrefix(part string) string {
	if len(h.prefix) == 0 {
		return ""
	}

	return fmt.Sprintf(h.prefix, part)
}

var (
	_ RFC8628CodeStrategy = (*RFC8628HMACSHAStrategy)(nil)
)
