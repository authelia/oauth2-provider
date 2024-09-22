package jwt

/*
func NewValidator(opts ...ValidatorOpt) (validator *Validator) {
	validator = &Validator{
		types: []string{consts.JSONWebTokenTypeJWT},
		nbf:   -1,
		exp:   -1,
		iat:   -1,
	}

	for _, opt := range opts {
		opt(validator)
	}

	return validator
}

type ValidatorOpt func(*Validator)

func ValidateIssuer(iss string) ValidatorOpt {
	return func(validator *Validator) {
		validator.iss = iss
	}
}

func ValidateSubject(sub string) ValidatorOpt {
	return func(validator *Validator) {
		validator.sub = sub
	}
}

func ValidateAudienceAll(aud []string) ValidatorOpt {
	return func(validator *Validator) {
		validator.audAll = aud
	}
}

func ValidateAudienceAny(aud []string) ValidatorOpt {
	return func(validator *Validator) {
		validator.audAny = aud
	}
}

func ValidateNotBefore(nbf int64) ValidatorOpt {
	return func(validator *Validator) {
		validator.nbf = nbf
	}
}

func ValidateRequireNotBefore() ValidatorOpt {
	return func(validator *Validator) {
		validator.requireNBF = true
	}
}

func ValidateExpires(exp int64) ValidatorOpt {
	return func(validator *Validator) {
		validator.exp = exp
	}
}

func ValidateRequireExpires() ValidatorOpt {
	return func(validator *Validator) {
		validator.requireEXP = true
	}
}

func ValidateIssuedAt(iat int64) ValidatorOpt {
	return func(validator *Validator) {
		validator.iat = iat
	}
}

func ValidateRequireIssuedAt() TokenValidationOption {
	return func(validator *Validator) {
		validator.requireIAT = true
	}
}

*/

/*
type Validator struct {
	types      []string
	alg        string
	kid        string
	iss        string
	sub        string
	audAll     []string
	audAny     []string
	nbf        int64
	requireNBF bool
	exp        int64
	requireEXP bool
	iat        int64
	requireIAT bool
}

func (v Validator) Validate(token *Token) (err error) {
	vErr := new(ValidationError)
	now := TimeFunc().Unix()

	if len(v.types) != 0 {
		if !validateTokenType(v.types, token.Header) {
			vErr.Inner = errors.New("token has an invalid typ")
			vErr.Errors |= ValidationErrorHeaderTypeInvalid
		}
	}

	if len(v.alg) != 0 {
		if v.alg != string(token.SignatureAlgorithm) {
			vErr.Inner = errors.New("token has an invalid alg")
			vErr.Errors |= ValidationErrorHeaderAlgorithmInvalid
		}
	}

	if len(v.kid) != 0 {
		if v.kid != token.KeyID {
			vErr.Inner = errors.New("token has an invalid kid")
			vErr.Errors |= ValidationErrorHeaderKeyIDInvalid
		}
	}

	if len(v.iss) != 0 {
		if !token.Claims.VerifyIssuer(v.iss, true) {
			vErr.Inner = errors.New("token has an invalid issuer")
			vErr.Errors |= ValidationErrorIssuer
		}
	}

	if len(v.sub) != 0 {
		if !token.Claims.VerifySubject(v.sub, true) {
			vErr.Inner = errors.New("token has an invalid subject")
			vErr.Errors |= ValidationErrorSubject
		}
	}

	if len(v.audAll) != 0 {
		if !token.Claims.VerifyAudienceAll(v.audAll, true) {
			vErr.Inner = errors.New("token has an invalid audience")
			vErr.Errors |= ValidationErrorAudience
		}
	}

	if len(v.audAny) != 0 {
		if !token.Claims.VerifyAudienceAny(v.audAny, true) {
			vErr.Inner = errors.New("token has an invalid audience")
			vErr.Errors |= ValidationErrorAudience
		}
	}

	if v.exp != -1 {
		exp := v.exp

		if exp == 0 {
			exp = now
		}

		if !token.Claims.VerifyExpiresAt(exp, v.requireEXP) {
			vErr.Inner = errors.New("token is expired")
			vErr.Errors |= ValidationErrorExpired
		}
	}

	if v.iat != -1 {
		iat := v.iat

		if iat == 0 {
			iat = now
		}

		if !token.Claims.VerifyIssuedAt(iat, v.requireIAT) {
			vErr.Inner = errors.New("token used before issued")
			vErr.Errors |= ValidationErrorIssuedAt
		}
	}

	if v.nbf != -1 {
		nbf := v.nbf

		if nbf == 0 {
			nbf = now
		}

		if !token.Claims.VerifyNotBefore(nbf, v.requireNBF) {
			vErr.Inner = errors.New("token is not valid yet")
			vErr.Errors |= ValidationErrorNotValidYet
		}
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

*/
