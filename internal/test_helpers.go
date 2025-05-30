// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
	xoauth2 "golang.org/x/oauth2"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func ptr(d time.Duration) *time.Duration {
	return &d
}

var TestLifespans = oauth2.ClientLifespanConfig{
	AuthorizationCodeGrantAccessTokenLifespan:  ptr(31 * time.Hour),
	AuthorizationCodeGrantIDTokenLifespan:      ptr(32 * time.Hour),
	AuthorizationCodeGrantRefreshTokenLifespan: ptr(33 * time.Hour),
	ClientCredentialsGrantAccessTokenLifespan:  ptr(34 * time.Hour),
	ImplicitGrantAccessTokenLifespan:           ptr(35 * time.Hour),
	ImplicitGrantIDTokenLifespan:               ptr(36 * time.Hour),
	JwtBearerGrantAccessTokenLifespan:          ptr(37 * time.Hour),
	PasswordGrantAccessTokenLifespan:           ptr(38 * time.Hour),
	PasswordGrantRefreshTokenLifespan:          ptr(39 * time.Hour),
	RefreshTokenGrantIDTokenLifespan:           ptr(40 * time.Hour),
	RefreshTokenGrantAccessTokenLifespan:       ptr(41 * time.Hour),
	RefreshTokenGrantRefreshTokenLifespan:      ptr(42 * time.Hour),
}

func RequireEqualDuration(t *testing.T, expected time.Duration, actual time.Duration, precision time.Duration) {
	delta := expected - actual
	if delta < 0 {
		delta = -delta
	}
	require.Less(t, delta, precision, fmt.Sprintf("expected %s; got %s", expected, actual))
}

func RequireEqualTime(t *testing.T, expected time.Time, actual time.Time, precision time.Duration) {
	delta := expected.Sub(actual)
	if delta < 0 {
		delta = -delta
	}
	require.Less(t, delta, precision, fmt.Sprintf(
		"expected %s; got %s",
		expected.Format(time.RFC3339Nano),
		actual.Format(time.RFC3339Nano),
	))
}

func ExtractJwtExpClaim(t *testing.T, token string) *time.Time {
	claims := &jwt.IDTokenClaims{}

	_, err := jwt.UnsafeParseSignedAny(token, claims)

	require.NoError(t, err)

	if claims.ExpirationTime == nil {
		return nil
	}

	return &claims.ExpirationTime.Time
}

//nolint:gocyclo
func ParseFormPostResponse(redirectURL string, resp io.ReadCloser) (authorizationCode, stateFromServer, iDToken string, token xoauth2.Token, customParameters url.Values, rFC6749Error map[string]string, err error) {
	token = xoauth2.Token{}
	rFC6749Error = map[string]string{}
	customParameters = url.Values{}

	doc, err := html.Parse(resp)
	if err != nil {
		return "", "", "", token, customParameters, rFC6749Error, err
	}

	body := findBody(doc.FirstChild.FirstChild)
	if body.Data != "body" {
		return "", "", "", token, customParameters, rFC6749Error, errors.New("Malformed html")
	}

	htmlEvent := body.Attr[0].Key
	if htmlEvent != "onload" {
		return "", "", "", token, customParameters, rFC6749Error, errors.New("onload event is missing")
	}

	onLoadFunc := body.Attr[0].Val
	if onLoadFunc != "javascript:document.forms[0].submit()" {
		return "", "", "", token, customParameters, rFC6749Error, errors.New("onload function is missing")
	}

	form := getNextNoneTextNode(body.FirstChild)
	if form.Data != "form" {
		return "", "", "", token, customParameters, rFC6749Error, errors.New("html form is missing")
	}

	for _, attr := range form.Attr {
		if attr.Key == "method" {
			if attr.Val != "post" {
				return "", "", "", token, customParameters, rFC6749Error, errors.New("html form post method is missing")
			}
		} else {
			if attr.Val != redirectURL {
				return "", "", "", token, customParameters, rFC6749Error, errors.New("html form post url is wrong")
			}
		}
	}

	for node := getNextNoneTextNode(form.FirstChild); node != nil; node = getNextNoneTextNode(node.NextSibling) {
		var k, v string

		for _, attr := range node.Attr {
			switch attr.Key {
			case "name":
				k = attr.Val
			case "value":
				v = attr.Val
			}
		}

		switch k {
		case consts.FormParameterState:
			stateFromServer = v
		case consts.FormParameterAuthorizationCode:
			authorizationCode = v
		case consts.AccessResponseExpiresIn:
			expires, err := strconv.Atoi(v)
			if err != nil {
				return "", "", "", token, customParameters, rFC6749Error, err
			}
			token.Expiry = time.Now().UTC().Add(time.Duration(expires) * time.Second)
		case consts.AccessResponseTokenType:
			token.TokenType = v
		case consts.AccessResponseAccessToken:
			token.AccessToken = v
		case consts.AccessResponseRefreshToken:
			token.RefreshToken = v
		case consts.AccessResponseIDToken:
			iDToken = v
		case consts.FormParameterError:
			rFC6749Error["ErrorField"] = v
		case consts.FormParameterErrorHint:
			rFC6749Error["HintField"] = v
		case consts.FormParameterErrorDescription:
			rFC6749Error["DescriptionField"] = v
		default:
			customParameters.Add(k, v)
		}
	}

	return
}

func getNextNoneTextNode(node *html.Node) *html.Node {
	nextNode := node.NextSibling
	if nextNode != nil && nextNode.Type == html.TextNode {
		nextNode = getNextNoneTextNode(node.NextSibling)
	}

	return nextNode
}

func findBody(node *html.Node) *html.Node {
	if node != nil {
		if node.Data == "body" {
			return node
		}
		return findBody(node.NextSibling)
	}

	return nil
}
