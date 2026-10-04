// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
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
	TokenExchangeGrantAccessTokenLifespan:      ptr(43 * time.Hour),
	TokenExchangeGrantRefreshTokenLifespan:     ptr(44 * time.Hour),
}

func RequireEqualDuration(t *testing.T, expected time.Duration, actual time.Duration, precision time.Duration) {
	delta := expected - actual
	if delta < 0 {
		delta = -delta
	}
	require.Less(t, delta, precision, fmt.Sprintf("expected %s; got %s", expected, actual))
}

func RequireEqualTime(t *testing.T, expected time.Time, actual time.Time, precision time.Duration) {
	t.Helper()

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

	body := findElement(doc, "body")
	if body == nil {
		return "", "", "", token, customParameters, rFC6749Error, errors.New("Malformed html")
	}

	onLoadFunc, ok := getAttr(body, "onload")
	if !ok {
		return "", "", "", token, customParameters, rFC6749Error, errors.New("onload event is missing")
	}

	if onLoadFunc != "javascript:document.forms[0].submit()" {
		return "", "", "", token, customParameters, rFC6749Error, errors.New("onload function is missing")
	}

	form := findElement(body, "form")
	if form == nil {
		return "", "", "", token, customParameters, rFC6749Error, errors.New("html form is missing")
	}

	if method, _ := getAttr(form, "method"); !strings.EqualFold(method, "post") {
		return "", "", "", token, customParameters, rFC6749Error, errors.New("html form post method is missing")
	}

	if action, _ := getAttr(form, "action"); action != redirectURL {
		return "", "", "", token, customParameters, rFC6749Error, errors.New("html form post url is wrong")
	}

	for _, node := range findElements(doc, "input") {
		if !isFormOwner(form, node) || !isSubmitted(node) {
			continue
		}

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

func getAttr(node *html.Node, key string) (string, bool) {
	for _, attr := range node.Attr {
		if attr.Key == key {
			return attr.Val, true
		}
	}

	return "", false
}

func isFormOwner(form, node *html.Node) bool {
	if owner, ok := getAttr(node, "form"); ok {
		id, _ := getAttr(form, "id")

		return id != "" && id == owner
	}

	for parent := node.Parent; parent != nil; parent = parent.Parent {
		if parent == form {
			return true
		}
	}

	return false
}

func isSubmitted(node *html.Node) bool {
	if name, _ := getAttr(node, "name"); name == "" {
		return false
	}

	if _, disabled := getAttr(node, "disabled"); disabled {
		return false
	}

	for parent := node.Parent; parent != nil; parent = parent.Parent {
		if parent.Type != html.ElementNode || parent.Data != "fieldset" {
			continue
		}

		if _, disabled := getAttr(parent, "disabled"); disabled {
			return false
		}
	}

	switch kind, _ := getAttr(node, "type"); strings.ToLower(kind) {
	case "submit", "button", "reset", "image":
		return false
	case "checkbox", "radio":
		_, checked := getAttr(node, "checked")

		return checked
	}

	return true
}

func findElement(node *html.Node, tag string) *html.Node {
	if elements := findElements(node, tag); len(elements) != 0 {
		return elements[0]
	}

	return nil
}

func findElements(node *html.Node, tag string) (elements []*html.Node) {
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.ElementNode && child.Data == "template" {
			continue
		}

		if child.Type == html.ElementNode && child.Data == tag {
			elements = append(elements, child)
		}

		elements = append(elements, findElements(child, tag)...)
	}

	return elements
}
