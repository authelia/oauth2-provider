// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"github.com/pkg/errors"
	"golang.org/x/text/language"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/x/errorsx"
)

// AddLocalizerToErr augments the error object with the localizer
// based on the language set in the requester object. This is primarily
// required for response writers like introspection that do not take in
// the requester in the Write* function that produces the translated
// message.
// See - WriteIntrospectionError, for example.
func AddLocalizerToErr(catalog i18n.MessageCatalog, err error, requester Requester) error {
	return AddLocalizerToErrWithLang(catalog, getLangFromRequester(requester), err)
}

// AddLocalizerToErrWithLang augments the error object with the localizer
// based on the language passed in. This is primarily
// required for response writers like introspection that do not take in
// the requester in the Write* function that produces the translated
// message.
// See - WriteIntrospectionError, for example.
func AddLocalizerToErrWithLang(catalog i18n.MessageCatalog, lang language.Tag, err error) error {
	var e RFC6749Error
	if errors.As(err, &e) {
		return e.WithLocalizer(catalog, lang)
	} else if errors.As(errorsx.Cause(err), &e) {
		return e.WithLocalizer(catalog, lang)
	}
	return err
}

func getLangFromRequester(requester Requester) language.Tag {
	lang := language.English
	g11nContext, ok := requester.(G11NContext)
	if ok {
		lang = g11nContext.GetLang()
	}

	return lang
}
