// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package i18n

import (
	"net/http"

	"golang.org/x/text/language"
)

// MessageCatalog declares the interface to get globalized messages
type MessageCatalog interface {
	GetMessage(ID string, tag language.Tag, v ...any) string
	GetLangFromRequest(r *http.Request) language.Tag
}

// GetMessage is a helper func to get the translated message based on
// the message ID and lang. If no matching message is found, it uses
// ID as the message itself.
func GetMessage(c MessageCatalog, id string, tag language.Tag, v ...any) string {
	return GetMessageOrDefault(c, id, tag, id, v...)
}

// GetMessageOrDefault is a helper func to get the translated message based on
// the message ID and lang. If no matching message is found, it returns the
// 'def' message.
func GetMessageOrDefault(c MessageCatalog, id string, tag language.Tag, def string, v ...any) string {
	if c != nil {
		if s := c.GetMessage(id, tag, v...); s != id {
			return s
		}
	}

	return def
}

// GetLangFromRequest is a helper func to get the language tag based on the
// HTTP request and the constructed message catalog.
func GetLangFromRequest(c MessageCatalog, r *http.Request) language.Tag {
	if c != nil {
		return c.GetLangFromRequest(r)
	}

	return language.English
}
