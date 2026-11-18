// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

// CarrySessionBindingForTest exposes carrySessionBinding to the external test package.
func CarrySessionBindingForTest(restored, session Session) {
	carrySessionBinding(restored, session)
}
