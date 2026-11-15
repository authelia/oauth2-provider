#!/bin/bash

# SPDX-FileCopyrightText: 2026 Authelia
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd "$( dirname "${BASH_SOURCE[0]}" )/.."

go list -f '{{.Dir}}' ./... | grep -v vendor | grep -v 'fosite$' | xargs goimports -w
goimports -w ./*.go
