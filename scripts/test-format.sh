#!/bin/bash

# SPDX-FileCopyrightText: 2026 Authelia
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd "$( dirname "${BASH_SOURCE[0]}" )/.."

toformat=$(go list -f '{{.Dir}}' ./... | grep -v vendor | grep -v 'fosite$' | xargs goimports -l)
[ -z "${toformat}" ] && echo "All files are formatted correctly"
[ -n "${toformat}" ] && echo "Please use \`goimports\` to format the following files:" && echo "${toformat}" && exit 1

exit 0
