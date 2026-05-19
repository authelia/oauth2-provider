# SPDX-FileCopyrightText: 2026 Authelia
#
# SPDX-License-Identifier: Apache-2.0

COPYRIGHT ?= Authelia
LICENSE   ?= Apache-2.0
YEAR      ?= $(shell date +%Y)
FILES     ?= $(shell git ls-files)

.PHONY: reuse-lint reuse-annotate reuse-annotate-all reuse-annotate-changed

format: format-goimports-reviser format-prettier

format-goimports-reviser: .bin/goimports-reviser
	.bin/goimports-reviser -rm-unused -recursive .

format-prettier: node_modules
	pnpm exec -- prettier --write .

generate: .bin/mockgen
	MOCKGEN=".bin/mockgen" ./generate-mocks.sh

help:
	@cat Makefile | grep '^[^ ]*:' | grep -v '^\.bin/' | grep -v '.SILENT:' | grep -v '^node_modules:' | grep -v help | sed 's/:.*#/#/' | column -s "#" -t

test:  # runs all tests
	go test ./...

# Annotate a specific set of files
reuse-annotate:
	reuse annotate \
		--copyright "$(COPYRIGHT)" \
		--license "$(LICENSE)" \
		--year "$(YEAR)" \
		$(FILES)

# Annotate every tracked file in the repo
reuse-annotate-all:
	reuse annotate \
		--copyright "$(COPYRIGHT)" \
		--license "$(LICENSE)" \
		--year "$(YEAR)" \
		--skip-unrecognised \
		$$(git ls-files)

# Annotate only files changed vs main
reuse-annotate-changed:
	reuse annotate \
		--copyright "$(COPYRIGHT)" \
		--license "$(LICENSE)" \
		--year "$(YEAR)" \
		$$(git diff --name-only --diff-filter=AM main...HEAD)

.bin/goimports-reviser: Makefile
	GOBIN=$(shell pwd)/.bin go install github.com/incu6us/goimports-reviser/v3@latest

.bin/mockgen: Makefile
	GOBIN=$(shell pwd)/.bin go install go.uber.org/mock/mockgen@latest

node_modules: pnpm-lock.yaml
	pnpm install --fix-lockfile

.DEFAULT_GOAL := help
