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

.bin/goimports-reviser: Makefile
	GOBIN=$(shell pwd)/.bin go install github.com/incu6us/goimports-reviser/v3@latest

.bin/mockgen: Makefile
	GOBIN=$(shell pwd)/.bin go install go.uber.org/mock/mockgen@latest

node_modules: pnpm-lock.yaml
	pnpm install --fix-lockfile

.DEFAULT_GOAL := help
