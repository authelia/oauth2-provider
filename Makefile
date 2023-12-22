format: .bin/goimports-reviser node_modules  # formats the source code
	.bin/goimports-reviser -rm-unused -recursive .
	npm exec -- prettier --write .

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

node_modules: package-lock.json
	npm ci
	touch node_modules

.DEFAULT_GOAL := help
