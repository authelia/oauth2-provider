// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

module authelia.com/provider/oauth2

go 1.25.0

toolchain go1.27.1

require (
	github.com/dgraph-io/ristretto v0.2.0
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/hashicorp/go-retryablehttp v0.7.8
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.12.1
	go.uber.org/mock v0.6.0
	golang.org/x/crypto v0.55.0
	golang.org/x/net v0.58.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/text v0.41.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
