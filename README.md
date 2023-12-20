## Fork

This is a hard fork of [ORY Fosite](https://github.com/ory/fosite) under the [Apache 2.0 License](LICENSE) for the 
purpose of performing self-maintenance of this critical dependency.

We however:

* Acknowledge the amazing hard work of the ORY developers in making such an amazing framework that we can do this with.
* Plan to continue to contribute back to te ORY Fosite and related projects.
* Have ensured the licensing is unchanged in this fork of the library.
* Do not have a formal affiliation with ORY and individuals utilizing this library should not allow their usage to be
  a reflection on ORY as this library is not maintained by them.

## Notable Differences

In an effort to assist users who wish to use this library we aim to maintain the following list of differences:

* Module path changed from `github.com/ory/fosite` to `github.com/authelia/oauth2`.
* Minimum dependency is go version 1.21.
* Removal of the following dependencies:
  * `go.opentelemetry.io/otel`
* Migration of the following dependencies:
  * `github.com/golang/mock` => `github.com/uber-go/mock`

## TODO

* Consolidate JWT and JOSE dependencies
* Remove unecessary dependencies and/or abstract them
* Apply downstream fixes
