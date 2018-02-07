# srp – A Go package for Secure Remote Password

[![GoDoc: Reference](https://godoc.org/github.com/agilebits/srp?status.svg)](https://godoc.org/github.com/agilebits/srp) [![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)


srp is a [Go language](https://golang.org) package for Secure Remote Password (SRP). It is an implementation of:

* [RFC 2945: The SRP Authentication and Key Exchange System](https://tools.ietf.org/html/rfc2945)
* [RFC 5054: Using the Secure Remote Password (SRP) Protocol for TLS Authentication](https://tools.ietf.org/html/rfc5054)

However, the hashing and padding scheme in this package is not interoperable with those specs.

It was developed by AgileBits to support part of the authentication process using in [1Password](https://1password.com/). Although there are some specific hooks and interfaces designed specifically for those purposes, this golang package may be of general use to others.

## Get started

To install srp, use `go get`:

```bash
go get github.com/agilebits/srp
```

Although the focus of this implementation is safety and ease of use (as opposed to speed), like all cryptographic tools, some understanding of its operation is required to not shoot yourself in the foot.

**Read the [package documentation](https://godoc.org/github.com/agilebits/srp) for a discussion of user security responsibilities.**

## Contribute

Issues are appreciated. Forks leading to pull requests are appreciated even more. 😎