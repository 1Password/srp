# srp – A Go package for Secure Remote Password

This golang for Secure Remote Password (SRP) from RFCs [2945](https://www.ietf.org/rfc/rfc2945.txt) and [5054](https://tools.ietf.org/html/rfc5054#ref-SRP-RFC). However its hashing and padding scheme differs from those and is is not inter-operable with them.

## Install

```bash
go get github.com/agilebits/srp
```

## Docs

The package includes extensive documentation.

Use your favorate way of reading go package documentation, including

- [![GoDoc](https://godoc.org/github.com/agilebits/srp?status.svg)](https://godoc.org/github.com/agilebits/srp) at https://godoc.org/github.com/agilebits/srp

Be sure to read the package documentation and the example(s). Although this has been designed with safety and ease of use in mind (instead of speed), like all cryptographic tools, some understanding of its operation is required to not shoot yourself in the foot. See the package documentation for a discussion of user security responsibilities.

## History

This was developed by AgileBits to support the authentication process used in as part of the authentication process using in [1Password](1Password.com). Although there are some specific hooks and interfaces designed specifically for those purposes, this golang package may be of general use to others.

## Contributing

Please create issues, and better still forks leading to pull requests for improvements.

## License

Apache License version 2. See [LICENSE](LICENSE.md)