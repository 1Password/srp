/**
 ** Copyright 2017 AgileBits, Inc.
 ** Licensed under the Apache License, Version 2.0 (the "License").
 **/

/*
Package srp Secure Remote Password protocol

The principal interface provided by this package is the SRP type. The end aim
of the caller is to to have an SRP server and SRP client arrive at the same
Key. See the documentation for the SRP structure and its methods for the nitty
gritty of use.

BUG(jpg): This does not use the same padding and hashing scheme as in RFC 5054,
and therefore is not interoperable with those clients and servers. Perhaps someday
we'll add an RFC 5054 mode that does that, but today is not that day.

The SRP protocol

It would be nice if this package could be used without having some understanding of the SRP protocol,
but too much of the language and naming depends on at least some familiarity. Here is a summary.

The Secure Remote Password protocol involves a server and a client proving to
each other that they know (or can derive) their long term secrets.
The client long term secret is known as "x" and the corresponding server secret,
the verifier, is known as "v". The verifier is mathematically related to x and is
computed by the client on first enrollment and transmitted to the server.

Typically the server will store the verifier and the client will derive x from a user
secret such as a password. Because the verifier can used like a password hash with
respect to cracking, the derivation of x should be designed to resist password cracking
if the verifier is compromised.

The client and the server must both use the same Diffie-Hellman group to perform
their computations.

The server and the client each send an ephemeral public key to each other
(The client sends A; the server sends B)
With their private knowledge of their own ephemeral secrets (a or b) and their
private knowledge of x (for the client) and v (for the server) along with public
knowledge they are able to prove to each other that they know their respective
secrets and can generate a session key, K, which may be used for further encryption
during the session.

Quoting from http://srp.stanford.edu/design.html (with some modification
for KDF)

    Names and notation
	N    A large safe prime (N = 2q+1, where q is prime)
	     All arithmetic is done modulo N.
  	g    A generator modulo N
  	k    Multiplier parameter (k = H(N, g) in SRP-6a;
             k = 3 for legacy SRP-6; k is a hash of the session ID within 1Password
  	H()  One-way hash function
  	^    (Modular) Exponentiation
  	u    Random scrambling parameter
  	a,b  Secret ephemeral values
  	A,B  Public ephemeral values
  	x    Long term client secret (derived via KDF)
	v    Long term server Verifier (derived from x)
	s    Salt for key derivation function
	I    User identifiers (username, account ID, etc)
	KDF()    Key Derivation Function

    The authentication protocol itself goes as follows

	User -> Host:  I, A = g^a                  (identifies self, a = random number)
	Host -> User:  s, B = kv + g^b             (sends salt, b = random number)

	Both:  u = H(A, B)

	User:  x = KDF(s, ...)             (user derives x)
	User:  S = (B - kg^x) ^ (a + ux)   (computes raw session key)
	User:  K = H(S)                    (computes session key)

	Host:  S = (Av^u) ^ b              (computes raw session key)
	Host:  K = H(S)                    (computes session key)

    Now the two parties have a shared, strong session key K.
    To complete authentication, they need to prove to each other that their keys match.

This package does not address the actual communication between client and
server. But through the SRP type it not only performs the calculations needed,
it also performs safety and sanity checks on its input, and it hides everything
from the caller except what the caller absolutely needs to provide.

The key derivation function, KDF()

	x is computed by the client via KDF, user secrets, and random salt, s.

	x = KDF(...)
	v = g^x

	v is sent to the server on first enrollment. v should be transmitted over a secure channel.
	The server then stores {I, s, v} long term. v needs to be protected in the same way that
	a password hash should be protected.

User's security responsibilities

The consumer is responsible for

1. Both client and server: Checking whether methods have returned without error.
This is particularly true of SRP.Key() and SetOthersPublic()

2. Client: Using an appropriate key derivation function for deriving x
from the user's password (and nudging user toward a good password)

3. Server: Storing the v securely (sent by the client on first enrollment).
A captured v can be used to masquerade as the server and be used like a password hash in a password cracking attempt

4. Both: Proving to each other that both have the same key. The package includes methods
that can assist with that.
*/
package srp // import "github.com/1password/srp"

// This file is just for the package documentation
