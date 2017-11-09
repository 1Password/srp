package srp

import "math/big"

/*
Package srp is intended to provide an interface for the computations
needed for the Secure Remote Password protocal (version 6a).

The guts of how to use this package is through the Srp type.

The Secure Remote Password protocol involves a server and a client proving to
each other that they know (or can derive) their long term secrets.
The client long term secret is known as "x" and the corresponding server secret,
the verifier, is known as "v". The verifier is mathematically related to x and is
computed by the client on first enrollment and transmistted to the server.

Typically, the server will store the verifier and the client will derive x from a user
secret such as a password. Because the verifier can used like a password hash with
respect to cracking, the derivation of x should be designed to resist password cracking
if the verifier compromised.

The client and the server must both use the same Diffie-Hellman group to peform
their computations.

The server and the client send an ephemeral public key to each other
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
  	k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  	H()  One-way hash function
  	^    (Modular) Exponentiation
  	u    Random scrambling parameter
  	a,b  Secret ephemeral values
  	A,B  Public ephemeral values
  	x    Long term client secret (derived via KDF)
	v    Long term server Verifier
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
server. But through the Srp type it not only performs the calculations needed,
it also performs safety and sanity checks on its input, and it hides everything
from the caller except what the caller absolutely needs to provide.

The key derivation function, KDF()

	v is computed by client via KDF, user secrets, and random salt, s.

	x = KDF(...)
	v = g^x

	v is sent to the server on first enrollment.
	The server then keeps {I, s, v} in its database.
*/

// NumberFromBytes converts a byte array to a number
func NumberFromBytes(bytes []byte) *big.Int {
	result := new(big.Int)
	for _, b := range bytes {
		result.Lsh(result, 8)
		result.Add(result, big.NewInt(int64(b)))
	}

	return result
}

// max of two integers
// (because go doesn't give me "a > b ? a : b" )
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
