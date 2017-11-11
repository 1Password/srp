/*
Package srp Secure Remote Password protocol

The principle interface provided by this package is the SRP type.

Creating the SRP object with with NewSRPServer() or NewSRPClient() takes care of generating your ephemeral
secret (a or b depending on whether you are a client or server), your public
ephemeral key (A or B depending on whether you are a client or server),
the multiplier k (if nil is passed as a value for k when creating).

A typical use by a server might be something like

	server := NewSRPServer(KnownGroups[RFC5054Group4096], v, nil)

	A := getAfromYourClientConnection(...) // your code
	if result, err := server.SetOthersPublic(A); result == nil || err != nil {
		// client sent a malicious A. Kill this session now
	}

	sendBtoClientSomehow(server.EphemeralPublic())

	if sessionKey, err := server.MakeKey(); sessionKey == nil || err != nil {
		// something went wrong
	}

	// You must still prove that both server and client created the same Key.

This still leaves some work outside of what the SRP object provides.
1. The key derivation of x is not handled by this object.
2. The communication between client and server.
3. The check that both client and server have negotiated the same Key is left outside.

The SRP protocol

It would be nice if this package could be used without having some understanding of the SRP protocol,
but too much of the language and naming is depends on at least some familiarity. Here is a summary.

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
server. But through the SRP type it not only performs the calculations needed,
it also performs safety and sanity checks on its input, and it hides everything
from the caller except what the caller absolutely needs to provide.

The key derivation function, KDF()

	x is computed by client via KDF, user secrets, and random salt, s.

	x = KDF(...)
	v = g^x

	v is sent to the server on first enrollment. v should be transmitted over a secure channel.
	The server then stores {I, s, v} long term. v needs to be protected in the same way that
	a password hash should be protected.
*/
package srp

// This file is just for the package documentation
