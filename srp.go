package srp

import (
	rand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

/*
SRP provides the primary interface to this package.

Because many of the inputs require checks against malicious data, many are set using
setters instead of being public/exported in the type. This is to ensure that bad
values do not get used.

Creating the SRP object with with NewSRP() takes care of generating your ephemeral
secret (a or b depending on whether you are a client or server), your public
ephemeral key (A or B depending on whether you are a client or server),
the multiplier k. (There is a setter for k if you wish to use a different scheme
to set those.

A typical use by a server might be something like

	server := NewSRP(true, true, KnownGroups[RFC5054Group4096], v)

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

	v is computed by client via KDF, user secrets, and random salt, s.

	x = KDF(...)
	v = g^x

	v is sent to the server on first enrollment.
	The server then keeps {I, s, v} in its database.
*/
type SRP struct {
	group            *Group
	ephemeralPrivate *big.Int // Little a or little b (ephemeral secrets)
	ephemeralPublicA *big.Int // Public A
	ephemeralPublicB *big.Int // Public A and B ephemeral values
	x, v             *big.Int // x and verifier (long term secrets)
	u                *big.Int // calculated scrambling parameter
	k                *big.Int // multiplier parameter
	premasterKey     *big.Int // unhashed derived session secret
	Key              *big.Int // H(premasterKey)
	isServer         bool
	badState         bool
}

// bigZero is a BigInt zero
var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

/*
NewSRP creates an SRP object and sets up defaults.

serverSide bool: Use true when creating an SRP object to be used on the server,
otherwise set false.

group *Group: Pointer to the Diffie-Hellman group to be used.

xORv *big.Int: Your long term secret, x or v. If you are the client, pass in x.
If you are the server pass in v.
*/
func NewSRP(serverSide bool, group *Group, xORv *big.Int) *SRP {

	// Goldberg Q: Why am I copying the group, instead of just using setting pointers?
	// Goldber A: Because every time I try to do it the "right" way bad things happen.
	sGroup := &Group{
		n:            group.n,
		g:            group.g,
		Label:        group.Label,
		ExponentSize: group.ExponentSize,
	}

	s := &SRP{
		// Setting these to Int-zero gives me a useful way to test
		// if these have been properly set later
		ephemeralPublicA: big.NewInt(0),
		ephemeralPrivate: big.NewInt(0),
		ephemeralPublicB: big.NewInt(0),
		u:                big.NewInt(0),
		k:                big.NewInt(0),
		x:                big.NewInt(0),
		v:                big.NewInt(0),
		premasterKey:     big.NewInt(0),
		Key:              big.NewInt(0),
		group:            sGroup,
		badState:         false,

		isServer: serverSide,
	}

	if s.isServer {
		s.v.Set(xORv)
	} else {
		s.x.Set(xORv)
	}

	s.makeLittleK()
	s.generateMySecret()
	if s.isServer {
		s.makeB()
	} else {
		s.makeA()
	}

	return s
}

// generateMySecret creates the little a or b
// According to RFC5054, this should be at least 32 bytes
// According to RFC2631 this should be uniform in the range
// [2, q-2], where q is the Sofie Germain prime from which
// N was created.
// According to RFC3526 §8 there are some specific sizes depending
// on the group. We go with RFC3526 values if available, otherwise
// a minimum of 32 bytes.

func (s *SRP) generateMySecret() *big.Int {

	eSize := max(s.group.ExponentSize, MinExponentSize)
	bytes := make([]byte, eSize)
	rand.Read(bytes)
	s.ephemeralPrivate = NumberFromBytes(bytes)
	return s.ephemeralPrivate
}

// makeLittleK initializes multiplier based on group paramaters
// k = H(N, g)
// This does _not_ confirm to RFC5054 padding
func (s *SRP) makeLittleK() (*big.Int, error) {
	if s.group == nil {
		return nil, fmt.Errorf("group not set")
	}
	h := sha256.New()
	h.Write(s.group.n.Bytes())
	h.Write(s.group.g.Bytes())
	s.k = NumberFromBytes(h.Sum(nil))
	return s.k, nil
}

// makeA calculates A (if necessary) and returns it
func (s *SRP) makeA() (*big.Int, error) {
	if s.group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if s.isServer {
		return nil, fmt.Errorf("only the client can make A")
	}
	if s.ephemeralPrivate.Cmp(bigZero) == 0 {
		s.ephemeralPrivate = s.generateMySecret()
	}

	s.ephemeralPublicA = &big.Int{}
	result := s.ephemeralPublicA.Exp(s.group.g, s.ephemeralPrivate, s.group.n)
	return result, nil
}

// makeB calculates B (if necessary) and returms it
func (s *SRP) makeB() (*big.Int, error) {

	term1 := &big.Int{}
	term2 := &big.Int{}

	// Absolute Prerequisits: Group, isServer, v
	if s.group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if !s.isServer {
		return nil, fmt.Errorf("only the server can make B")
	}
	if s.v.Cmp(bigZero) == 0 {
		return nil, fmt.Errorf("k must be known before B can be calculated")
	}

	// Generatable prerequists: k, b if needed
	if s.k.Cmp(bigZero) == 0 {
		var err error
		if s.k, err = s.makeLittleK(); err != nil {
			return nil, err
		}
	}
	if s.ephemeralPrivate.Cmp(bigZero) == 0 {
		s.ephemeralPrivate = s.generateMySecret()
	}

	// B = kv + g^b  (term1 is kv, term2 is g^b)
	term2.Exp(s.group.g, s.ephemeralPrivate, s.group.n)
	term1.Mul(s.k, s.v)
	term1.Mod(term1, s.group.n) // We can work with smaller numbers through modular reduction
	s.ephemeralPublicB.Add(term1, term2)
	s.ephemeralPublicB.Mod(s.ephemeralPublicB, s.group.n) // more modular reduction

	return s.ephemeralPublicB, nil
}

// EphemeralPublic returns A on client or B on server
// If you are a client, you will need to send A to the server.
// If you are a server, you will need to send B to the client.
// But this abstracts away from user needing to keep A and B straight. Caller
// just needs to send EphemeralPublic() to the other party.
func (s *SRP) EphemeralPublic() *big.Int {
	if s.isServer {
		return s.ephemeralPublicB
	}
	return s.ephemeralPublicA
}

// IsPublicValid checks to see whether public A or B is valid within the group
// A client can do very bad things by sending a malicious A to the server.
// The server can do mildly bad things by sending a malicious B to the client.
// This method is public in case the user wishes to check those values earlier than
// than using SetOthersPublic(), which also performs this check.
func (s *SRP) IsPublicValid(AorB *big.Int) bool {

	result := big.Int{}
	// There are three ways to fail.
	// 1. If we aren't checking with respect to a valid group
	// 2. If public paramater zero or a multiple of M
	// 3. If public parameter is not relatively prime to N (a bad group?)
	if s.group == nil {
		return false
	}
	if s.group.g.Cmp(bigZero) == 0 {
		return false
	}

	if result.Mod(AorB, s.group.n); result.Sign() == 0 {
		return false
	}

	if result.GCD(nil, nil, AorB, s.group.n).Cmp(bigOne) != 0 {
		return false
	}
	return true
}

// Verifier retruns the verifier as calculated by the client.
// On first enrollment, the client will need to send the verifier to the server,
// which the server will store as its long term secret. Only a client can
// compute the verifier as it requires knowledge of x.
func (s *SRP) Verifier() (*big.Int, error) {
	if s.isServer {
		return nil, fmt.Errorf("server may not produce a verifier")
	}
	return s.makeVerifier()
}

// calculateU creates a hash A and B
// It does not use RFC 5054 compatable hashing
func (s *SRP) calculateU() (*big.Int, error) {
	if !s.IsPublicValid(s.ephemeralPublicA) || !s.IsPublicValid(s.ephemeralPublicB) {
		s.u = nil
		return nil, fmt.Errorf("both A and B must be known to calculate u")
	}

	h := sha256.New()

	h.Write([]byte(fmt.Sprintf("%x%x", s.ephemeralPublicA, s.ephemeralPublicB)))

	s.u = NumberFromBytes(h.Sum(nil))
	return s.u, nil
}

// SetOthersPublic sets A if server and B if client
// Caller *MUST* check for error status and abort the session
// on error. This setter will invoke IsPublicValid() and error
// status must be heeded, as other party may attempt to send
// a malicious emphemeral public key (A or B).
//
// When used by the server, this sets A, when used by the client
// it sets B. But caller doesn't need to worry about whether this
// is A or B. Instead the caller just needs to know that they
// are setting the public ephemeral key received from the other party.
func (s *SRP) SetOthersPublic(AorB *big.Int) error {
	if !s.IsPublicValid(AorB) {
		s.badState = true
		s.Key = nil
		return fmt.Errorf("invalid public exponent")
	}

	if s.isServer {
		s.ephemeralPublicA.Set(AorB)
	} else {
		s.ephemeralPublicB.Set(AorB)
	}
	if u, err := s.calculateU(); u == nil || err != nil {
		return fmt.Errorf("failed to calculate u: %s", err)
	}
	return nil
}

func (s *SRP) isUValid() bool {
	if s.u == nil || s.badState {
		s.u = nil
		return false
	}
	if s.u.Cmp(bigZero) == 0 {
		return false
	}
	return true
}

// makeVerifier creates to the verifier from x and paramebers
func (s *SRP) makeVerifier() (*big.Int, error) {
	if s.group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if s.badState {
		return nil, fmt.Errorf("we have bad data")
	}
	if s.x.Cmp(bigZero) == 0 {
		return nil, fmt.Errorf("x must be known to calculate v")
	}

	result := s.v.Exp(s.group.g, s.x, s.group.n)

	return result, nil
}

// MakeKey creates and returns the session Key
// Once the ephemeral public key is received from the other party and properly
// set, SRP should have enough information to compute the session key.
//
// If and only if, each party knowns their respective long term secret
// (x for client, v for server) will both parties compute the same Key.
// It is up to the caller to test that both client and server have the same
// key. (A challange back and forth will do the job)
func (s *SRP) MakeKey() (*big.Int, error) {
	if s.badState {
		return nil, fmt.Errorf("we've got bad data")
	}
	if s.group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if !s.isUValid() {
		return nil, fmt.Errorf("u must be known to make Key")
	}
	if s.ephemeralPrivate.Cmp(bigZero) == 0 {
		return nil, fmt.Errorf("cannot make Key with my ephemeral secret")
	}

	b := &big.Int{} // base
	e := &big.Int{} // exponent

	if s.isServer {
		// S = (Av^u) ^ b
		if s.v == nil || s.ephemeralPublicA == nil {
			return nil, fmt.Errorf("not enough is known to create Key")
		}
		b.Exp(s.v, s.u, s.group.n)
		b.Mul(b, s.ephemeralPublicA)
		e = s.ephemeralPrivate

	} else {
		// (B - kg^x) ^ (a + ux)
		if s.ephemeralPublicB == nil || s.k == nil || s.x == nil {
			return nil, fmt.Errorf("not enough is known to create Key")
		}
		e.Mul(s.u, s.x)
		e.Add(e, s.ephemeralPrivate)

		b.Exp(s.group.g, s.x, s.group.n)
		b.Mul(b, s.k)
		b.Sub(s.ephemeralPublicB, b)
		b.Mod(b, s.group.n)
	}

	s.premasterKey.Exp(b, e, s.group.n)

	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%x", s.premasterKey)))

	s.Key = NumberFromBytes(h.Sum(nil))
	return s.Key, nil

}

// SetK sets the multiplier k if we do not derive it internally ala 5054.
// This is particularly useful for 1Password, where we use the SessionID
// in the creation of K. Input is a byte slice that will be converted
// to a big Int. This saves the caller from having to import math/big
func (s *SRP) SetK(bytes []byte) (k *big.Int, err error) {
	k = BigIntFromBytes(bytes)
	if k == nil or k.Cmp(bigZero) {
		return nil, fmt.Errorf("SRP failed to set multiplier k")
	}
	s.k.Set(k)
	return s.k
}
