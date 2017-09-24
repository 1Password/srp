package srp

import (
	rand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

/*
Srp provides the primary interface to this package.

Because many of the inputs require checks against malicious data, many are set using
setters instead of being public/exported in the type. This is to ensure that bad
values do not get used.

Creating the Srp object with with NewSrp() takes care of generating your ephemeral
secret (a or b depending on whether you are a client or server), your public
ephemeral key (A or B depending on whether you are a client or server),
the multiplier k. (There is a setter for k if you wish to use a different scheme
to set those.

A typical use by a server might be something like

	server := NewSrp(true, true, KnownGroups[RFC5054Group4096], v)

	A := getAfromYourClientConnection(...) // your code
	if result, err := server.SetOthersPublic(A); result == nil || err != nil {
		// client sent a malicious A. Kill this session now
	}

	sendBtoClientSomehow(server.EphemeralPublic())

	if sessionKey, err := server.MakeKey(); sessionKey == nil || err != nil {
		// something went wrong
	}

	// You must still prove that both server and client created the same Key.

This still leaves some work outside of what the Srp object provides.
1. The key derivation of x is not handled by this object.
2. The communication between client and server. 
3. The check that both client and server have negotiated the same Key is left outside.

*/
type Srp struct {
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
	secretSize       int // size for generating ephemeral secrets in bytes
}

// bigZero is a BigInt zero
var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

/*
NewSrp creates an Srp object and sets up defaults.

serverSide bool: Use true when creating an Srp object to be used on the server,
otherwise set false.

group *Group: Pointer to the Diffie-Hellman group to be used.

xORv *big.Int: Your long term secret, x or v. If you are the client, pass in x.
If you are the server pass in v.
*/
func NewSrp(serverSide bool, group *Group, xORv *big.Int) *Srp {
	s := new(Srp)

	// Setting these to Int-zero gives me a useful way to test
	// if these have been properly set later
	s.ephemeralPublicA = big.NewInt(0)
	s.ephemeralPrivate = big.NewInt(0)
	s.ephemeralPublicB = big.NewInt(0)
	s.u = big.NewInt(0)
	s.k = big.NewInt(0)
	s.x = big.NewInt(0)
	s.v = big.NewInt(0)
	s.premasterKey = big.NewInt(0)
	s.Key = big.NewInt(0)
	s.group = NewGroup()
	s.badState = false

	s.isServer = serverSide
	s.secretSize = 32 // what RFC 5054 suggests

	s.group.N = s.group.N.Set(group.N)
	s.group.g = s.group.g.Set(group.g)

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
func (s *Srp) generateMySecret() *big.Int {
	s.ephemeralPrivate = s.random()
	return s.ephemeralPrivate
}

// makeLittleK initializes multiplier based on group paramaters
// k = H(N, g)
// This does _not_ confirm to RFC5054 padding
func (s *Srp) makeLittleK() (*big.Int, error) {
	if s.group == nil {
		return nil, fmt.Errorf("group not set")
	}
	h := sha256.New()
	h.Write(s.group.N.Bytes())
	h.Write(s.group.g.Bytes())
	s.k = NumberFromBytes(h.Sum(nil))
	return s.k, nil
}

// makeA calculates A (if necessary) and returns it
func (s *Srp) makeA() (*big.Int, error) {
	if s.group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if s.isServer {
		return nil, fmt.Errorf("only the client can make A")
	}
	if s.ephemeralPrivate.Cmp(bigZero) == 0 {
		s.ephemeralPrivate = s.generateMySecret()
	}

	s.ephemeralPublicA = new(big.Int)
	result := s.ephemeralPublicA.Exp(s.group.g, s.ephemeralPrivate, s.group.N)
	return result, nil
}

// makeB calculates B (if necessary) and returms it
func (s *Srp) makeB() (*big.Int, error) {

	term1 := new(big.Int)
	term2 := new(big.Int)

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
	term2.Exp(s.group.g, s.ephemeralPrivate, s.group.N)
	term1.Mul(s.k, s.v)
	term1.Mod(term1, s.group.N) // We can work with smaller numbers through modular reduction
	s.ephemeralPublicB.Add(term1, term2)
	s.ephemeralPublicB.Mod(s.ephemeralPublicB, s.group.N) // more modular reduction

	return s.ephemeralPublicB, nil
}

// EphemeralPublic returns A on client or B on server
// If you are a client, you will need to send A to the server.
// If you are a server, you will need to send B to the client.
// But this abstracts away from user needing to keep A and B straight. Caller
// just needs to send EphemeralPublic() to the other party.
func (s *Srp) EphemeralPublic() *big.Int {
	if s.isServer {
		return s.ephemeralPublicB
	} else {
		return s.ephemeralPublicA
	}
}

// IsPublicValid checks to see whether public A or B is valid within the group
// A client can do very bad things by sending a malicious A to the server.
// The server can do mildly bad things by sending a malicious B to the client.
// This method is public in case the user wishes to check those values earlier than
// than using SetOthersPublic(), which also performs this check.
func (s *Srp) IsPublicValid(AorB *big.Int) bool {

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

	if result.Mod(AorB, s.group.N); result.Sign() == 0 {
		return false
	}

	if result.GCD(nil, nil, AorB, s.group.N).Cmp(bigOne) != 0 {
		return false
	}
	return true
}

// Verifier retruns the verifier as calculated by the client.
// On first enrollment, the client will need to send the verifier to the server,
// which the server will store as its long term secret. Only a client can
// compute the verifier as it requires knowledge of x.
func (s *Srp) Verifier() (*big.Int, error) {
	if s.isServer {
		return nil, fmt.Errorf("server may not produce a verifier")
	}
	return s.makeVerifier()
}

// calculateU creates a hash A and B
// It does not use RFC 5054 compatable hashing
func (s *Srp) calculateU() (*big.Int, error) {
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
func (s *Srp) SetOthersPublic(AorB *big.Int) error {
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

func (s *Srp) isUValid() bool {
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
func (s *Srp) makeVerifier() (*big.Int, error) {
	if s.group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if s.badState {
		return nil, fmt.Errorf("we have bad data")
	}
	if s.x.Cmp(bigZero) == 0 {
		return nil, fmt.Errorf("x must be known to calculate v")
	}

	result := s.v.Exp(s.group.g, s.x, s.group.N)

	return result, nil
}

// MakeKey creates and returns the session Key
// Once the ephemeral public key is received from the other party and properly
// set, Srp should have enough information to compute the session key.
//
// If and only if, each party knowns their respective long term secret
// (x for client, v for server) will both parties compute the same Key.
// It is up to the caller to test that both client and server have the same
// key. (A challange back and forth will do the job)
func (s *Srp) MakeKey() (*big.Int, error) {
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

	b := new(big.Int) // base
	e := new(big.Int) // exponent

	if s.isServer {
		// S = (Av^u) ^ b
		if s.v == nil || s.ephemeralPublicA == nil {
			return nil, fmt.Errorf("not enough is known to create Key")
		}
		b.Exp(s.v, s.u, s.group.N)
		b.Mul(b, s.ephemeralPublicA)
		e = s.ephemeralPrivate

	} else {
		// (B - kg^x) ^ (a + ux)
		if s.ephemeralPublicB == nil || s.k == nil || s.x == nil {
			return nil, fmt.Errorf("not enough is known to create Key")
		}
		e.Mul(s.u, s.x)
		e.Add(e, s.ephemeralPrivate)

		b.Exp(s.group.g, s.x, s.group.N)
		b.Mul(b, s.k)
		b.Sub(s.ephemeralPublicB, b)
		b.Mod(b, s.group.N)
	}

	s.premasterKey.Exp(b, e, s.group.N)

	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%x", s.premasterKey)))

	s.Key = NumberFromBytes(h.Sum(nil))
	return s.Key, nil

}

func (s *Srp) random() *big.Int {
	bytes := make([]byte, s.secretSize)
	rand.Read(bytes)

	return NumberFromBytes(bytes)
}
