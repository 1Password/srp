package srp

import (
	rand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Srp calculator object
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
	secretSize       int // size for generating ephemeral secrets in bytes
	b5Compatible     bool
}

// B0 is a BigInt zero
var B0 = big.NewInt(0)

// NewSrp creates an Srp object and sets up defaults
// xORv is the SRP-x if setting up a client or the verifier if setting up a server
func NewSrp(serverSide bool, b5Compatible bool, group *Group, xORv *big.Int) *Srp {
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

	s.isServer = serverSide
	s.b5Compatible = b5Compatible
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
	s.k = s.numberFromBytes(h.Sum(nil))
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
	if s.ephemeralPrivate.Cmp(B0) == 0 {
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
	if s.v.Cmp(B0) == 0 {
		return nil, fmt.Errorf("k must be known before B can be calculated")
	}

	// Generatable prerequists: k, b if needed
	if s.k.Cmp(B0) == 0 {
		var err error
		if s.k, err = s.makeLittleK(); err != nil {
			return nil, err
		}
	}
	if s.ephemeralPrivate.Cmp(B0) == 0 {
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
func (s *Srp) EphemeralPublic() *big.Int {
	if s.isServer {
		return s.ephemeralPublicB
	} else {
		return s.ephemeralPublicA
	}
}

// Verifier retruns the verifier as calculated by the client
func (s *Srp) Verifier() (*big.Int, error) {
	if s.isServer {
		return nil, fmt.Errorf("server may not produce a verifier")
	}
	return s.makeVerifier()
}

// calculateU creates a hash A and B
// Its behavior depends on whether b5Compatible is set
func (s *Srp) calculateU() (*big.Int, error) {
	if !s.isAValid() || !s.isBValid() {
		return nil, fmt.Errorf("both A and B must be known to calculate u")
	}

	h := sha256.New()
	if s.b5Compatible {
		h.Write([]byte(fmt.Sprintf("%x%x", s.ephemeralPublicA, s.ephemeralPublicB)))
	} else {
		h.Write(s.ephemeralPublicA.Bytes())
		h.Write(s.ephemeralPublicB.Bytes())
	}
	s.u = s.numberFromBytes(h.Sum(nil))
	return s.u, nil
}

func (s *Srp) isPublicValid(AorB *big.Int) bool {
	if s.group == nil {
		return false
	}
	if AorB == nil {
		return false
	}

	t := big.Int{}
	if t.Mod(AorB, s.group.N); t.Sign() == 0 {
		return false
	}
	if t.GCD(nil, nil, AorB, s.group.N).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	return true
}

// SetOthersPublic sets A if server and B if client
// Caller _must_ check for error status, and abort the session
// on error. Any further action with Srp should crash after bad A or B set
func (s *Srp) SetOthersPublic(AorB *big.Int) error {
	if !s.isPublicValid(AorB) {
		s.ephemeralPrivate = nil
		s.ephemeralPublicA = nil
		s.ephemeralPublicB = nil
		s.x = nil
		s.v = nil
		return fmt.Errorf("invalid public exponent")
	}

	if s.isServer {
		s.ephemeralPublicA.Set(AorB)
	} else {
		s.ephemeralPublicB.Set(AorB)
	}
	return nil
}

func (s *Srp) isAValid() bool {
	return s.isPublicValid(s.ephemeralPublicA)
}
func (s *Srp) isBValid() bool {
	return s.isPublicValid(s.ephemeralPublicB)
}

func (s *Srp) isUValid() bool {
	if s.u.Cmp(B0) == 0 {
		return false
	}
	return true
}

// makeVerifier creates to the verifier from x and paramebers
func (s *Srp) makeVerifier() (*big.Int, error) {
	if s.group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if s.x.Cmp(B0) == 0 {
		return nil, fmt.Errorf("x must be known to calculate v")
	}

	result := s.v.Exp(s.group.g, s.x, s.group.N)

	return result, nil
}

// MakeKey creates and returns the session Key
func (s *Srp) MakeKey() (*big.Int, error) {
	if s.group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if !s.isUValid() {
		return nil, fmt.Errorf("u must be known to make Key")
	}
	if s.ephemeralPrivate.Cmp(B0) == 0 {
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
	if s.b5Compatible {
		h.Write([]byte(fmt.Sprintf("%x", s.premasterKey)))
	} else {
		h.Write(s.premasterKey.Bytes())
	}

	s.Key = s.numberFromBytes(h.Sum(nil))
	return s.Key, nil

}

func (s *Srp) random() *big.Int {
	bytes := make([]byte, s.secretSize)
	rand.Read(bytes)

	return s.numberFromBytes(bytes)
}

func (s *Srp) numberFromBytes(bytes []byte) *big.Int {
	result := new(big.Int)
	for _, b := range bytes {
		result.Lsh(result, 8)
		result.Add(result, big.NewInt(int64(b)))
	}

	return result
}
