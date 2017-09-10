package srp

import (
	rand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Srp calculator object
type Srp struct {
	Group        *DHGroup
	secret       *big.Int // Little a or little b (ephemeral secrets)
	A, B         *big.Int // Public A and B ephemeral values
	x, v         *big.Int // x and verifier (long term secrets)
	u            *big.Int // calculated scrambling parameter
	k            *big.Int // multiplier parameter
	premasterKey *big.Int // unhashed derived session secret
	Key          *big.Int // H(premasterKey)
	IsServer     bool
	secretSize   int // size for generating ephemeral secrets in bytes
	b5Compatible bool
}

// DHGroup is the Diffie-Hellman group we will use for SRP
type DHGroup struct {
	N *big.Int
	g *big.Int
}

// NewDHGroup allocates the big ints of this group
func NewDHGroup() *DHGroup {
	r := new(DHGroup)
	r.N = new(big.Int)
	r.g = new(big.Int)
	return r
}

// B0 is a BigInt zero
var B0 = big.NewInt(0)

// NewSrp creates an Srp object and sets up defaults
// xORv is the SRP-x if setting up a client or the verifier if setting up a server
func NewSrp(serverSide bool, b5Compatible bool, group *Group, xORv *big.Int) *Srp {
	s := new(Srp)

	// Setting these to Int-zero gives me a useful way to test
	// if these have been properly set later
	s.A = big.NewInt(0)
	s.secret = big.NewInt(0)
	s.B = big.NewInt(0)
	s.u = big.NewInt(0)
	s.k = big.NewInt(0)
	s.x = big.NewInt(0)
	s.v = big.NewInt(0)
	s.premasterKey = big.NewInt(0)
	s.Key = big.NewInt(0)
	s.Group = NewDHGroup()

	s.IsServer = serverSide
	s.b5Compatible = b5Compatible
	s.secretSize = 32 // what RFC 5054 suggests

	s.Group.N = s.Group.N.Set(group.N)
	s.Group.g = s.Group.g.Set(group.g)

	if s.IsServer {
		s.v.Set(xORv)
	} else {
		s.x.Set(xORv)
	}

	s.makeLittleK()
	s.generateMySecret()
	if s.IsServer {
		s.makeB()
	} else {
		s.makeA()
	}

	return s
}

// generateMySecret creates the little a or b
func (s *Srp) generateMySecret() *big.Int {
	s.secret = s.random()
	return s.secret
}

// makeLittleK initializes multiplier based on group paramaters
// k = H(N, g)
// This does _not_ confirm to RFC5054 padding
func (s *Srp) makeLittleK() (*big.Int, error) {
	if s.Group == nil {
		return nil, fmt.Errorf("group not set")
	}
	h := sha256.New()
	h.Write(s.Group.N.Bytes())
	h.Write(s.Group.g.Bytes())
	s.k = s.numberFromBytes(h.Sum(nil))
	return s.k, nil
}

// makeA calculates A (if necessary) and returns it
func (s *Srp) makeA() (*big.Int, error) {
	if s.Group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if s.IsServer {
		return nil, fmt.Errorf("only the client can make A")
	}
	if s.secret.Cmp(B0) == 0 {
		s.secret = s.generateMySecret()
	}

	s.A = new(big.Int)
	result := s.A.Exp(s.Group.g, s.secret, s.Group.N)
	return result, nil
}

// makeB calculates B (if necessary) and returms it
func (s *Srp) makeB() (*big.Int, error) {

	term1 := new(big.Int)
	term2 := new(big.Int)

	// Absolute Prerequisits: Group, IsServer, v
	if s.Group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if !s.IsServer {
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
	if s.secret.Cmp(B0) == 0 {
		s.secret = s.generateMySecret()
	}

	// B = kv + g^b  (term1 is kv, term2 is g^b)
	term2.Exp(s.Group.g, s.secret, s.Group.N)
	term1.Mul(s.k, s.v)
	term1.Mod(term1, s.Group.N) // We can work with smaller numbers through modular reduction
	s.B.Add(term1, term2)
	s.B.Mod(s.B, s.Group.N) // more modular reduction

	return s.B, nil
}

// calculateU creates a hash A and B
// Its behavior depends on whether b5Compatible is set
func (s *Srp) calculateU() (*big.Int, error) {
	if !s.isAValid() || !s.isBValid() {
		return nil, fmt.Errorf("both A and B must be known to calculate u")
	}

	h := sha256.New()
	if s.b5Compatible {
		h.Write([]byte(fmt.Sprintf("%x%x", s.A, s.B)))
	} else {
		h.Write(s.A.Bytes())
		h.Write(s.B.Bytes())
	}
	s.u = s.numberFromBytes(h.Sum(nil))
	return s.u, nil
}

func (s *Srp) isPublicValid(AorB *big.Int) bool {
	if s.Group == nil {
		return false
	}
	if AorB == nil {
		return false
	}

	t := big.Int{}
	if t.Mod(AorB, s.Group.N); t.Sign() == 0 {
		return false
	}
	if t.GCD(nil, nil, AorB, s.Group.N).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	return true
}

func (s *Srp) isAValid() bool {
	return s.isPublicValid(s.A)
}
func (s *Srp) isBValid() bool {
	return s.isPublicValid(s.B)
}

func (s *Srp) isUValid() bool {
	if s.u == nil {
		return false
	}
	if s.u.Cmp(B0) == 0 {
		return false
	}
	return true
}

func (s *Srp) makeVerifer() (*big.Int, error) {
	if s.Group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if s.x.Cmp(B0) == 0 {
		return nil, fmt.Errorf("x must be known to calculate v")
	}

	result := s.v.Exp(s.Group.g, s.x, s.Group.N)

	return result, nil
}

// MakeKey creates and returns the session Key
func (s *Srp) MakeKey() (*big.Int, error) {
	if s.Group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if !s.isUValid() {
		return nil, fmt.Errorf("u must be known to make Key")
	}
	if s.secret.Cmp(B0) == 0 {
		return nil, fmt.Errorf("cannot make Key with my ephemeral secret")
	}

	b := new(big.Int)
	e := new(big.Int)

	if s.IsServer {
		// S = (Av^u) ^ b
		if s.v == nil || s.A == nil {
			return nil, fmt.Errorf("not enough is know to create Key")
		}
		b.Exp(s.v, s.u, s.Group.N)
		b.Mul(b, s.A)
		e = s.secret

	} else {
		// (B - kg^x) ^ (a + ux)
		if s.B == nil || s.k == nil || s.x == nil {
			return nil, fmt.Errorf("not enough is know to create Key")
		}
		e.Mul(s.u, s.x)
		e.Add(e, s.secret)

		b.Exp(s.Group.g, s.x, s.Group.N)
		b.Mul(b, s.k)
		b.Sub(s.B, b)
		b.Mod(b, s.Group.N)
	}

	s.premasterKey.Exp(b, e, s.Group.N)

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
