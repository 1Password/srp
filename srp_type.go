package srp

import (
	rand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Srp calculator object
type Srp struct {
	Group        *Group
	secret       *big.Int // Little a or little b (ephemeral secrets)
	A, B         *big.Int // Public A and B ephemeral values
	x, v         *big.Int // x and verifier (long term secrets)
	u            *big.Int // calculated scrambling parameter
	k            *big.Int // multiplier parameter
	Key          *big.Int // Derived session K
	IsServer     bool
	secretSize   int // size for generating ephemeral secrets in bytes
	b5Compatible bool
}

// NewSrp creates an Srp object and sets up defaults
// xORv is the SRP-x if setting up a client or the verifier if setting up a server
func NewSrp(serverSide bool, b5Compatible bool, group *Group, xORv *big.Int) *Srp {
	s := new(Srp)

	s.IsServer = serverSide
	s.b5Compatible = b5Compatible

	// There has to be a better way, but everything else crashed
	s.Group = new(Group)
	s.Group.N = group.N
	s.Group.g = group.g

	if s.IsServer {
		s.v = xORv
	} else {
		s.x = xORv
	}

	s.secretSize = 24

	s.makeLittleK()
	s.GenerateMySecret()
	if s.IsServer {
		s.MakeB()
	} else {
		s.MakeA()
	}

	return s
}

// GenerateMySecret creates the little a or b
func (s *Srp) GenerateMySecret() *big.Int {
	s.secret = s.random()
	return s.secret
}

// makeLittleK initializes multiplier based on group paramaters
// k = H(N, g)
// This does _not_ confirm to RFC5054 padding
func (s *Srp) makeLittleK() (*big.Int, error) {
	if s.k != nil {
		return s.k, nil
	}
	if s.Group == nil {
		return nil, fmt.Errorf("group not set")
	}
	h := sha256.New()
	h.Write(s.Group.N.Bytes())
	h.Write(s.Group.g.Bytes())
	s.k = s.numberFromBytes(h.Sum(nil))
	return s.k, nil
}

// SetLittleK allows us to manually set k if we don't like the specs
func (s *Srp) SetLittleK(k *big.Int) {
	*(s.k) = *k // Is this deferencing needed? Can I trust caller to not change value in k?
}

// MakeA calculates A (if necessary) and returns it
func (s *Srp) MakeA() (*big.Int, error) {
	if s.A != nil {
		return s.A, nil
	}
	if s.Group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if s.IsServer {
		return nil, fmt.Errorf("only the client can make A")
	}
	if s.secret == nil {
		s.secret = s.GenerateMySecret()
	}

	s.A = new(big.Int)
	result := s.A.Exp(s.Group.g, s.secret, s.Group.N)
	return result, nil
}

// MakeB calculates B (if necessary) and returms it
func (s *Srp) MakeB() (*big.Int, error) {

	term1 := new(big.Int)
	term2 := new(big.Int)
	s.B = new(big.Int)

	// Absolute Prerequisits: Group, IsServer, v
	if s.Group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if !s.IsServer {
		return nil, fmt.Errorf("only the server can make B")
	}
	if s.v == nil {
		return nil, fmt.Errorf("k must be known before B can be calculated")
	}

	// Generatable prerequists: k, b if needed
	if s.k == nil {
		var err error
		if s.k, err = s.makeLittleK(); err != nil {
			return nil, err
		}
	}
	if s.secret == nil {
		s.secret = s.GenerateMySecret()
	}

	// B = kv + g^b  (term1 is kv, term2 is g^b)
	term2.Exp(s.Group.g, s.secret, s.Group.N)
	term1.Mul(s.k, s.v)
	term1.Mod(term1, s.Group.N) // We can work with smaller numbers through modular reduction
	s.B.Add(term1, term2)
	s.B.Mod(s.B, s.Group.N) // more modular reduction

	return s.B, nil
}

// myPublic returns (and posibly calculates) A if client and B if server
// This abstraction is probably not very useful and will probably just go away
func (s *Srp) myPublic() (*big.Int, error) {
	if s.Group == nil {
		return nil, fmt.Errorf("group not set")
	}

	if s.IsServer {
		return s.MakeB()
	}
	return s.MakeA()
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
	if s.u.Cmp(big.NewInt(1)) != 0 {
		return false
	}
	return true
}

func (s *Srp) makeVerifer() (*big.Int, error) {
	if s.Group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if s.x == nil {
		return nil, fmt.Errorf("x must be known to calculate v")
	}

	if s.v == nil {
		s.v = new(big.Int)
	}
	return s.v.Exp(s.Group.g, s.x, s.Group.N), nil
}

// MakeKey creates and returns the session Key
func (s *Srp) MakeKey() (*big.Int, error) {
	if s.Group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if !s.isUValid() {
		return nil, fmt.Errorf("u must be known to make Key")
	}
	if s.secret == nil {
		return nil, fmt.Errorf("cannot make Key with my ephemeral secret")
	}

	b := new(big.Int)
	e := new(big.Int)
	S := new(big.Int)

	if s.IsServer {
		// S = (Av^u) ^ b
		if s.v == nil || s.A == nil {
			return nil, fmt.Errorf("not enough is know to create Key")
		}
		b.Exp(s.v, s.u, s.Group.N)
		b.Mul(s.v, s.A)
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

	S.Exp(b, e, s.Group.N)

	h := sha256.New()
	if s.b5Compatible {
		h.Write([]byte(fmt.Sprintf("%x", S)))
	} else {
		h.Write(S.Bytes())
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
