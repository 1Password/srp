package srp

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Srp calculator object
type Srp struct {
	Group      *Group
	secret     *big.Int // Little a or little b (ephemeral secrets)
	A, B       *big.Int // Public A and B ephemeral values
	x, v       *big.Int // x and verifier (long term secrets)
	u          *big.Int // calculated scrambling parameter
	k          *big.Int // multiplier parameter
	K          *big.Int // Derived session K
	IsServer   bool
	secretSize int // size for generating ephemeral secrets in bytes
}

// GenerateMySecret creates the little a or b
func (s *Srp) GenerateMySecret() *big.Int {
	s.secret = RandomNumber()
	return s.secret
}

// makeLittleK initializes multiplier based on group paramaters
// k = H(N, g)
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
	s.k = NumberFromBytes(h.Sum(nil))
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
	return s.A.Exp(s.Group.g, s.secret, s.Group.N), nil
}

// MakeB calculates B (if necessary) and returms it
func (s *Srp) MakeB() (*big.Int, error) {
	if s.B != nil {
		return s.B, nil
	}

	var term1, term2 *big.Int

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

// calculateU hashes the bytes of A and B
// This is not the same hashing as used in old interface
func (s *Srp) calculateU() (*big.Int, error) {
	if s.A == nil || s.B == nil {
		return nil, fmt.Errorf("both A and B must be known to calculate u")
	}

	h := sha256.New()
	h.Write(s.A.Bytes())
	h.Write(s.B.Bytes())
	s.u = NumberFromBytes(h.Sum(nil))
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
