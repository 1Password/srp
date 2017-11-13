package srp

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

/*
From http://srp.stanford.edu/design.html

	Client -> Server:  M = H(H(N) xor H(g), H(I), s, A, B, Key)
	Server >- Client: H(A, M, K)

	The client must show its proof first

To make that useful, we are going to need to define the hash of big ints.
We will use math/big Bytes() to get the absolute value as a big-endian byte
slice (without padding to size of N)
*/

// M returns the server's proof of knowledge of key
func (s *SRP) M(salt []byte, uname string) ([]byte, error) {
	if s.m != nil {
		return s.m, nil
	}
	if s.key == nil {
		return nil, fmt.Errorf("don't try to prove anything before you have the key")
	}

	// First lets work on the H(H(A) ⊕ H(g)) part.
	nHash := sha256.Sum256(s.group.n.Bytes())
	gHash := sha256.Sum256(s.group.g.Bytes())
	groupXOR := make([]byte, sha256.Size)
	if length := safeXORBytes(groupXOR, nHash[:], gHash[:]); length != sha256.Size {
		return nil, fmt.Errorf("XOR had %d bytes instead of %d",
			length, sha256.Size)
	}
	groupHash := sha256.Sum256(groupXOR)

	uHash := sha256.Sum256([]byte(uname))
	h := sha256.New()

	h.Write(groupHash[:])
	h.Write(uHash[:])
	h.Write(salt)
	h.Write(s.ephemeralPublicA.Bytes())
	h.Write(s.ephemeralPublicB.Bytes())
	h.Write(s.key)

	s.m = h.Sum(nil)
	return s.m, nil
}

// GoodServerProof takes the post-key negotiation proof from the server
// and compares it with what we (the client think it should be)
func (s *SRP) GoodServerProof(salt []byte, uname string, proof []byte) bool {
	myM, err := s.M(salt, uname)
	if err != nil {
		// well that's odd. Better retrurn false if something is wrong here
		s.isServerProved = false
		return false
	}
	s.isServerProved = bytes.Equal(myM, proof)
	return s.isServerProved
}

// ClientProof constructs the clients proof that it knows the key
func (s *SRP) ClientProof() ([]byte, error) {
	if !s.isServer && !s.isServerProved {
		return nil, fmt.Errorf("don't construct client proof until server is proved")
	}
	if s.cProof != nil {
		return s.cProof, nil
	}

	if s.ephemeralPublicA == nil || s.m == nil || s.key == nil {
		return nil, fmt.Errorf("not enough pieces in place to construct client proof")
	}
	h := sha256.New()
	h.Write(s.ephemeralPublicA.Bytes())
	h.Write(s.m)
	h.Write(s.key)
	s.cProof = h.Sum(nil)
	return s.cProof, nil
}

// GoodClientProof returns true if the given proof is the same as what we calculate
func (s *SRP) GoodClientProof(proof []byte) bool {
	myCP, err := s.ClientProof()
	if err != nil {
		return false
	}
	return bytes.Equal(myCP, proof)
}

// lifted straight from https://golang.org/src/crypto/cipher/xor.go
func safeXORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}
