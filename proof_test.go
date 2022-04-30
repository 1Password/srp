/**
 ** Copyright 2017 AgileBits, Inc.
 ** Licensed under the Apache License, Version 2.0 (the "License").
 **/

package srp

import (
	"encoding/hex"
	"math/big"
	"testing"
)

var sampleSRP = new(SRP)

func init() {
	// We will need a minimal sample SRP object to play with, with a group, A, B, and key
	// We don't need to actually compute the key, but we should use
	// plausible values for these in our tests
	group := KnownGroups[RFC5054Group2048]
	key, _ := hex.DecodeString("1fad6d1c06537a32c672d90eff92a9ad88fa7f5f333605d6d0bf3712b4a57078")

	// instead of hardcoding in A and B (which are really really big), it is easier
	// to just code in plausible a and b, and generate A and B from those.
	a, _ := new(big.Int).SetString("62c07608fa04d2fdfeb5e281fe6c459d4ff03e6aa439a1a5b399a4648f8ddd7e", 16)
	b, _ := new(big.Int).SetString("c18136e73ea06f5e795a6ad8f8140c450fd98027d8ea8cfa6aea0e8c7e73c88a", 16)

	A := new(big.Int).Exp(group.g, a, group.n)
	B := new(big.Int).Exp(group.g, b, group.n)

	sampleSRP.ephemeralPublicA = A
	sampleSRP.ephemeralPublicB = B
	sampleSRP.group = group
	sampleSRP.key = key
}

func TestM(t *testing.T) {
	salt, _ := hex.DecodeString("2e1a520e226f461e840e40e0")
	username := "Polly@cracker.example"

	client := new(SRP).copy(sampleSRP)
	client.isServer = false

	server := new(SRP).copy(sampleSRP)
	server.isServer = true

	M, err := server.M(salt, username)
	if err != nil {
		t.Errorf("server failed to produce M: %s", err)
	}

	if !client.GoodServerProof(salt, username, M) {
		t.Errorf("client rejected server proof")
	}
}

// These copy utilities should probably be moved elsewhere. And perhaps they are
// unnecessary. For for future tests, I will want to modify the client or the server
// SRP object on its own, without changing the values in the other.

func (g *Group) copy(x *Group) *Group {
	if x == nil {
		return nil
	}
	g.g = safeSet(x.g)
	g.n = safeSet(x.n)
	g.Label = x.Label
	g.ExponentSize = x.ExponentSize
	return g
}

func (s *SRP) copy(x *SRP) *SRP {
	if x == nil {
		return nil
	}

	// There has GOT be a better way of going this.
	s.group = new(Group).copy(x.group)

	// Using Set to copy the big Ints. I really don't
	// know whether straight assignment would work.
	// There are things about go that I don't get
	s.ephemeralPrivate = safeSet(x.ephemeralPrivate)
	s.ephemeralPublicA = safeSet(x.ephemeralPublicA)
	s.ephemeralPublicB = safeSet(x.ephemeralPublicB)
	s.x = safeSet(x.x)
	s.v = safeSet(x.v)
	s.u = safeSet(x.u)
	s.k = safeSet(x.k)
	s.premasterKey = safeSet(x.premasterKey)

	s.key = x.key

	s.isServer = x.isServer
	s.badState = x.badState
	s.isServerProved = x.isServerProved
	s.m = x.m
	s.cProof = x.cProof

	return s
}

func safeSet(x *big.Int) *big.Int {
	if x == nil {
		return nil
	}
	return new(big.Int).Set(x)
}
