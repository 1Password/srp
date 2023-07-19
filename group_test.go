package srp

import (
	"errors"
	"math/big"
	"testing"
)

var runVerySlowTests = false // run slow tests on groups?

func TestGroups(t *testing.T) {
	MinGroupSize = 1024 // We need a 1024 group to test against spec
	for _, grp := range KnownGroups {
		if err := checkGroup(*grp); err != nil {
			t.Errorf("bad group %s: %s", grp.Label, err)
		}
		if runVerySlowTests {
			if err := checkGroupSlow(*grp); err != nil {
				t.Errorf("suspicious group %s: %s", grp.Label, err)
			}
		}
	}
}

func TestMakeK(t *testing.T) {
	MinGroupSize = 1024 // We need this to test against spec (though we are using sha256 here)
	type TestVec struct {
		groupID   int
		expectedK string
	}
	testVectors := []TestVec{
		{
			groupID:   RFC5054Group1024,
			expectedK: "1a1a4c140cde70ae360c1ec33a33155b1022df951732a476a862eb3ab8206a5c",
		},
		{
			groupID:   RFC5054Group4096,
			expectedK: "3509477ea9fca66eadb7cf7b1bd0eb508f54d3989a9c988006a7d0b338374dd2",
		},
	}

	for _, tVec := range testVectors {
		grp := KnownGroups[tVec.groupID]
		k := grp.LittleK(Hash.Sha256Name)
		if k == nil {
			t.Errorf("failed to create k for %s", grp.Label)
		}
		exK := NumberFromString(tVec.expectedK)
		if k.Cmp(exK) != 0 {
			t.Errorf("unexpected k for %s", grp.Label)
		}
	}
}

func checkGroup(group Group) error {
	if group.n == nil {
		return errors.New("N not set")
	}
	if group.g == nil {
		return errors.New("g not set")
	}
	if group.n.BitLen() < MinGroupSize {
		return errors.New("N too small")
	}
	if group.g.Cmp(bigOne) != 1 {
		return errors.New("g < 2")
	}
	z := new(big.Int)
	if z.GCD(nil, nil, group.g, group.n).Cmp(bigOne) != 0 {
		return errors.New("GCD(g, N) != 1")
	}

	return nil
}

// These tests are very slow. Several seconds per group
// Also they do not defend against maliciously crafted groups.
func checkGroupSlow(group Group) error {
	if !group.n.ProbablyPrime(2) {
		return errors.New("N isn't prime")
	}

	// is N a safe prime?
	// Does N = 2q + 1, where q is prime?
	q := new(big.Int)
	q.Sub(group.n, bigOne)
	q.Div(q, big.NewInt(2))
	if !q.ProbablyPrime(2) {
		return errors.New("N isn't a safe prime")
	}
	return nil
}

/**
 ** Copyright 2017, 2022 AgileBits, Inc.
 ** Licensed under the Apache License, Version 2.0 (the "License").
 **/
