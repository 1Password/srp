/**
 ** Copyright 2017 AgileBits, Inc.
 ** Licensed under the Apache License, Version 2.0 (the "License").
 **/

package srp

import (
	"encoding/hex"
	"strings"
	"testing"
)

type rfc5054TestVector struct {
	I         string
	P         string
	salt      string
	expectedX string
}

var aliceVector = rfc5054TestVector{
	I:         "alice",
	P:         "password123",
	salt:      "BEB25379 D1A8581E B5A72767 3A2441EE",
	expectedX: "94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124",
}

// TestKDFRFC5054 only tests the key derivation function in Appendix B of 5054.
// That is, it is only about getting the x value from the
// salt, username, and password. TestNewSRPAgainstSpec() does further testing
// on computations given the derived x.
func TestKDFRFC5054(t *testing.T) {
	vec := aliceVector
	expX := NumberFromString(vec.expectedX)
	vec.salt = strings.ReplaceAll(vec.salt, " ", "")
	s, _ := hex.DecodeString(vec.salt)

	x, err := KDFRFC5054(s, vec.I, vec.P)
	if err != nil {
		t.Fatalf("KDFRFC5054: %v", err)
	}

	if expX.Cmp(x) != 0 {
		t.Error("didn't derive correct x")
	}
}
