package srp

import (
	"math/big"
	"strings"
)

// NumberFromString converts a string (hex) to a number
func NumberFromString(s string) *big.Int {
	n := strings.Replace(s, " ", "", -1)

	result := new(big.Int)
	result.SetString(strings.TrimPrefix(n, "0x"), 16)

	return result
}

// max of integer arguments
// (because go doesn't give me "a > b ? a : b" )
func maxInt(n1 int, nums ...int) int {
	max := n1
	for _, n := range nums {
		if n > max {
			max = n
		}
	}
	return max
}

// bigIntFromBytes converts a byte array to a number
func bigIntFromBytes(bytes []byte) *big.Int {
	result := new(big.Int)
	for _, b := range bytes {
		result.Lsh(result, 8)
		result.Add(result, big.NewInt(int64(b)))
	}
	return result
}

/**
 ** Copyright 2017 AgileBits, Inc.
 ** Licensed under the Apache License, Version 2.0 (the "License").
 **/
