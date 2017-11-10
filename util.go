package srp

import (
	"math/big"
	"strings"
)

// numberFromBtyes converts a byte array to a number
func numberFromBtyes(bytes []byte) *big.Int {
	result := new(big.Int)
	for _, b := range bytes {
		result.Lsh(result, 8)
		result.Add(result, big.NewInt(int64(b)))
	}

	return result
}

// NumberFromString converts a string (hex) to a number
func NumberFromString(s string) *big.Int {
	n := strings.Replace(s, " ", "", -1)

	result := new(big.Int)
	result.SetString(strings.TrimPrefix(n, "0x"), 16)

	return result
}

// max of two integers
// (because go doesn't give me "a > b ? a : b" )
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
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
