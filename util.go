package srp

import "math/big"

// NumberFromBytes converts a byte array to a number
func NumberFromBytes(bytes []byte) *big.Int {
	result := new(big.Int)
	for _, b := range bytes {
		result.Lsh(result, 8)
		result.Add(result, big.NewInt(int64(b)))
	}

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

// BigIntFromBytes converts a byte array to a number
func BigIntFromBytes(bytes []byte) *big.Int {
	result := new(big.Int)
	for _, b := range bytes {
		result.Lsh(result, 8)
		result.Add(result, big.NewInt(int64(b)))
	}
	return result
}
