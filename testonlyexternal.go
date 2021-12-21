package srp

import "math/big"

/*
We export a few ways to manipulate unexported parts of an SRP object so
users of SRP can perform some tests of their own with certain fixed
values. This methods are all named TestOnly... and should not be used
outside of such a testing context
*/

// TestOnlyResetKey sets to final key back to nil. This is used only for testing
// integration with caller
//
// Deprecated: This is only used for testing integration with caller. Never if real life.
func (s *SRP) TestOnlyResetKey() {
	s.key = nil
}

// TestOnlyResetEphemeralPublic should only be used when constructing
// tests of SRP integration with the consumer.
//
// Deprecated: This is for testing only. It is not meant to
// be used in real code, and may disappear at any moment.
func (s *SRP) TestOnlyResetEphemeralPublic() {
	s.ephemeralPublicA.Set(bigZero)
}

// TestOnlySetEphemeralSecret should only be used when constructing
// tests of SRP integration with the consumer.
//
// Deprecated: This is for testing only. It is not meant to
// be used in real code, and may disappear at any moment.
func (s *SRP) TestOnlySetEphemeralSecret(secret *big.Int) {
	s.ephemeralPrivate.Set(secret)
}

/**
 ** Copyright 2017 AgileBits, Inc.
 ** Licensed under the Apache License, Version 2.0 (the "License").
 **/
