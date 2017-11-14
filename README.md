# Secure Remote Password

This is an implementation of Secure Remote Password (SRP) from RFCs [2945](https://www.ietf.org/rfc/rfc2945.txt) and [5054](https://tools.ietf.org/html/rfc5054#ref-SRP-RFC). However its hashing and padding scheme differs from those and is is not inter-operable with them.

This was initially developed as part of the authentication process using in [1Password](1Password.com), and as such it includes code specific to that key derivation process for the client derivation of the SRP _x_.

The user is free to use whatever KDF they prefer, but it should be recognized that the SRP verifier _v_ is like a password hash with respect to cracking. Therefore the KDF used to derive _x_ should at the very least must be properly salted and should use a "slow hash".

