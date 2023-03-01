# Deterministic Crypto

This is a partial fork of some of the crypto packages in order to support
deterministic crypto operations. Google does not support this by design
despite taking a `rand.Random` for all operations. They don't users to rely
on specific e.g. private keys being generated.

I want to have this anyway, so I'll do what [this issue](https://github.com/golang/go/issues/38548#issuecomment-617409930) recommends: I fork
the relevant crypto routines. I only fork those parts that called the
`MaybeReadByte()` function and their dependencies.

Also I removed all the BoringCrypto stuff and other experimental features.

I do not claim ownership of this code. I took it from Google and then changed
it. The Go License is included here as well.