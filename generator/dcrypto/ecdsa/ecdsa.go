// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as
// defined in FIPS 186-4 and SEC 1, Version 2.0.
//
// Signatures generated by this package are not deterministic, but entropy is
// mixed with the private key and the message, achieving the same level of
// security in case of randomness source failure.
package ecdsa

// [FIPS 186-4] references ANSI X9.62-2005 for the bulk of the ECDSA algorithm.
// That standard is not freely available, which is a problem in an open source
// implementation, because not only the implementer, but also any maintainer,
// contributor, reviewer, auditor, and learner needs access to it. Instead, this
// package references and follows the equivalent [SEC 1, Version 2.0].
//
// [FIPS 186-4]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
// [SEC 1, Version 2.0]: https://www.secg.org/sec1-v2.pdf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/sha512"
	"errors"
	"io"
	"math/big"
	"sync"

	internalEcdsa "crypto/ecdsa"

	"github.com/wokdav/gopki/generator/dcrypto/internal/bigmod"
	"github.com/wokdav/gopki/generator/dcrypto/internal/nistec"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// GenerateKey generates a public and private key pair.
func GenerateKey(c elliptic.Curve, rand io.Reader) (*internalEcdsa.PrivateKey, error) {
	switch c.Params() {
	case elliptic.P224().Params():
		return generateNISTEC(p224(), rand)
	case elliptic.P256().Params():
		return generateNISTEC(p256(), rand)
	case elliptic.P384().Params():
		return generateNISTEC(p384(), rand)
	case elliptic.P521().Params():
		return generateNISTEC(p521(), rand)
	default:
		return generateLegacy(c, rand)
	}
}

func generateNISTEC[Point nistPoint[Point]](c *nistCurve[Point], rand io.Reader) (*internalEcdsa.PrivateKey, error) {
	k, Q, err := randomPoint(c, rand)
	if err != nil {
		return nil, err
	}

	priv := new(internalEcdsa.PrivateKey)
	priv.PublicKey.Curve = c.curve
	priv.D = new(big.Int).SetBytes(k.Bytes(c.N))
	priv.PublicKey.X, priv.PublicKey.Y, err = c.pointToAffine(Q)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// randomPoint returns a random scalar and the corresponding point using the
// procedure given in FIPS 186-4, Appendix B.5.2 (rejection sampling).
func randomPoint[Point nistPoint[Point]](c *nistCurve[Point], rand io.Reader) (k *bigmod.Nat, p Point, err error) {
	k = bigmod.NewNat()
	for {
		b := make([]byte, c.N.Size())
		if _, err = io.ReadFull(rand, b); err != nil {
			return
		}

		// Mask off any excess bits to increase the chance of hitting a value in
		// (0, N). These are the most dangerous lines in the package and maybe in
		// the library: a single bit of bias in the selection of nonces would likely
		// lead to key recovery, but no tests would fail. Look but DO NOT TOUCH.
		if excess := len(b)*8 - c.N.BitLen(); excess > 0 {
			// Just to be safe, assert that this only happens for the one curve that
			// doesn't have a round number of bits.
			if excess != 0 && c.curve.Params().Name != "P-521" {
				panic("ecdsa: internal error: unexpectedly masking off bits")
			}
			b[0] >>= excess
		}

		// FIPS 186-4 makes us check k <= N - 2 and then add one.
		// Checking 0 < k <= N - 1 is strictly equivalent.
		// None of this matters anyway because the chance of selecting
		// zero is cryptographically negligible.
		if _, err = k.SetBytes(b, c.N); err == nil && k.IsZero() == 0 {
			break
		}

		if testingOnlyRejectionSamplingLooped != nil {
			testingOnlyRejectionSamplingLooped()
		}
	}

	p, err = c.newPoint().ScalarBaseMult(k.Bytes(c.N))
	return
}

// testingOnlyRejectionSamplingLooped is called when rejection sampling in
// randomPoint rejects a candidate for being higher than the modulus.
var testingOnlyRejectionSamplingLooped func()

// errNoAsm is returned by signAsm and verifyAsm when the assembly
// implementation is not available.
var errNoAsm = errors.New("no assembly implementation available")

// SignASN1 signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the ASN.1 encoded signature.
func SignASN1(rand io.Reader, priv *internalEcdsa.PrivateKey, hash []byte) ([]byte, error) {
	csprng, err := mixedCSPRNG(rand, priv, hash)
	if err != nil {
		return nil, err
	}

	if sig, err := signAsm(priv, csprng, hash); err != errNoAsm {
		return sig, err
	}

	switch priv.Curve.Params() {
	case elliptic.P224().Params():
		return signNISTEC(p224(), priv, csprng, hash)
	case elliptic.P256().Params():
		return signNISTEC(p256(), priv, csprng, hash)
	case elliptic.P384().Params():
		return signNISTEC(p384(), priv, csprng, hash)
	case elliptic.P521().Params():
		return signNISTEC(p521(), priv, csprng, hash)
	default:
		return signLegacy(priv, csprng, hash)
	}
}

func signNISTEC[Point nistPoint[Point]](c *nistCurve[Point], priv *internalEcdsa.PrivateKey, csprng io.Reader, hash []byte) (sig []byte, err error) {
	// SEC 1, Version 2.0, Section 4.1.3

	k, R, err := randomPoint(c, csprng)
	if err != nil {
		return nil, err
	}

	// kInv = k⁻¹
	kInv := bigmod.NewNat()
	inverse(c, kInv, k)

	Rx, err := R.BytesX()
	if err != nil {
		return nil, err
	}
	r, err := bigmod.NewNat().SetOverflowingBytes(Rx, c.N)
	if err != nil {
		return nil, err
	}

	// The spec wants us to retry here, but the chance of hitting this condition
	// on a large prime-order group like the NIST curves we support is
	// cryptographically negligible. If we hit it, something is awfully wrong.
	if r.IsZero() == 1 {
		return nil, errors.New("ecdsa: internal error: r is zero")
	}

	e := bigmod.NewNat()
	hashToNat(c, e, hash)

	s, err := bigmod.NewNat().SetBytes(priv.D.Bytes(), c.N)
	if err != nil {
		return nil, err
	}
	s.Mul(r, c.N)
	s.Add(e, c.N)
	s.Mul(kInv, c.N)

	// Again, the chance of this happening is cryptographically negligible.
	if s.IsZero() == 1 {
		return nil, errors.New("ecdsa: internal error: s is zero")
	}

	return encodeSignature(r.Bytes(c.N), s.Bytes(c.N))
}

func encodeSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

// addASN1IntBytes encodes in ASN.1 a positive integer represented as
// a big-endian byte slice with zero or more leading zeroes.
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

// inverse sets kInv to the inverse of k modulo the order of the curve.
func inverse[Point nistPoint[Point]](c *nistCurve[Point], kInv, k *bigmod.Nat) {
	if c.curve.Params().Name == "P-256" {
		kBytes, err := nistec.P256OrdInverse(k.Bytes(c.N))
		// Some platforms don't implement P256OrdInverse, and always return an error.
		if err == nil {
			_, err := kInv.SetBytes(kBytes, c.N)
			if err != nil {
				panic("ecdsa: internal error: P256OrdInverse produced an invalid value")
			}
			return
		}
	}

	// Calculate the inverse of s in GF(N) using Fermat's method
	// (exponentiation modulo P - 2, per Euler's theorem)
	kInv.Exp(k, c.nMinus2, c.N)
}

// hashToNat sets e to the left-most bits of hash, according to
// SEC 1, Section 4.1.3, point 5 and Section 4.1.4, point 3.
func hashToNat[Point nistPoint[Point]](c *nistCurve[Point], e *bigmod.Nat, hash []byte) {
	// ECDSA asks us to take the left-most log2(N) bits of hash, and use them as
	// an integer modulo N. This is the absolute worst of all worlds: we still
	// have to reduce, because the result might still overflow N, but to take
	// the left-most bits for P-521 we have to do a right shift.
	if size := c.N.Size(); len(hash) > size {
		hash = hash[:size]
		if excess := len(hash)*8 - c.N.BitLen(); excess > 0 {
			hash = bytes.Clone(hash)
			for i := len(hash) - 1; i >= 0; i-- {
				hash[i] >>= excess
				if i > 0 {
					hash[i] |= hash[i-1] << (8 - excess)
				}
			}
		}
	}
	_, err := e.SetOverflowingBytes(hash, c.N)
	if err != nil {
		panic("ecdsa: internal error: truncated hash is too long")
	}
}

// mixedCSPRNG returns a CSPRNG that mixes entropy from rand with the message
// and the private key, to protect the key in case rand fails. This is
// equivalent in security to RFC 6979 deterministic nonce generation, but still
// produces randomized signatures.
func mixedCSPRNG(rand io.Reader, priv *internalEcdsa.PrivateKey, hash []byte) (io.Reader, error) {
	// This implementation derives the nonce from an AES-CTR CSPRNG keyed by:
	//
	//    SHA2-512(priv.D || entropy || hash)[:32]
	//
	// The CSPRNG key is indifferentiable from a random oracle as shown in
	// [Coron], the AES-CTR stream is indifferentiable from a random oracle
	// under standard cryptographic assumptions (see [Larsson] for examples).
	//
	// [Coron]: https://cs.nyu.edu/~dodis/ps/merkle.pdf
	// [Larsson]: https://web.archive.org/web/20040719170906/https://www.nada.kth.se/kurser/kth/2D1441/semteo03/lecturenotes/assump.pdf

	// Get 256 bits of entropy from rand.
	entropy := make([]byte, 32)
	if _, err := io.ReadFull(rand, entropy); err != nil {
		return nil, err
	}

	// Initialize an SHA-512 hash context; digest...
	md := sha512.New()
	md.Write(priv.D.Bytes()) // the private key,
	md.Write(entropy)        // the entropy,
	md.Write(hash)           // and the input hash;
	key := md.Sum(nil)[:32]  // and compute ChopMD-256(SHA-512),
	// which is an indifferentiable MAC.

	// Create an AES-CTR instance to use as a CSPRNG.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a CSPRNG that xors a stream of zeros with
	// the output of the AES-CTR instance.
	const aesIV = "IV for ECDSA CTR"
	return &cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}, nil
}

type zr struct{}

var zeroReader = zr{}

// Read replaces the contents of dst with zeros. It is safe for concurrent use.
func (zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

type nistCurve[Point nistPoint[Point]] struct {
	newPoint func() Point
	curve    elliptic.Curve
	N        *bigmod.Modulus
	nMinus2  []byte
}

// nistPoint is a generic constraint for the nistec Point types.
type nistPoint[T any] interface {
	Bytes() []byte
	BytesX() ([]byte, error)
	SetBytes([]byte) (T, error)
	Add(T, T) T
	ScalarMult(T, []byte) (T, error)
	ScalarBaseMult([]byte) (T, error)
}

// pointToAffine is used to convert a nistec Point to a PublicKey.
func (curve *nistCurve[Point]) pointToAffine(p Point) (x, y *big.Int, err error) {
	out := p.Bytes()
	if len(out) == 1 && out[0] == 0 {
		// This is the encoding of the point at infinity.
		return nil, nil, errors.New("ecdsa: public key point is the infinity")
	}
	byteLen := (curve.curve.Params().BitSize + 7) / 8
	x = new(big.Int).SetBytes(out[1 : 1+byteLen])
	y = new(big.Int).SetBytes(out[1+byteLen:])
	return x, y, nil
}

var p224Once sync.Once
var _p224 *nistCurve[*nistec.P224Point]

func p224() *nistCurve[*nistec.P224Point] {
	p224Once.Do(func() {
		_p224 = &nistCurve[*nistec.P224Point]{
			newPoint: func() *nistec.P224Point { return nistec.NewP224Point() },
		}
		precomputeParams(_p224, elliptic.P224())
	})
	return _p224
}

var p256Once sync.Once
var _p256 *nistCurve[*nistec.P256Point]

func p256() *nistCurve[*nistec.P256Point] {
	p256Once.Do(func() {
		_p256 = &nistCurve[*nistec.P256Point]{
			newPoint: func() *nistec.P256Point { return nistec.NewP256Point() },
		}
		precomputeParams(_p256, elliptic.P256())
	})
	return _p256
}

var p384Once sync.Once
var _p384 *nistCurve[*nistec.P384Point]

func p384() *nistCurve[*nistec.P384Point] {
	p384Once.Do(func() {
		_p384 = &nistCurve[*nistec.P384Point]{
			newPoint: func() *nistec.P384Point { return nistec.NewP384Point() },
		}
		precomputeParams(_p384, elliptic.P384())
	})
	return _p384
}

var p521Once sync.Once
var _p521 *nistCurve[*nistec.P521Point]

func p521() *nistCurve[*nistec.P521Point] {
	p521Once.Do(func() {
		_p521 = &nistCurve[*nistec.P521Point]{
			newPoint: func() *nistec.P521Point { return nistec.NewP521Point() },
		}
		precomputeParams(_p521, elliptic.P521())
	})
	return _p521
}

func precomputeParams[Point nistPoint[Point]](c *nistCurve[Point], curve elliptic.Curve) {
	params := curve.Params()
	c.curve = curve
	c.N = bigmod.NewModulusFromBig(params.N)
	c.nMinus2 = new(big.Int).Sub(params.N, big.NewInt(2)).Bytes()
}
