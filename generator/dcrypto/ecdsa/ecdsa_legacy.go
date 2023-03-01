// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdsa

import (
	"crypto/elliptic"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	internalEcdsa "crypto/ecdsa"
)

// This file contains a math/big implementation of ECDSA that is only used for
// deprecated custom curves.

func generateLegacy(c elliptic.Curve, rand io.Reader) (*internalEcdsa.PrivateKey, error) {
	k, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}

	priv := new(internalEcdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

// hashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

var errZeroParam = errors.New("zero parameter")

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the signature as a pair of integers. Most applications should use
// SignASN1 instead of dealing directly with r, s.
func Sign(rand io.Reader, priv *internalEcdsa.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	sig, err := SignASN1(rand, priv, hash)
	if err != nil {
		return nil, nil, err
	}

	r, s = new(big.Int), new(big.Int)
	var inner cryptobyte.String
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1 from SignASN1")
	}
	return r, s, nil
}

func signLegacy(priv *internalEcdsa.PrivateKey, csprng io.Reader, hash []byte) (sig []byte, err error) {
	c := priv.Curve

	// SEC 1, Version 2.0, Section 4.1.3
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, errZeroParam
	}
	var k, kInv, r, s *big.Int
	for {
		for {
			k, err = randFieldElement(c, csprng)
			if err != nil {
				return nil, err
			}

			kInv = new(big.Int).ModInverse(k, N)

			r, _ = c.ScalarBaseMult(k.Bytes())
			r.Mod(r, N)
			if r.Sign() != 0 {
				break
			}
		}

		e := hashToInt(hash, c)
		s = new(big.Int).Mul(priv.D, r)
		s.Add(s, e)
		s.Mul(s, kInv)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			break
		}
	}

	return encodeSignature(r.Bytes(), s.Bytes())
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid. Most applications should
// use VerifyASN1 instead of dealing directly with r, s.
func Verify(pub *internalEcdsa.PublicKey, hash []byte, r, s *big.Int) bool {
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	sig, err := encodeSignature(r.Bytes(), s.Bytes())
	if err != nil {
		return false
	}
	return internalEcdsa.VerifyASN1(pub, hash, sig)
}

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.2.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	// See randomPoint for notes on the algorithm. This has to match, or s390x
	// signatures will come out different from other architectures, which will
	// break TLS recorded tests.
	for {
		N := c.Params().N
		b := make([]byte, (N.BitLen()+7)/8)
		if _, err = io.ReadFull(rand, b); err != nil {
			return
		}
		if excess := len(b)*8 - N.BitLen(); excess > 0 {
			b[0] >>= excess
		}
		k = new(big.Int).SetBytes(b)
		if k.Sign() != 0 && k.Cmp(N) < 0 {
			return
		}
	}
}
