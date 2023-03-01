// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rsa implements RSA encryption as specified in PKCS #1 and RFC 8017.
//
// RSA is a single, fundamental operation that is used in this package to
// implement either public-key encryption or public-key signatures.
//
// The original specification for encryption and signatures with RSA is PKCS #1
// and the terms "RSA encryption" and "RSA signatures" by default refer to
// PKCS #1 version 1.5. However, that specification has flaws and new designs
// should use version 2, usually called by just OAEP and PSS, where
// possible.
//
// Two sets of interfaces are included in this package. When a more abstract
// interface isn't necessary, there are functions for encrypting/decrypting
// with v1.5/OAEP and signing/verifying with v1.5/PSS. If one needs to abstract
// over the public key primitive, the PrivateKey type implements the
// Decrypter and Signer interfaces from the crypto package.
//
// Operations in this package are implemented using constant-time algorithms,
// except for [GenerateKey], [PrivateKey.Precompute], and [PrivateKey.Validate].
// Every other operation only leaks the bit size of the involved values, which
// all depend on the selected key size.
package rsa

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/big"

	"github.com/wokdav/gopki/generator/dcrypto/internal/bigmod"

	internalRsa "crypto/rsa"
)

var bigOne = big.NewInt(1)

var (
	errPublicModulus       = errors.New("crypto/rsa: missing public modulus")
	errPublicExponentSmall = errors.New("crypto/rsa: public exponent too small")
	errPublicExponentLarge = errors.New("crypto/rsa: public exponent too large")
)

// checkPub sanity checks the public key before we use it.
// We require pub.E to fit into a 32-bit integer so that we
// do not have different behavior depending on whether
// int is 32 or 64 bits. See also
// https://www.imperialviolet.org/2012/03/16/rsae.html.
func checkPub(pub *internalRsa.PublicKey) error {
	if pub.N == nil {
		return errPublicModulus
	}
	if pub.E < 2 {
		return errPublicExponentSmall
	}
	if pub.E > 1<<31-1 {
		return errPublicExponentLarge
	}
	return nil
}

// Prime returns a number of the given bit length that is prime with high probability.
// Prime will return error for any error returned by rand.Read or if bits < 2.
func Prime(rand io.Reader, bits int) (*big.Int, error) {
	if bits < 2 {
		return nil, errors.New("crypto/rand: prime size must be at least 2-bit")
	}

	b := uint(bits % 8)
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, (bits+7)/8)
	p := new(big.Int)

	for {
		if _, err := io.ReadFull(rand, bytes); err != nil {
			return nil, err
		}

		// Clear bits in the first byte to make sure the candidate has a size <= bits.
		bytes[0] &= uint8(int(1<<b) - 1)
		// Don't let the value be too small, i.e, set the most significant two bits.
		// Setting the top two bits, rather than just the top bit,
		// means that when two of these values are multiplied together,
		// the result isn't ever one bit short.
		if b >= 2 {
			bytes[0] |= 3 << (b - 2)
		} else {
			// Here b==1, because b cannot be zero.
			bytes[0] |= 1
			if len(bytes) > 1 {
				bytes[1] |= 0x80
			}
		}
		// Make the value odd since an even number this large certainly isn't prime.
		bytes[len(bytes)-1] |= 1

		p.SetBytes(bytes)
		if p.ProbablyPrime(20) {
			return p, nil
		}
	}
}

// GenerateKey generates an RSA keypair of the given bit size using the
// random source random (for example, crypto/rand.Reader).
func GenerateKey(random io.Reader, bits int) (*internalRsa.PrivateKey, error) {
	return GenerateMultiPrimeKey(random, 2, bits)
}

// GenerateMultiPrimeKey generates a multi-prime RSA keypair of the given bit
// size and the given random source.
//
// Table 1 in "[On the Security of Multi-prime RSA]" suggests maximum numbers of
// primes for a given bit size.
//
// Although the public keys are compatible (actually, indistinguishable) from
// the 2-prime case, the private keys are not. Thus it may not be possible to
// export multi-prime private keys in certain formats or to subsequently import
// them into other code.
//
// This package does not implement CRT optimizations for multi-prime RSA, so the
// keys with more than two primes will have worse performance.
//
// Note: The use of this function with a number of primes different from
// two is not recommended for the above security, compatibility, and performance
// reasons. Use GenerateKey instead.
//
// [On the Security of Multi-prime RSA]: http://www.cacr.math.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
func GenerateMultiPrimeKey(random io.Reader, nprimes int, bits int) (*internalRsa.PrivateKey, error) {
	priv := new(internalRsa.PrivateKey)
	priv.E = 65537

	if nprimes < 2 {
		return nil, errors.New("crypto/rsa: GenerateMultiPrimeKey: nprimes must be >= 2")
	}

	if bits < 64 {
		primeLimit := float64(uint64(1) << uint(bits/nprimes))
		// pi approximates the number of primes less than primeLimit
		pi := primeLimit / (math.Log(primeLimit) - 1)
		// Generated primes start with 11 (in binary) so we can only
		// use a quarter of them.
		pi /= 4
		// Use a factor of two to ensure that key generation terminates
		// in a reasonable amount of time.
		pi /= 2
		if pi <= float64(nprimes) {
			return nil, errors.New("crypto/rsa: too few primes of given length to generate an RSA key")
		}
	}

	primes := make([]*big.Int, nprimes)

NextSetOfPrimes:
	for {
		todo := bits
		// crypto/rand should set the top two bits in each prime.
		// Thus each prime has the form
		//   p_i = 2^bitlen(p_i) × 0.11... (in base 2).
		// And the product is:
		//   P = 2^todo × α
		// where α is the product of nprimes numbers of the form 0.11...
		//
		// If α < 1/2 (which can happen for nprimes > 2), we need to
		// shift todo to compensate for lost bits: the mean value of 0.11...
		// is 7/8, so todo + shift - nprimes * log2(7/8) ~= bits - 1/2
		// will give good results.
		if nprimes >= 7 {
			todo += (nprimes - 2) / 5
		}
		for i := 0; i < nprimes; i++ {
			var err error
			primes[i], err = Prime(random, todo/(nprimes-i))
			if err != nil {
				return nil, err
			}
			todo -= primes[i].BitLen()
		}

		// Make sure that primes is pairwise unequal.
		for i, prime := range primes {
			for j := 0; j < i; j++ {
				if prime.Cmp(primes[j]) == 0 {
					continue NextSetOfPrimes
				}
			}
		}

		n := new(big.Int).Set(bigOne)
		totient := new(big.Int).Set(bigOne)
		pminus1 := new(big.Int)
		for _, prime := range primes {
			n.Mul(n, prime)
			pminus1.Sub(prime, bigOne)
			totient.Mul(totient, pminus1)
		}
		if n.BitLen() != bits {
			// This should never happen for nprimes == 2 because
			// crypto/rand should set the top two bits in each prime.
			// For nprimes > 2 we hope it does not happen often.
			continue NextSetOfPrimes
		}

		priv.D = new(big.Int)
		e := big.NewInt(int64(priv.E))
		ok := priv.D.ModInverse(e, totient)

		if ok != nil {
			priv.Primes = primes
			priv.N = n
			break
		}
	}

	priv.Precompute()
	return priv, nil
}

func encrypt(pub *internalRsa.PublicKey, plaintext []byte) ([]byte, error) {
	N := bigmod.NewModulusFromBig(pub.N)
	m, err := bigmod.NewNat().SetBytes(plaintext, N)
	if err != nil {
		return nil, err
	}
	e := intToBytes(pub.E)

	return bigmod.NewNat().Exp(m, e, N).Bytes(N), nil
}

// intToBytes returns i as a big-endian slice of bytes with no leading zeroes,
// leaking only the bit size of i through timing side-channels.
func intToBytes(i int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(i))
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

// decrypt performs an RSA decryption of ciphertext into out. If check is true,
// m^e is calculated and compared with ciphertext, in order to defend against
// errors in the CRT computation.
func decrypt(priv *internalRsa.PrivateKey, ciphertext []byte, check bool) ([]byte, error) {
	var (
		err  error
		m, c *bigmod.Nat
		N    *bigmod.Modulus
	)

	//gopki note: precomputed values can't be used here
	//since we can't access those values from the outside
	//of the package and I don't want to fork the keys as well
	N = bigmod.NewModulusFromBig(priv.N)
	c, err = bigmod.NewNat().SetBytes(ciphertext, N)
	if err != nil {
		return nil, internalRsa.ErrDecryption
	}
	m = bigmod.NewNat().Exp(c, priv.D.Bytes(), N)

	if check {
		c1 := bigmod.NewNat().Exp(m, intToBytes(priv.E), N)
		if c1.Equal(c) != 1 {
			return nil, internalRsa.ErrDecryption
		}
	}

	return m.Bytes(N), nil
}

const withCheck = true
const noCheck = false
