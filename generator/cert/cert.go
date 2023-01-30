// Package cert includes all necessary functions and data structures for
// certificate generation. It handles everything regarding ASN.1, PEM and
// crypto. It is designed to becompletely oblivious to any configuration
// or database. It just serves as a general-purpose generator for keys
// and certificates.
//
// Unsigned certificates and keys are bundled in a [cert.CertificateContext].
// CertificateContexts are able to sign their data to yield a [cert.Certificate].
package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/keybase/go-crypto/brainpool"
)

// Certificate data structure that can be serialized
// via [asn1.Unmarshal]
type Certificate struct {
	TBSCertificate     TbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// Unsigned certificate structure that can be serialized
// via [asn1.Unmarshal]
type TbsCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             pkix.RDNSequence
	Validity           validity
	Subject            pkix.RDNSequence
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// Structure for all issuer related information.
// This includes everything needed for signing,
// as well as information, that extensions might need.
// For example, an AuthorityKeyIdentifier extension could
// use the raw public key of the issuer to calculate a hash.
type IssuerContext struct {
	crypto.PrivateKey
	publicKeyRaw []byte
	issuerDn     pkix.RDNSequence
}

// Represents all information about an entity prior to signing.
// This includes the entities' private key, certificate data
// and issuer information.
type CertificateContext struct {
	*TbsCertificate
	crypto.PrivateKey
	Issuer     *IssuerContext
	Extensions []ExtensionBuilder
}

// Interface that is used to build X.509 extensions lazily.
// A lot of information might still be unknown, when a
// [config.CertificateContent] is built initially. Things
// like issuer information might be available much later
// and this interface ensures that external parties have
// enough time to manipulate their [cert.CertificateContext]
// before the extensions are built.
type ExtensionBuilder interface {
	Compile(ctx *CertificateContext) (*pkix.Extension, error)
}

// Algorithm Identifiers
var (
	oidRsaEncryption = []int{1, 2, 840, 113549, 1, 1, 1}
	oidEcPublicKey   = []int{1, 2, 840, 10045, 2, 1}
)

// Signature Algorithm OIDs
var (
	oidRSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidRSAWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidRSAWithSHA384   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidRSAWithSHA512   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// EC Curve OIDs
var (
	oidP224            = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidP256            = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384            = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidP521            = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	oidBrainpoolP384r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}
	oidBrainpoolP512r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}
	oidBrainpoolP256t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 8}
	oidBrainpoolP384t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 12}
	oidBrainpoolP512t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 14}
)

var (
	oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}
)

var (
	defaultRandom  *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	snMax          *big.Int   = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(16), big.NewInt(0))
	defaultSubject            = pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  oidCommonName,
				Value: "Dummy Certificate"}},
	}
)

// Writes the given [cert.Certificate] into a PEM file.
// For simplicities' sake PEM files are currently assumed
// to contain only one block.
// It fails when either [asn1.Unmarshal] or [pem.Encode]
// return an error.
func (c Certificate) WritePem(w io.Writer) error {
	//certificate
	b, err := asn1.Marshal(c)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	}

	if err = pem.Encode(w, block); err != nil {
		return err
	}

	return nil
}

// Writes the given [crypto.PublicKey] into an unencrypted
// PKCS#8 PEM file.
// For simplicities' sake PEM files are currently assumed
// to contain only one block.
// It fails when either [x509.MarshalPKCS8PrivateKey] or [pem.Encode]
// return an error.
func WritePrivateKeyToPem(prk crypto.PrivateKey, w io.Writer) error {
	b, err := x509.MarshalPKCS8PrivateKey(prk)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}

	if err = pem.Encode(w, block); err != nil {
		return err
	}

	return nil
}

// Find first block, where blockType is a substring of the block's type
// and return the bytes in that block.
func pemFindFirst(pemBytes []byte, blockType string) ([]byte, error) {
	currentBlock := pemBytes
	var p *pem.Block

	for {
		p, currentBlock = pem.Decode(currentBlock)
		if p == nil {
			if len(currentBlock) != 0 {
				return nil, errors.New("can't decode data as PEM")
			}

			break
		}

		if strings.Contains(p.Type, blockType) {
			return p.Bytes, nil
		}
	}

	return nil, fmt.Errorf("no block containing '%v' was found", blockType)
}

// Find first PRIVATE KEY in the provided reader and return it
func ImportKeyPem(pemBytes []byte) (crypto.PrivateKey, error) {
	keyBytes, err := pemFindFirst(pemBytes, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Find first CERTIFICATE in the provided reader, then unmarshal and return it
func ImportCertPem(pemBytes []byte) (*Certificate, error) {
	certBytes, err := pemFindFirst(pemBytes, "CERTIFICATE")
	if err != nil {
		return nil, err
	}

	cert := &Certificate{}
	_, err = asn1.Unmarshal(certBytes, cert)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// Syntactic sugar to yield a [config.IssuerContext] from a
// [config.CertificateContext].
func AsIssuer(c CertificateContext) IssuerContext {
	return IssuerContext{
		publicKeyRaw: c.PublicKey.PublicKey.Bytes,
		issuerDn:     c.Subject,
		PrivateKey:   c.PrivateKey,
	}
}

// Converts an OID in dotted decimal form into a [asn1.ObjectIdentifier].
func OidFromString(s string) (asn1.ObjectIdentifier, error) {
	if len(s) == 0 {
		return asn1.ObjectIdentifier{}, nil
	}
	oidList := strings.Split(s, ".")
	oid := make([]int, len(oidList))

	for i, number := range oidList {
		n, err := strconv.Atoi(number)
		if err != nil {
			return nil, err
		}

		oid[i] = n
	}

	return asn1.ObjectIdentifier(oid), nil
}

type keyType uint

const (
	rsaKey keyType = iota
	ecKey
)

type SignatureAlgorithm uint

const (
	ECDSAwithSHA1 SignatureAlgorithm = iota
	ECDSAwithSHA256
	ECDSAwithSHA384
	ECDSAwithSHA512
	RSAwithSHA1
	RSAwithSHA256
	RSAwithSHA384
	RSAwithSHA512
)

type KeyAlgorithm uint

const (
	RSA1024 KeyAlgorithm = iota
	RSA2048
	RSA4096
	RSA8192
	P224
	P256
	P384
	P521
	BrainpoolP256r1
	BrainpoolP384r1
	BrainpoolP512r1
	BrainpoolP256t1
	BrainpoolP384t1
	BrainpoolP512t1
)

var keyTypes map[KeyAlgorithm]keyType = map[KeyAlgorithm]keyType{
	RSA1024:         rsaKey,
	RSA2048:         rsaKey,
	RSA4096:         rsaKey,
	RSA8192:         rsaKey,
	P224:            ecKey,
	P256:            ecKey,
	P384:            ecKey,
	P521:            ecKey,
	BrainpoolP256r1: ecKey,
	BrainpoolP384r1: ecKey,
	BrainpoolP512r1: ecKey,
	BrainpoolP256t1: ecKey,
	BrainpoolP384t1: ecKey,
	BrainpoolP512t1: ecKey,
}

var curves map[KeyAlgorithm]elliptic.Curve
var curveOids map[string][]byte

func init() {
	curves = make(map[KeyAlgorithm]elliptic.Curve, 10)
	curves[P224] = elliptic.P224()
	curves[P256] = elliptic.P256()
	curves[P384] = elliptic.P384()
	curves[P521] = elliptic.P521()
	curves[BrainpoolP256r1] = brainpool.P256r1()
	curves[BrainpoolP384r1] = brainpool.P384r1()
	curves[BrainpoolP512r1] = brainpool.P512r1()
	curves[BrainpoolP256t1] = brainpool.P256t1()
	curves[BrainpoolP384t1] = brainpool.P384t1()
	curves[BrainpoolP512t1] = brainpool.P512t1()

	curveOids = make(map[string][]byte, 10)
	curveOids[curves[P224].Params().Name], _ = asn1.Marshal(oidP224)
	curveOids[curves[P256].Params().Name], _ = asn1.Marshal(oidP256)
	curveOids[curves[P384].Params().Name], _ = asn1.Marshal(oidP384)
	curveOids[curves[P521].Params().Name], _ = asn1.Marshal(oidP521)
	curveOids[curves[BrainpoolP256r1].Params().Name], _ = asn1.Marshal(oidBrainpoolP256r1)
	curveOids[curves[BrainpoolP384r1].Params().Name], _ = asn1.Marshal(oidBrainpoolP384r1)
	curveOids[curves[BrainpoolP512r1].Params().Name], _ = asn1.Marshal(oidBrainpoolP512r1)
	curveOids[curves[BrainpoolP256t1].Params().Name], _ = asn1.Marshal(oidBrainpoolP256t1)
	curveOids[curves[BrainpoolP384t1].Params().Name], _ = asn1.Marshal(oidBrainpoolP384t1)
	curveOids[curves[BrainpoolP512t1].Params().Name], _ = asn1.Marshal(oidBrainpoolP512t1)
}

var sigAlgOids map[SignatureAlgorithm]asn1.ObjectIdentifier = map[SignatureAlgorithm]asn1.ObjectIdentifier{
	RSAwithSHA1:     oidRSAWithSHA1,
	RSAwithSHA256:   oidRSAWithSHA256,
	RSAwithSHA384:   oidRSAWithSHA384,
	RSAwithSHA512:   oidRSAWithSHA512,
	ECDSAwithSHA1:   oidECDSAWithSHA1,
	ECDSAwithSHA256: oidECDSAWithSHA256,
	ECDSAwithSHA384: oidECDSAWithSHA384,
	ECDSAwithSHA512: oidECDSAWithSHA512,
}

func (ctx *CertificateContext) SetPrivateKey(key crypto.PrivateKey) error {
	ctx.PrivateKey = key
	rsaKey, ok := key.(*rsa.PrivateKey)
	if ok {
		ctx.TbsCertificate.PublicKey.Algorithm.Algorithm = oidRsaEncryption
		ctx.TbsCertificate.PublicKey.Algorithm.Parameters = asn1.NullRawValue
		ctx.TbsCertificate.PublicKey.PublicKey.Bytes = x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
		return nil
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if ok {
		oid, exists := curveOids[ecKey.Params().Name]

		if !exists {
			return fmt.Errorf("cert: can't import private key, since the curve '%v' is unknown", ecKey.Params().Name)
		}
		_, err := asn1.Unmarshal(oid, &ctx.TbsCertificate.PublicKey.Algorithm.Parameters)
		if err != nil {
			return err
		}
		ctx.TbsCertificate.PublicKey.Algorithm.Algorithm = oidEcPublicKey
		if err != nil {
			return err
		}

		ctx.TbsCertificate.PublicKey.PublicKey.Bytes = elliptic.Marshal(ecKey.Curve, ecKey.PublicKey.X, ecKey.PublicKey.Y)
		curveParam, exists := curveOids[ecKey.Params().Name]
		if !exists {
			return fmt.Errorf("cert: unknown ec key curve: %v", ecKey.Params().Name)
		}
		_, err = asn1.Unmarshal(curveParam, &ctx.TbsCertificate.PublicKey.Algorithm.Parameters)
		if err != nil {
			return err
		}
	}

	return errors.New("cert: private key neither compatible with ecdsa.PrivateKey nor with rsa.PrivateKey")
}

func (ctx *CertificateContext) SetIssuer(issuerCtx IssuerContext) {
	ctx.TbsCertificate.Issuer = issuerCtx.issuerDn
	ctx.Issuer = &issuerCtx
}

func (ctx *CertificateContext) GeneratePrivateKey(keyAlg KeyAlgorithm) error {
	var err error
	var prk crypto.PrivateKey

	keyType, exists := keyTypes[keyAlg]
	if !exists {
		return fmt.Errorf("cert: illegal key algorithm: %#v", keyAlg)
	}

	if keyType == rsaKey {
		var prkTmp *rsa.PrivateKey
		var bitSize int
		switch keyAlg {
		case RSA1024:
			bitSize = 1024
		case RSA2048:
			bitSize = 2048
		case RSA4096:
			bitSize = 4096
		case RSA8192:
			bitSize = 8192
		default:
			return fmt.Errorf("cert: incompatible key algorithm for RSA: %v", keyAlg)
		}

		prkTmp, err = rsa.GenerateKey(defaultRandom, bitSize)
		if err != nil {
			return err
		}

		ctx.TbsCertificate.PublicKey.PublicKey.Bytes = x509.MarshalPKCS1PublicKey(&prkTmp.PublicKey)
		prk = prkTmp
	} else {
		var prkTmp *ecdsa.PrivateKey
		var curve elliptic.Curve

		curve, exists := curves[keyAlg]
		if !exists {
			return fmt.Errorf("cert: unknown ec key algorithm identifier: %v", keyAlg)
		}

		prkTmp, err = ecdsa.GenerateKey(curve, defaultRandom)
		if err != nil {
			return err
		}
		prk = prkTmp
	}

	ctx.SetPrivateKey(prk)

	return nil
}

// This is the intended way to generate a new [cert.CertificateContext].
// It always generates a new key corresponding to the keyAlg argument.
//
// The function applies the following defaults:
// - SerialNumber is always random
// - If subject is nil, it will be set to "CN=DummyCertificate"
// - The context is built to be self-signed. If this is not intended, issuer context should be changed afterwards accordingly.
// - The alias is set to a hexadecimal representation of the serial number
// - Time values are converted to UTC
// - The extensions will be generated after calling the [cert.Sign] function
func NewCertificateContext(subject pkix.RDNSequence, ext []ExtensionBuilder, validNotBefore time.Time, validNotAfter time.Time) *CertificateContext {
	tbs := TbsCertificate{}
	tbs.Version = 2
	tbs.SerialNumber = new(big.Int).Rand(defaultRandom, snMax)

	tbs.Validity.NotBefore = validNotBefore.UTC()
	tbs.Validity.NotAfter = validNotAfter.UTC()
	if subject != nil {
		tbs.Subject = subject
	} else {
		tbs.Subject = defaultSubject
	}

	tbs.Issuer = tbs.Subject
	ctx := CertificateContext{&tbs, nil, &IssuerContext{
		PrivateKey:   nil,
		publicKeyRaw: tbs.PublicKey.PublicKey.Bytes,
		issuerDn:     tbs.Subject,
	}, ext}

	return &ctx
}

func resolveAlg(alg SignatureAlgorithm) (crypto.Hash, hash.Hash, asn1.ObjectIdentifier, keyType, error) {
	var hashAlgId crypto.Hash
	var hashAlg hash.Hash
	var sigAlgOid asn1.ObjectIdentifier

	var wantKey keyType
	var err error
	switch alg {
	case RSAwithSHA1:
		hashAlg = crypto.SHA1.New()
		hashAlgId = crypto.SHA1
		sigAlgOid = oidRSAWithSHA1
		wantKey = rsaKey
	case RSAwithSHA256:
		hashAlg = crypto.SHA256.New()
		hashAlgId = crypto.SHA256
		sigAlgOid = oidRSAWithSHA256
		wantKey = rsaKey
	case RSAwithSHA384:
		hashAlg = crypto.SHA384.New()
		hashAlgId = crypto.SHA384
		sigAlgOid = oidRSAWithSHA384
		wantKey = rsaKey
	case RSAwithSHA512:
		hashAlg = crypto.SHA512.New()
		hashAlgId = crypto.SHA512
		sigAlgOid = oidRSAWithSHA512
		wantKey = rsaKey
	case ECDSAwithSHA1:
		hashAlg = crypto.SHA1.New()
		hashAlgId = crypto.SHA1
		sigAlgOid = oidECDSAWithSHA1
		wantKey = ecKey
	case ECDSAwithSHA256:
		hashAlg = crypto.SHA256.New()
		hashAlgId = crypto.SHA256
		sigAlgOid = oidECDSAWithSHA256
		wantKey = ecKey
	case ECDSAwithSHA384:
		hashAlg = crypto.SHA384.New()
		hashAlgId = crypto.SHA384
		sigAlgOid = oidECDSAWithSHA384
		wantKey = ecKey
	case ECDSAwithSHA512:
		hashAlg = crypto.SHA512.New()
		hashAlgId = crypto.SHA512
		sigAlgOid = oidECDSAWithSHA512
		wantKey = ecKey
	default:
		err = fmt.Errorf("cert: unknown signature algorithm :'%v'", alg)
	}

	return hashAlgId, hashAlg, sigAlgOid, wantKey, err
}

// Sign the provided information to finally yield a certificate.
// This is also the point, where the extensions will be generated
// through the provided Builder interfaces.
//
// This function will also populate some certificate prior to signing:
// - Signature Algorithm will be set according to alg.
// - Issuer will be set according to the provided [cert.IssuerContext]
// - All extensions will be overwritten with the builder's outputs.
func (c *CertificateContext) Sign(alg SignatureAlgorithm) (*Certificate, error) {
	out := Certificate{}
	out.TBSCertificate = *c.TbsCertificate

	if c.Issuer == nil || c.Issuer.PrivateKey == nil {
		return nil, errors.New("cert: provided IssuerContext is nil. can't sign")
	}

	out.TBSCertificate.SignatureAlgorithm = pkix.AlgorithmIdentifier{
		Algorithm: sigAlgOids[alg],
	}
	out.TBSCertificate.Issuer = c.Issuer.issuerDn

	//generate extensions as late as possible
	out.TBSCertificate.Extensions = make([]pkix.Extension, len(c.Extensions))

	for i, builder := range c.Extensions {
		extOutput, err := builder.Compile(c)
		if err != nil {
			return nil, fmt.Errorf("cert: error compiling extension #%v: %v", i, err.Error())
		}
		out.TBSCertificate.Extensions[i] = *extOutput
	}

	//marshal stuff to sign
	b, err := asn1.Marshal(out.TBSCertificate)
	if err != nil {
		return nil, err
	}

	//determine hash algorithm
	var digest []byte
	var hashAlgId crypto.Hash
	var hashAlg hash.Hash
	var wantKey keyType
	hashAlgId, hashAlg, out.SignatureAlgorithm.Algorithm, wantKey, err = resolveAlg(alg)
	if err != nil {
		return nil, err
	}

	hashAlg.Write(b)
	digest = hashAlg.Sum(nil)

	//convert key and sign
	var signature []byte
	if wantKey == ecKey {
		ecdsaPrk, ok := c.Issuer.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("cert: provided key is not ECDSA compatible")
		}

		signature, err = ecdsa.SignASN1(defaultRandom, ecdsaPrk, digest)
		if err != nil {
			return nil, err
		}
	} else if wantKey == rsaKey {
		rsaPrk, ok := c.Issuer.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("cert: provided key is not RSA compatible")
		}

		signature, err = rsa.SignPKCS1v15(defaultRandom, rsaPrk, hashAlgId, digest)
		if err != nil {
			return nil, err
		}
	} else {
		panic("sign function is broken")
	}

	out.SignatureValue = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	return &out, nil
}
