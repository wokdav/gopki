package cert

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

type ExtensionOid int

const (
	OidExtensionSubjectKeyId ExtensionOid = iota
	OidExtensionKeyUsage
	OidExtensionExtendedKeyUsage
	OidExtensionAuthorityKeyId
	OidExtensionBasicConstraints
	OidExtensionSubjectAltName
	OidExtensionCertificatePolicies
	OidExtensionNameConstraints
	OidExtensionCRLDistributionPoints
	OidExtensionAuthorityInfoAccess
	OidExtensionCRLNumber
	oidExtensionLen
)

var (
	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionCRLNumber             = []int{2, 5, 29, 20}
)

var oids []asn1.ObjectIdentifier = []asn1.ObjectIdentifier{
	oidExtensionSubjectKeyId,
	oidExtensionKeyUsage,
	oidExtensionExtendedKeyUsage,
	oidExtensionAuthorityKeyId,
	oidExtensionBasicConstraints,
	oidExtensionSubjectAltName,
	oidExtensionCertificatePolicies,
	oidExtensionNameConstraints,
	oidExtensionCRLDistributionPoints,
	oidExtensionAuthorityInfoAccess,
	oidExtensionCRLNumber,
}

// Returns the appropriate OID object. If the provided
// index is out of bounds, the bool return will be false.
func GetOid(i ExtensionOid) (asn1.ObjectIdentifier, bool) {
	if i < 0 || i >= oidExtensionLen {
		return nil, false
	}

	return oids[i], true
}

// Create a Subject Key Identifier Extension according to RFC5280.
// The identifier will be the SHA-1 hash of the subject's raw public key in
// the provided [cert.CertificateContext]. It returns an error, if the context or
// the public key is nil.
func NewSubjectKeyIdentifier(critical bool, ctx *CertificateContext) (*pkix.Extension, error) {
	var content []byte
	if ctx == nil || ctx.TbsCertificate.PublicKey.PublicKey.Bytes == nil {
		return nil, errors.New("extensions: public key is nil, hash would be pointless")
	}

	hashAlg := crypto.SHA1.New()
	hashAlg.Write(ctx.TbsCertificate.PublicKey.PublicKey.Bytes)
	content = hashAlg.Sum(nil)

	marshalledId, err := asn1.Marshal(content)
	if err != nil {
		return nil, err
	}

	out := pkix.Extension{
		Critical: critical,
		Id:       oidExtensionSubjectKeyId,
		Value:    marshalledId,
	}
	return &out, nil
}

type KeyUsage uint8

const (
	DigitalSignature KeyUsage = 128
	NonRepudiation   KeyUsage = 64
	KeyEncipherment  KeyUsage = 32
	DataEncipherment KeyUsage = 16
	KeyAgreement     KeyUsage = 8
	KeyCertSign      KeyUsage = 4
	CRLSign          KeyUsage = 2
)

// Create a Key Usage Extension according to RFC5280.
// It will ensure that the flaglist is always valid, effectively
// ignoring the least significant bit of flags by zeroing it.
func NewKeyUsage(critical bool, flags KeyUsage) pkix.Extension {
	content := make([]byte, 1)
	content[0] = uint8(flags & 0xFE) //lowest bit must be zero

	bs := asn1.BitString{
		Bytes:     content,
		BitLength: 7,
	}

	//disard error since we control the data
	bitStringRaw, _ := asn1.Marshal(bs)

	out := pkix.Extension{
		Critical: true,
		Id:       oidExtensionKeyUsage,
		Value:    bitStringRaw,
	}

	return out
}

// Interface used to generate the correct GeneralName
// structre with the appropriate tags.
// Each implementation should be easy to create, preferably
// via primitive data types.
type GeneralName interface {
	marshal() ([]byte, error)
}

type (
	GeneralNameRFC822 string
	GeneralNameDNS    string
	GeneralNameIP     [4]byte
	GeneralNameURI    string
)

func (g GeneralNameRFC822) marshal() ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Tag:   1,
		Class: asn1.ClassContextSpecific,
		Bytes: []byte(g),
	})
}

func (g GeneralNameDNS) marshal() ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Tag:   2,
		Class: asn1.ClassContextSpecific,
		Bytes: []byte(g),
	})
}

func (g GeneralNameURI) marshal() ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Tag:   6,
		Class: asn1.ClassContextSpecific,
		Bytes: []byte(g),
	})
}

func (g GeneralNameIP) marshal() ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Tag:   7 | asn1.TagOctetString,
		Class: asn1.ClassContextSpecific,
		Bytes: g[:],
	})
}

// Create a Subject Alternative Name according to RFC5280.
func NewSubjectAlternativeName(critical bool, names []GeneralName) (*pkix.Extension, error) {
	nameBuffer := new(bytes.Buffer)
	for _, name := range names {
		b, err := name.marshal()
		if err != nil {
			return nil, err
		}
		nameBuffer.Write(b)
	}

	sanBody, _ := asn1.Marshal(asn1.RawValue{
		Tag:        asn1.TagSequence,
		Class:      asn1.ClassUniversal,
		IsCompound: true,
		Bytes:      nameBuffer.Bytes(),
	})

	return &pkix.Extension{
		Critical: critical,
		Id:       oidExtensionSubjectAltName,
		Value:    sanBody,
	}, nil
}

// Create a Subject Alternative Name according to RFC5280.
// There are no bounds on the pathLen, so it will never fail.
func NewBasicConstraints(critical bool, isCa bool, pathLen int) pkix.Extension {
	type BasicConstraints struct {
		IsCa    bool `asn1:"optional"`
		Pathlen int  `asn1:"optional"`
	}

	bcStruct := BasicConstraints{IsCa: isCa, Pathlen: pathLen}
	bcBody, _ := asn1.Marshal(bcStruct)

	return pkix.Extension{
		Critical: critical,
		Id:       oidExtensionBasicConstraints,
		Value:    bcBody,
	}
}

// PolicyInfo for the Certificate Policies Extension.
// Currently it only contains the Policy OID, not the Policy Qualifiers.
type PolicyInfo struct {
	// TODO: add policy qualifiers
	asn1.ObjectIdentifier
}

// Create a Certificate Policies Extension according to RFC5280.
func NewCertificatePolicies(critical bool, policyIds []PolicyInfo) pkix.Extension {
	polBody, _ := asn1.Marshal(policyIds)

	return pkix.Extension{
		Critical: critical,
		Id:       oidExtensionCertificatePolicies,
		Value:    polBody,
	}
}

type AccessMethod int

const (
	Ocsp AccessMethod = iota
)

// Contains one Access Description for the AIA extension.
type AccessDescription struct {
	AccessMethod
	AccessLocation GeneralName
}

var (
	oidAiaOcsp = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
)

// Create an Authority Information Access Extension according to RFC5280.
// It takes care of resolving the provided AccessMethods to the corresponding OIDs.
// It will fail, if an access method is not known.
func NewAuthorityInfoAccess(critical bool, accessInfo []AccessDescription) (*pkix.Extension, error) {
	bbAccessInfo := new(bytes.Buffer)
	bbExtension := new(bytes.Buffer)
	for _, infoElement := range accessInfo {
		bbAccessInfo.Reset()
		switch infoElement.AccessMethod {
		case Ocsp:
			infoOid, _ := asn1.Marshal(oidAiaOcsp)
			bbAccessInfo.Write(infoOid)
		default:
			return nil, fmt.Errorf("extensions: unknown access method: %d", infoElement.AccessMethod)
		}
		b, err := infoElement.AccessLocation.marshal()
		bbAccessInfo.Write(b)
		if err != nil {
			return nil, err
		}
		accessInfoAsn1, _ := asn1.Marshal(asn1.RawValue{
			Tag:        asn1.TagSequence,
			Bytes:      bbAccessInfo.Bytes(),
			IsCompound: true,
		})

		bbExtension.Write(accessInfoAsn1)
	}

	aiaMarshalled, _ := asn1.Marshal(asn1.RawValue{
		Tag:        asn1.TagSequence,
		Bytes:      bbExtension.Bytes(),
		IsCompound: true,
	})

	return &pkix.Extension{
		Id:       oidExtensionAuthorityInfoAccess,
		Critical: critical,
		Value:    aiaMarshalled,
	}, nil
}

type ExtKeyUsage uint

const (
	//Set explicitly, since these correspond to array indicies.
	ServerAuth      ExtKeyUsage = 0
	ClientAuth      ExtKeyUsage = 1
	CodeSigning     ExtKeyUsage = 2
	EmailProtection ExtKeyUsage = 3
	TimeStamping    ExtKeyUsage = 4
	OcspSigning     ExtKeyUsage = 5
	extKeyUsageLen  ExtKeyUsage = 6
)

var extKeyUsages []asn1.ObjectIdentifier = []asn1.ObjectIdentifier{
	{1, 3, 6, 1, 5, 5, 7, 3, 1}, //ServerAuth
	{1, 3, 6, 1, 5, 5, 7, 3, 2}, //ClientAuth
	{1, 3, 6, 1, 5, 5, 7, 3, 3}, //CodeSigning
	{1, 3, 6, 1, 5, 5, 7, 3, 4}, //EmailProtection
	{1, 3, 6, 1, 5, 5, 7, 3, 8}, //TimeStamping
	{1, 3, 6, 1, 5, 5, 7, 3, 9}, //OcspSigning
}

func GetExtendedKeyUsage(k ExtKeyUsage) (asn1.ObjectIdentifier, bool) {
	if k >= extKeyUsageLen {
		return nil, false
	}

	return extKeyUsages[k], true
}

// Create an Extended Key Usage Extension according to RFC5280.
func NewExtendedKeyUsage(critical bool, usages []asn1.ObjectIdentifier) (*pkix.Extension, error) {
	extKuMarshalled, err := asn1.Marshal(usages)
	if err != nil {
		return nil, err
	}

	return &pkix.Extension{
		Id:       oidExtensionExtendedKeyUsage,
		Critical: critical,
		Value:    extKuMarshalled,
	}, nil
}

type AuthorityKeyIdentifier struct {
	KeyIdentifier []byte `asn1:"tag:0,optional"`
	//Not supported at the moment
	//CertIssuer    []GeneralName `asn1:"tag:1,optional"`
	//CertSerial    *big.Int      `asn1:"tag:2,optional"`
}

// Create an Authority Key Identifier Extension according to RFC5280.
// This function allows to set the ID to any arbitrary value the struct allows.
func NewAuthorityKeyIdentifierFromStruct(critical bool, rawAuthkeyId AuthorityKeyIdentifier) (*pkix.Extension, error) {
	authKidMarshalled, err := asn1.Marshal(rawAuthkeyId)
	if err != nil {
		return nil, err
	}

	return &pkix.Extension{
		Id:       oidExtensionAuthorityKeyId,
		Critical: critical,
		Value:    authKidMarshalled,
	}, nil
}

// Create an Authority Key Identifier Extension according to RFC5280.
// This function generates the ID by calculating the SHA-1 hash of the provided
// public key of the IssuerContext.
func NewAuthorityKeyIdentifierHash(critical bool, ctx *CertificateContext) (*pkix.Extension, error) {
	if ctx.Issuer == nil || ctx.Issuer.publicKeyRaw == nil {
		return nil, errors.New("extensions: issuer public key is nil, hash would be pointless")
	}

	hashAlg := crypto.SHA1.New()
	hashAlg.Write(ctx.Issuer.publicKeyRaw)
	keyIdStruct := AuthorityKeyIdentifier{KeyIdentifier: hashAlg.Sum(nil)}

	keyIdMarshalled, err := asn1.Marshal(keyIdStruct)
	if err != nil {
		return nil, err
	}

	return &pkix.Extension{
		Id:       oidExtensionAuthorityKeyId,
		Critical: critical,
		Value:    keyIdMarshalled,
	}, nil
}
