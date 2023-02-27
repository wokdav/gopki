package cert

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"reflect"
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
	OidExtensionAdmission
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
	oidExtensionAdmission             = []int{1, 3, 36, 8, 3, 3}
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
	oidExtensionAdmission,
}

// Returns the appropriate OID object. If the provided
// index is out of bounds, the bool return will be false.
func GetOid(i ExtensionOid) (asn1.ObjectIdentifier, bool) {
	if i < 0 || i >= oidExtensionLen {
		return nil, false
	}

	return oids[i], true
}

func partialMarshallStruct(in any, offset uint, len uint) ([]byte, error) {
	ty := reflect.TypeOf(in)
	if ty.Kind() != reflect.Struct {
		return nil, errors.New("extensions: input must be struct")
	}

	var err error
	bb := bytes.Buffer{}
	var tmp []byte

	val := reflect.ValueOf(in)
	off := int(offset)
	for i := 0; i < int(len); i++ {
		currentField := reflect.TypeOf(in).Field(off + i)
		_, ok := currentField.Tag.Lookup("asn1")
		field := val.Field(off + i).Interface()
		if ok {
			tmp, err = asn1.MarshalWithParams(field, currentField.Tag.Get("asn1"))
		} else {
			tmp, err = asn1.Marshal(field)
		}

		if err != nil {
			return nil, err
		}
		bb.Write(tmp)
	}

	return bb.Bytes(), nil
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
type PolicyInfo struct {
	asn1.ObjectIdentifier
	Qualifiers []PolicyQualifier `asn1:"optional"`
}

type PolicyQualifier struct {
	QualifierId asn1.ObjectIdentifier
	Cps         string `asn1:"optional,ia5"`
	UserNotice  `asn1:"optional"`
}

type UserNotice struct {
	NoticeRef    NoticeReference `asn1:"optional"`
	ExplicitText string          `asn1:"optional,utf8"`
}

type NoticeReference struct {
	Organization  string `asn1:"utf8"`
	NoticeNumbers []int
}

// Create a Certificate Policies Extension according to RFC5280.
func NewCertificatePolicies(critical bool, policyIds []PolicyInfo) (*pkix.Extension, error) {
	polBody, err := asn1.Marshal(policyIds)

	if err != nil {
		return nil, err
	}

	return &pkix.Extension{
		Critical: critical,
		Id:       oidExtensionCertificatePolicies,
		Value:    polBody,
	}, nil
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
	if ctx.Issuer == nil || ctx.Issuer.PublicKeyRaw == nil {
		return nil, errors.New("extensions: issuer public key is nil, hash would be pointless")
	}

	hashAlg := crypto.SHA1.New()
	hashAlg.Write(ctx.Issuer.PublicKeyRaw)
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

type Admission struct {
	AdmissionAuthority GeneralName `asn1:"optional"`
	Contents           []Admissions
}

type Admissions struct {
	AdmissionAuthority GeneralName `asn1:"optional,explicit"`
	NamingAuthority    `asn1:"tag:1,optional,explicit"`
	ProfessionInfos    []ProfessionInfo `omitempty,asn1:"optional"`
}

type NamingAuthority struct {
	Oid  asn1.ObjectIdentifier `asn1:"optional"`
	URL  string                `asn1:"ia5,optional"`
	Text string                `asn1:"utf8,optional"`
}

type ProfessionInfo struct {
	NamingAuthority    `asn1:"tag:0,explicit,optional"`
	ProfessionItems    []string                `asn1:"omitempty,optional"`
	ProfessionOids     []asn1.ObjectIdentifier `asn1:"omitempty,optional"`
	RegistrationNumber string                  `asn1:"printable,optional"`
	AddProfessionInfo  []byte                  `asn1:"omitempty,optional"`
}

func makeExplicit(b []byte) []byte {
	//safe operation, so we ignore the error
	wrap, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Tag:        0,
		Bytes:      b,
	})

	return wrap
}

func (ad Admission) marshal() ([]byte, error) {
	var err error
	bb := bytes.Buffer{}
	var tmp []byte

	if ad.AdmissionAuthority != nil {
		tmp, err = ad.AdmissionAuthority.marshal()
		if err != nil {
			return nil, err
		}
		bb.Write(tmp)
	}

	adxbb := bytes.Buffer{}
	for _, content := range ad.Contents {
		tmp, err := content.marshal()
		if err != nil {
			return nil, err
		}

		adxbb.Write(tmp)
	}

	adxMarshalled, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      adxbb.Bytes(),
	})
	if err != nil {
		return nil, err
	}

	bb.Write(adxMarshalled)

	//finally wrap in sequence
	axMarshalled, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      bb.Bytes(),
	})
	if err != nil {
		return nil, err
	}

	return axMarshalled, nil
}

func (ax Admissions) marshal() ([]byte, error) {
	var err error
	bb := bytes.Buffer{}
	var tmp []byte

	if ax.AdmissionAuthority != nil {
		tmp, err = ax.AdmissionAuthority.marshal()
		if err != nil {
			return nil, err
		}
		bb.Write(makeExplicit(tmp))
	}

	tmp, err = partialMarshallStruct(ax, 1, 1)
	if err != nil {
		return nil, err
	}
	bb.Write(tmp)

	pibb := bytes.Buffer{}
	if len(ax.ProfessionInfos) > 0 {
		for _, pi := range ax.ProfessionInfos {
			tmp, err = pi.marshal()
			if err != nil {
				return nil, err
			}
			pibb.Write(tmp)
		}

		piMarshalled, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      pibb.Bytes(),
		})
		if err != nil {
			return nil, err
		}
		bb.Write(piMarshalled)
	}

	//finally wrap in sequence
	axMarshalled, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      bb.Bytes(),
	})
	if err != nil {
		return nil, err
	}

	return axMarshalled, nil
}

func (pi ProfessionInfo) marshal() ([]byte, error) {
	var err error
	bb := bytes.Buffer{}
	var tmp []byte

	tmp, err = partialMarshallStruct(pi, 0, 1)
	if err != nil {
		return nil, err
	}
	bb.Write(tmp)

	if len(pi.ProfessionItems) > 0 {
		bbItems := bytes.Buffer{}
		for _, item := range pi.ProfessionItems {
			tmp, err = asn1.MarshalWithParams(item, "utf8")
			if err != nil {
				return nil, err
			}
			bbItems.Write(tmp)
		}
		tmp, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      bbItems.Bytes(),
		})
		if err != nil {
			return nil, err
		}
		bb.Write(tmp)
	}

	tmp, err = partialMarshallStruct(pi, 2, 3)
	if err != nil {
		return nil, err
	}
	bb.Write(tmp)

	//finally wrap in sequence
	piMarshalled, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      bb.Bytes(),
	})
	if err != nil {
		return nil, err
	}

	return piMarshalled, nil
}

// Create Admission Extension conforming to Common PKI V2.0_02
func NewAdmission(critical bool, admission Admission) (*pkix.Extension, error) {
	marshalled, err := admission.marshal()
	if err != nil {
		return nil, err
	}
	return &pkix.Extension{
		Id:       oidExtensionAdmission,
		Critical: critical,
		Value:    marshalled,
	}, nil
}

func NewAdmissionFromProfessionItems(critical bool, professionItems []string, professionOids []asn1.ObjectIdentifier, registrationNumber string) (*pkix.Extension, error) {
	adm := Admission{
		Contents: []Admissions{
			{
				ProfessionInfos: []ProfessionInfo{
					{
						ProfessionItems:    professionItems,
						ProfessionOids:     professionOids,
						RegistrationNumber: registrationNumber,
					},
				},
			},
		},
	}

	return NewAdmission(critical, adm)
}
