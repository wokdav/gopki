package v1

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/wokdav/gopki/generator/cert"
	"github.com/wokdav/gopki/generator/config"
)

// Struct for unmarshaling JSON/YAML extensions.
// The config expects a list of objects, where each object has only
// one key-value pair. This ensures readability and preserves the
// order of extensions while still not having to unmarshal everything
// by hand. This is also enforced through the schema.
//
// This means that only one pointer is not nil after parsing.
// We later use reflection to find out, which one it is and return
// the appropriate pointer value as a [config.ExtensionConfig].
//
// This struct must only include exactly one [config.ExtensionConfig]
// implementation for each extension.
//
// To add an extension, simply write your [config.ExtensionConfig]
// implementation and add a pointer to this struct.
type AnyExtension struct {
	*SubjectKeyIdentifier `json:"subjectKeyIdentifier"`
	*KeyUsage             `json:"keyUsage"`
	*SubjectAltName       `json:"subjectAlternativeName"`
	*BasicConstraints     `json:"basicConstraints"`
	*CertPolicies         `json:"certificatePolicies"`
	*AuthInfoAccess       `json:"authorityInformationAccess"`
	*AuthKeyId            `json:"authorityKeyIdentifier"`
	*ExtKeyUsage          `json:"extendedKeyUsage"`
	*AdmissionExtension   `json:"admission"`
	*OcspNoCheckExtension `json:"ocspNoCheck"`
	*CustomExtension      `json:"custom"`
	Optional              bool `json:"optional"`
	Override              bool `json:"override"`
}

type ExtensionType int

//TODO: Handle conversion to cert config instances via interface
//TODO: Generalize binary into own json file to incorporate NULL etc.
//TODO: Same goes for generalNames.

//TODO: Allow whitspace before and after equal sign for RDNs

const (
	TypeIllegal ExtensionType = iota
	TypeSubjectKeyIdentifier
	TypeKeyUsage
	TypeSubjectAltName
	TypeBasicConstraints
	TypeCertPolicies
	TypeAuthInfoAccess
	TypeAuthKeyId
	TypeAdmission
	TypeExtKeyUsage
	TypeExtOcspNoCheck
	TypeCustomExtension
)

func parseExtensions(e []AnyExtension) ([]config.ExtensionConfig, error) {
	out := make([]config.ExtensionConfig, 0, len(e))
	for i, ext := range e {
		extStructVal := reflect.ValueOf(ext)
		extStructTyp := reflect.TypeOf(ext)
		found := false
		for j := 0; j < extStructVal.NumField(); j++ {
			innerStructValPtr := extStructVal.Field(j)
			innerStructTyp := extStructTyp.Field(j)
			if innerStructValPtr.Kind() != reflect.Pointer {
				//skip non-pointer fields
				continue
			}

			//find first non-nil ptr
			if innerStructValPtr.IsNil() {
				continue
			}

			found = true
			innerStructAny := innerStructValPtr.Elem().Interface()
			innerStruct, ok := innerStructAny.(config.ExtensionConfig)
			if !ok {
				return nil, fmt.Errorf("field '%v' can't be casted properly", innerStructTyp.Name)
			}

			out = append(out, innerStruct)
		}

		if !found {
			return nil, fmt.Errorf("extension number %d contains no extensions; "+
				"did you forget to set the extension explicitly to an empty dict?", i)
		}
	}
	return out[:], nil
}

type GeneralName struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

func (g GeneralName) convert() (cert.GeneralName, error) {
	switch g.Type {
	case "ip":
		var ipAddr cert.GeneralNameIP
		octets := strings.Split(g.Name, ".")
		if len(octets) != 4 {
			return nil, fmt.Errorf("extensions: expected 4 orrctets, got %v from %v", len(octets), octets)
		}
		for j, octet := range octets {
			v, err := strconv.Atoi(octet)
			if err != nil {
				return nil, fmt.Errorf("extensions: can't decode octet#%d. not a valid integer: %v", j, octet)
			}
			if v > 255 || v < 0 {
				return nil, fmt.Errorf("extensions: can't decode octet#%d. out of bounds (0-255): %v", j, octet)
			}
			ipAddr[j] = uint8(v)
		}

		return ipAddr, nil
	case "dns":
		return cert.GeneralNameDNS(g.Name), nil
	case "mail":
		return cert.GeneralNameDNS(g.Name), nil
	case "url":
		return cert.GeneralNameDNS(g.Name), nil
	case "":
		//make sure to support empty values
		return nil, nil

	default:
		return nil, errors.New("extensions: no general name recognized")
	}

}

// JSON/YAML representation for this extension.
// Also implements [config.ExtensionConfig]
type SubjectKeyIdentifier struct {
	Raw      string `json:"raw"`
	Critical bool   `json:"critical"`
	Content  string `json:"content"`
}

func (s SubjectKeyIdentifier) Oid() (asn1.ObjectIdentifier, error) {
	oid, ok := cert.GetOid(cert.OidExtensionSubjectKeyId)
	if !ok {
		panic("Bug: Extension OID not in bounds!")
	}

	return oid, nil
}

func (s SubjectKeyIdentifier) Builder() (cert.ExtensionBuilder, error) {
	if len(s.Raw) != 0 && len(s.Content) != 0 {
		return nil, errors.New(
			"config-v1: [subjectKeyId] ambiguous definition; content and raw both are given")
	}
	oid, ok := cert.GetOid(cert.OidExtensionSubjectKeyId)
	if !ok {
		panic("Bug: Extension OID not in bounds!")
	}
	if len(s.Raw) != 0 {
		b, err := readRawString(s.Raw)
		if err != nil {
			return nil, err
		}
		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       oid,
				Critical: s.Critical,
				Value:    b,
			},
		}, nil
	} else if strings.HasPrefix(s.Content, binaryPrefix) {
		b, err := readRawString(s.Content)
		if err != nil {
			return nil, err
		}
		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       oid,
				Critical: s.Critical,
				Value:    b,
			},
		}, nil
	} else if s.Content == "hash" {
		return config.FunctionBuilder{
			Function: func(ctx *cert.CertificateContext) (*pkix.Extension, error) {
				return cert.NewSubjectKeyIdentifier(s.Critical, ctx)
			},
		}, nil
	} else if len(s.Content) != 0 {
		b, err := readRawString(s.Content)
		if err != nil {
			return nil, err
		}
		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       oid,
				Critical: s.Critical,
				Value:    b,
			},
		}, nil
	}

	return config.OverrideNeededBuilder{}, nil
}

const (
	DigitalSignature string = "digitalSignature"
	NonRepudiation   string = "nonRepudiation"
	KeyEncipherment  string = "keyEncipherment"
	DataEncipherment string = "dataEncipherment"
	KeyAgreement     string = "keyAgreement"
	KeyCertSign      string = "keyCertSign"
	CRLSign          string = "crlSign"
)

// JSON/YAML representation for this extension.
// Also implements [config.ExtensionConfig]
type KeyUsage struct {
	Raw      string   `json:"raw"`
	Critical bool     `json:"critical"`
	Content  []string `json:"content"`
}

func (k KeyUsage) Oid() (asn1.ObjectIdentifier, error) {
	oid, ok := cert.GetOid(cert.OidExtensionKeyUsage)
	if !ok {
		panic("Bug: Extension OID not in bounds!")
	}

	return oid, nil
}

func (k KeyUsage) Builder() (cert.ExtensionBuilder, error) {
	if len(k.Raw) != 0 && len(k.Content) != 0 {
		return nil, errors.New(
			"config-v1: [keyUsage] ambiguous definition; content and raw both are given")
	}
	if len(k.Raw) != 0 {
		oid, ok := cert.GetOid(cert.OidExtensionKeyUsage)
		if !ok {
			panic("Bug: Extension OID not in bounds!")
		}
		b, err := readRawString(k.Raw)
		if err != nil {
			return nil, err
		}
		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       oid,
				Critical: k.Critical,
				Value:    b,
			},
		}, nil
	}

	usageFlags := cert.KeyUsage(0)
	if k.Content != nil {
		for _, flagString := range k.Content {
			switch flagString {
			case DigitalSignature:
				usageFlags |= cert.DigitalSignature
			case NonRepudiation:
				usageFlags |= cert.NonRepudiation
			case KeyEncipherment:
				usageFlags |= cert.KeyEncipherment
			case DataEncipherment:
				usageFlags |= cert.DataEncipherment
			case KeyAgreement:
				usageFlags |= cert.KeyAgreement
			case KeyCertSign:
				usageFlags |= cert.KeyCertSign
			case CRLSign:
				usageFlags |= cert.CRLSign
			default:
				return nil, fmt.Errorf("config-v1: [keyUsage] unknown key usage: %v", flagString)
			}
		}
		return config.ConstantBuilder{
			Extension: cert.NewKeyUsage(k.Critical, usageFlags),
		}, nil
	}

	return config.OverrideNeededBuilder{}, nil
}

// JSON/YAML representation for this extension.
// Also implements [config.ExtensionConfig]
type SubjectAltName struct {
	Raw      string                 `json:"raw"`
	Critical bool                   `json:"critical"`
	Content  []SubjAltNameComponent `json:"content"`
}

type SubjAltNameComponent struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

func (s SubjectAltName) Oid() (asn1.ObjectIdentifier, error) {
	oid, ok := cert.GetOid(cert.OidExtensionSubjectAltName)
	if !ok {
		panic("Bug: Extension OID not in bounds!")
	}

	return oid, nil
}

func (s SubjectAltName) Builder() (cert.ExtensionBuilder, error) {
	if len(s.Raw) != 0 && len(s.Content) != 0 {
		return nil, errors.New(
			"config-v1: [subjectAltName] ambiguous definition; content and raw both are given")
	}

	if len(s.Raw) != 0 {
		oid, ok := cert.GetOid(cert.OidExtensionSubjectAltName)
		if !ok {
			panic("Bug: Extension OID not in bounds!")
		}

		b, err := readRawString(s.Raw)
		if err != nil {
			return nil, err
		}
		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       oid,
				Critical: s.Critical,
				Value:    b,
			},
		}, nil
	}

	if s.Content == nil {
		return config.OverrideNeededBuilder{}, nil
	}

	sanValues := make([]cert.GeneralName, len(s.Content))
	for i, component := range s.Content {
		switch component.Type {
		case "mail":
			sanValues[i] = cert.GeneralNameRFC822(component.Name)
		case "dns":
			sanValues[i] = cert.GeneralNameDNS(component.Name)
		case "ip":
			octets := strings.Split(component.Name, ".")
			if len(octets) != 4 {
				return nil, fmt.Errorf("config-v1: [subjectAlternativeName] expected 4 octets for IP, not %v", len(octets))
			}

			var ipAddr cert.GeneralNameIP
			for j, octet := range octets {
				v, err := strconv.Atoi(octet)
				if err != nil {
					return nil, fmt.Errorf("config-v1: [subjectAlternativeName] can't decode octet#%d. not a valid integer: %v", j, octet)
				}
				ipAddr[j] = byte(v)
			}

			sanValues[i] = ipAddr
		default:
			return nil, fmt.Errorf("config-v1: [subjectAlternativeName] unknown SAN type: %v", component.Type)
		}
	}

	sanExt, err := cert.NewSubjectAlternativeName(s.Critical, sanValues)
	if err != nil {
		return nil, err
	}

	return config.ConstantBuilder{Extension: *sanExt}, nil
}

type BasicConstraintsObj struct {
	Ca      bool `json:"ca"`
	PathLen int  `json:"pathLen"`
}

// JSON/YAML representation for this extension.
// Also implements [config.ExtensionConfig]
type BasicConstraints struct {
	Raw      string               `json:"raw"`
	Critical bool                 `json:"critical"`
	Content  *BasicConstraintsObj `json:"content"`
}

func (b BasicConstraints) Oid() (asn1.ObjectIdentifier, error) {
	oid, ok := cert.GetOid(cert.OidExtensionBasicConstraints)
	if !ok {
		panic("Bug: Extension OID not in bounds!")
	}

	return oid, nil
}

func (b BasicConstraints) Builder() (cert.ExtensionBuilder, error) {
	if b.Content != nil && len(b.Raw) != 0 {
		return nil, errors.New("config-v1: [basicConstraints] ambiguous - both raw and content are given")
	}

	if b.Content != nil {
		return config.ConstantBuilder{
			Extension: cert.NewBasicConstraints(b.Critical, b.Content.Ca, b.Content.PathLen),
		}, nil
	}

	if len(b.Raw) != 0 {
		oid, ok := cert.GetOid(cert.OidExtensionBasicConstraints)
		if !ok {
			panic("Bug: Extension OID not in bounds!")
		}

		by, err := readRawString(b.Raw)
		if err != nil {
			return nil, err
		}
		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       oid,
				Critical: b.Critical,
				Value:    by,
			},
		}, nil
	}

	return config.OverrideNeededBuilder{}, nil
}

type UserNotice struct {
	Organization string `json:"organization"`
	Numbers      []int  `json:"numbers"`
	Text         string `json:"text"`
}

type PolicyQualifiers struct {
	Cps         string `json:"cps"`
	*UserNotice `json:"userNotice"`
}

type CertPolicy struct {
	Oid        string             `json:"oid"`
	Qualifiers []PolicyQualifiers `json:"qualifiers"`
}

// JSON/YAML representation for this extension.
// Also implements [config.ExtensionConfig]
type CertPolicies struct {
	Raw      string       `json:"raw"`
	Critical bool         `json:"critical"`
	Content  []CertPolicy `json:"content"`
}

func (c CertPolicies) Oid() (asn1.ObjectIdentifier, error) {
	oid, ok := cert.GetOid(cert.OidExtensionCertificatePolicies)
	if !ok {
		panic("Bug: Extension OID not in bounds!")
	}

	return oid, nil
}

func (c CertPolicies) Builder() (cert.ExtensionBuilder, error) {
	if len(c.Raw) != 0 && len(c.Content) != 0 {
		return nil, errors.New(
			"config-v1: [certPolicies] ambiguous definition; content and raw both are given")
	}

	if len(c.Raw) != 0 {
		oid, ok := cert.GetOid(cert.OidExtensionCertificatePolicies)
		if !ok {
			panic("Bug: Extension OID not in bounds!")
		}

		b, err := readRawString(c.Raw)
		if err != nil {
			return nil, err
		}
		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       oid,
				Critical: c.Critical,
				Value:    b,
			},
		}, nil
	} else if c.Content != nil {
		policyIds := make([]cert.PolicyInfo, len(c.Content))
		for i, policyObj := range c.Content {
			id, err := cert.OidFromString(policyObj.Oid)
			if err != nil {
				return nil, err
			}

			policyIds[i] = cert.PolicyInfo{ObjectIdentifier: id}

			if policyObj.Qualifiers == nil {
				continue
			}

			policyIds[i].Qualifiers = make([]cert.PolicyQualifier, len(policyObj.Qualifiers))

			for j, qualifier := range policyObj.Qualifiers {
				if len(qualifier.Cps) > 0 {
					policyIds[i].Qualifiers[j].QualifierId = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}
					policyIds[i].Qualifiers[j].Cps = qualifier.Cps
					continue
				}
				if qualifier.UserNotice != nil {
					policyIds[i].Qualifiers[j].QualifierId = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}
					policyIds[i].Qualifiers[j].UserNotice = cert.UserNotice{
						NoticeRef: cert.NoticeReference{
							Organization:  qualifier.Organization,
							NoticeNumbers: qualifier.Numbers,
						},
						ExplicitText: qualifier.Text,
					}
					continue
				}
				return nil, fmt.Errorf("config-v1: no valid qualifier in struct: %v", qualifier)
			}
		}
		ext, err := cert.NewCertificatePolicies(c.Critical, policyIds)
		if err != nil {
			return nil, err
		}
		return config.ConstantBuilder{Extension: *ext}, nil
	}

	return config.OverrideNeededBuilder{}, nil
}

type SingleAuthInfo struct {
	Ocsp string `json:"ocsp"`
}

// JSON/YAML representation for this extension.
// Also implements [config.ExtensionConfig]
type AuthInfoAccess struct {
	Raw      string           `json:"raw"`
	Critical bool             `json:"critical"`
	Content  []SingleAuthInfo `json:"content"`
}

func (a AuthInfoAccess) Oid() (asn1.ObjectIdentifier, error) {
	oid, ok := cert.GetOid(cert.OidExtensionAuthorityInfoAccess)
	if !ok {
		panic("Bug: Extension OID not in bounds!")
	}

	return oid, nil
}

func (a AuthInfoAccess) Builder() (cert.ExtensionBuilder, error) {
	if len(a.Raw) != 0 && len(a.Content) != 0 {
		return nil, errors.New(
			"config-v1: [certPolicies] ambiguous definition; content and raw both are given")
	}

	if len(a.Raw) != 0 {
		oid, ok := cert.GetOid(cert.OidExtensionAuthorityInfoAccess)
		if !ok {
			panic("Bug: Extension OID not in bounds!")
		}

		b, err := readRawString(a.Raw)
		if err != nil {
			return nil, err
		}
		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       oid,
				Critical: a.Critical,
				Value:    b,
			},
		}, nil
	} else if a.Content != nil {
		accessInfoList := make([]cert.AccessDescription, len(a.Content))
		for i, infoElement := range a.Content {
			if len(infoElement.Ocsp) == 0 {
				return nil, errors.New("config-v1: [authorityInfoAccess] no ocsp value given")
			}

			accessInfoList[i] = cert.AccessDescription{
				AccessMethod:   cert.Ocsp,
				AccessLocation: cert.GeneralNameURI(infoElement.Ocsp),
			}
		}
		ext, err := cert.NewAuthorityInfoAccess(a.Critical, accessInfoList)
		if err != nil {
			return nil, err
		}

		return config.ConstantBuilder{Extension: *ext}, nil
	}

	return config.OverrideNeededBuilder{}, nil
}

type AuthKeyIdContent struct {
	Id string `json:"id"`
}

// JSON/YAML representation for this extension.
// Also implements [config.ExtensionConfig]
type AuthKeyId struct {
	Raw      string           `json:"raw"`
	Critical bool             `json:"critical"`
	Content  AuthKeyIdContent `json:"content"`
}

func (a AuthKeyId) Oid() (asn1.ObjectIdentifier, error) {
	oid, ok := cert.GetOid(cert.OidExtensionAuthorityKeyId)
	if !ok {
		panic("Bug: Extension OID not in bounds!")
	}

	return oid, nil
}

func (a AuthKeyId) Builder() (cert.ExtensionBuilder, error) {
	if len(a.Raw) != 0 && len(a.Content.Id) != 0 {
		return nil, errors.New(
			"config-v1: [certPolicies] ambiguous definition; content and raw both are given")
	}

	if len(a.Raw) != 0 {
		oid, ok := cert.GetOid(cert.OidExtensionAuthorityKeyId)
		if !ok {
			panic("Bug: Extension OID not in bounds!")
		}

		b, err := readRawString(a.Raw)
		if err != nil {
			return nil, err
		}
		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       oid,
				Critical: a.Critical,
				Value:    b,
			},
		}, nil
	} else if len(a.Content.Id) != 0 {
		if a.Content.Id == "hash" {
			return config.FunctionBuilder{
				Function: func(ctx *cert.CertificateContext) (*pkix.Extension, error) {
					return cert.NewAuthorityKeyIdentifierHash(
						a.Critical,
						ctx,
					)
				},
			}, nil
		} else if strings.HasPrefix(a.Content.Id, binaryPrefix) {
			b, err := readRawString(a.Content.Id)
			if err != nil {
				return nil, err
			}

			ext, err := cert.NewAuthorityKeyIdentifierFromStruct(
				a.Critical,
				cert.AuthorityKeyIdentifier{
					KeyIdentifier: b,
				},
			)
			if err != nil {
				return nil, err
			}

			return config.ConstantBuilder{Extension: *ext}, nil
		} else {
			return nil, fmt.Errorf("config-v1: [authKeyId] illegal id: %v", a.Content.Id)
		}
	}

	return config.OverrideNeededBuilder{}, nil
}

// JSON/YAML representation for this extension.
// Also implements [config.ExtensionConfig]
type ExtKeyUsage struct {
	Raw      string   `json:"raw"`
	Critical bool     `json:"critical"`
	Content  []string `json:"content"`
}

const (
	ServerAuth      string = "serverAuth"
	ClientAuth      string = "clientAuth"
	CodeSigning     string = "codeSigning"
	EmailProtection string = "emailProtection"
	TimeStamping    string = "timeStamping"
	OcspSigning     string = "OCSPSigning"
)

func (e ExtKeyUsage) Oid() (asn1.ObjectIdentifier, error) {
	oid, ok := cert.GetOid(cert.OidExtensionExtendedKeyUsage)
	if !ok {
		panic("Bug: Extension OID not in bounds!")
	}

	return oid, nil
}

func extKeyUsageOid(s string) (asn1.ObjectIdentifier, error) {
	var out asn1.ObjectIdentifier
	var err error

	switch s {
	case ServerAuth:
		out, _ = cert.GetExtendedKeyUsage(cert.ServerAuth)
	case ClientAuth:
		out, _ = cert.GetExtendedKeyUsage(cert.ClientAuth)
	case CodeSigning:
		out, _ = cert.GetExtendedKeyUsage(cert.CodeSigning)
	case EmailProtection:
		out, _ = cert.GetExtendedKeyUsage(cert.EmailProtection)
	case TimeStamping:
		out, _ = cert.GetExtendedKeyUsage(cert.TimeStamping)
	case OcspSigning:
		out, _ = cert.GetExtendedKeyUsage(cert.OcspSigning)
	default:
		out, err = cert.OidFromString(s)
		if err != nil {
			err = fmt.Errorf("config-v1: [extendedKeyUsage] '%v' is neither a valid key usage nor a valid oid", s)
		}
	}

	return out, err
}

func (e ExtKeyUsage) Builder() (cert.ExtensionBuilder, error) {
	if len(e.Raw) != 0 && len(e.Content) != 0 {
		return nil, errors.New(
			"config-v1: [extKeyUsage] ambiguous definition; content and raw both are given")
	}

	if len(e.Raw) != 0 {
		oid, ok := cert.GetOid(cert.OidExtensionExtendedKeyUsage)
		if !ok {
			panic("Bug: Extension OID not in bounds!")
		}

		b, err := readRawString(e.Raw)
		if err != nil {
			return nil, err
		}
		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       oid,
				Critical: e.Critical,
				Value:    b,
			},
		}, nil
	} else if e.Content != nil {
		usageList := make([]asn1.ObjectIdentifier, len(e.Content))
		for i, usageStr := range e.Content {
			var err error
			usageList[i], err = extKeyUsageOid(usageStr)
			if err != nil {
				return nil, err
			}
		}
		ext, err := cert.NewExtendedKeyUsage(e.Critical, usageList)
		if err != nil {
			return nil, err
		}

		return config.ConstantBuilder{Extension: *ext}, nil
	}

	return config.OverrideNeededBuilder{}, nil
}

type AdmissionExtension struct {
	Raw      string     `json:"raw"`
	Critical bool       `json:"critical"`
	Content  *Admission `json:"content"`
}

type Admission struct {
	AdmissionAuthority GeneralName       `json:"admissionAuthority"`
	Admissions         []SingleAdmission `json:"admissions"`
}

func (a Admission) convert() (*cert.Admission, error) {
	var err error
	auth, err := a.AdmissionAuthority.convert()
	if err != nil {
		return nil, err
	}

	adms := make([]cert.Admissions, len(a.Admissions))
	for i, adm := range a.Admissions {
		admTmp, err := adm.convert()
		if err != nil {
			return nil, err
		}
		adms[i] = *admTmp
	}

	return &cert.Admission{
		AdmissionAuthority: auth,
		Contents:           adms,
	}, nil
}

type NamingAuthority struct {
	Oid  string `json:"oid"`
	Url  string `json:"url"`
	Text string `json:"text"`
}

func (n NamingAuthority) convert() (*cert.NamingAuthority, error) {
	var err error
	var nAuthOid asn1.ObjectIdentifier
	if len(n.Oid) > 0 {
		nAuthOid, err = cert.OidFromString(n.Oid)
		if err != nil {
			return nil, err
		}
	}

	return &cert.NamingAuthority{
		Oid:  nAuthOid,
		URL:  n.Url,
		Text: n.Text,
	}, nil
}

type ProfessionInfo struct {
	NamingAuthority    `json:"namingAuthority"`
	ProfessionItems    []string `json:"professionItems"`
	ProfessionOids     []string `json:"professionOids"`
	RegistrationNumber string   `json:"registrationNumber"`
	AddProfessionInfo  string   `json:"addProfessionInfo"`
}

type SingleAdmission struct {
	AdmissionAuthority GeneralName `json:"admissionAuthority"`
	NamingAuthority    `json:"namingAuthority"`
	ProfessionInfos    []ProfessionInfo `json:"professionInfos"`
}

func (s SingleAdmission) convert() (*cert.Admissions, error) {
	auth, err := s.AdmissionAuthority.convert()
	if err != nil {
		return nil, err
	}

	nameAuth, err := s.NamingAuthority.convert()
	if err != nil {
		return nil, err
	}

	profInfo := make([]cert.ProfessionInfo, len(s.ProfessionInfos))
	for i, pi := range s.ProfessionInfos {
		innerNameAuth, err := pi.NamingAuthority.convert()
		if err != nil {
			return nil, err
		}
		profOids := make([]asn1.ObjectIdentifier, len(pi.ProfessionOids))
		for j, oid := range pi.ProfessionOids {
			profOids[j], err = cert.OidFromString(oid)
			if err != nil {
				return nil, err
			}
		}
		var addProfInfo []byte
		if len(pi.AddProfessionInfo) > 0 {
			addProfInfo, err = readRawString(pi.AddProfessionInfo)
			if err != nil {
				return nil, err
			}
		}

		profInfo[i] = cert.ProfessionInfo{
			NamingAuthority:    *innerNameAuth,
			ProfessionItems:    pi.ProfessionItems,
			ProfessionOids:     profOids,
			RegistrationNumber: pi.RegistrationNumber,
			AddProfessionInfo:  addProfInfo,
		}

	}

	return &cert.Admissions{
		AdmissionAuthority: auth,
		NamingAuthority:    *nameAuth,
		ProfessionInfos:    profInfo,
	}, nil
}

func (a AdmissionExtension) Oid() (asn1.ObjectIdentifier, error) {
	oid, ok := cert.GetOid(cert.OidExtensionAdmission)
	if !ok {
		panic("Bug: Extension OID not in bounds!")
	}

	return oid, nil
}

func (a AdmissionExtension) Builder() (cert.ExtensionBuilder, error) {
	if len(a.Raw) != 0 && a.Content == nil {
		return nil, errors.New(
			"config-v1: [admission] ambiguous definition; content and raw both are given")
	}

	if len(a.Raw) != 0 {
		oid, ok := cert.GetOid(cert.OidExtensionAdmission)
		if !ok {
			panic("Bug: Extension OID not in bounds!")
		}

		b, err := readRawString(a.Raw)
		if err != nil {
			return nil, err
		}
		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       oid,
				Critical: a.Critical,
				Value:    b,
			},
		}, nil
	} else if a.Content != nil {
		adConverted, err := a.Content.convert()
		if err != nil {
			return nil, err
		}
		ext, err := cert.NewAdmission(a.Critical, *adConverted)
		if err != nil {
			return nil, err
		}

		return config.ConstantBuilder{Extension: *ext}, nil
	}

	return config.OverrideNeededBuilder{}, nil
}

type OcspNoCheckExtension struct {
	Raw      string `json:"raw"`
	Critical bool   `json:"critical"`
}

func (o OcspNoCheckExtension) Oid() (asn1.ObjectIdentifier, error) {
	oid, ok := cert.GetOid(cert.OidExtensionOcspNoCheck)
	if !ok {
		panic("Bug: Extension OID not in bounds!")
	}

	return oid, nil
}

func (o OcspNoCheckExtension) Builder() (cert.ExtensionBuilder, error) {
	if len(o.Raw) == 0 {
		return config.ConstantBuilder{Extension: cert.NewOcspNoCheck(o.Critical)}, nil
	} else {
		oid, ok := cert.GetOid(cert.OidExtensionAdmission)
		if !ok {
			panic("Bug: Extension OID not in bounds!")
		}

		b, err := readRawString(o.Raw)
		if err != nil {
			return nil, err
		}
		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       oid,
				Critical: o.Critical,
				Value:    b,
			},
		}, nil
	}
}

// JSON/YAML representation for this custom extensions.
// Also implements [config.ExtensionConfig]
type CustomExtension struct {
	OidStr   string `json:"oid"`
	Raw      string `json:"raw"`
	Critical bool   `json:"critical"`
}

func (c CustomExtension) Oid() (asn1.ObjectIdentifier, error) {
	return cert.OidFromString(c.OidStr)
}

func (c CustomExtension) Builder() (cert.ExtensionBuilder, error) {
	if len(c.Raw) != 0 {
		oidObj, err := c.Oid()
		if err != nil {
			return nil, err
		}

		b, err := readRawString(c.Raw)
		if err != nil {
			return nil, err
		}
		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       oidObj,
				Critical: c.Critical,
				Value:    b,
			},
		}, nil
	}

	return nil, fmt.Errorf("config-v1: [customExtension] raw-content not given")
}

func readRawString(s string) ([]byte, error) {
	if strings.HasPrefix(s, binaryPrefix) {
		b64Str := strings.TrimPrefix(s, binaryPrefix)
		dec := base64.NewDecoder(base64.StdEncoding, strings.NewReader(b64Str))

		b := make([]byte, len(b64Str))
		n, err := dec.Read(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	} else if s == emptyPrefix {
		//maybe this is unnecessary
		return make([]byte, 0), nil
	} else if s == nullPrefix {
		return asn1.NullBytes, nil
	}

	return nil, fmt.Errorf("cert: unrecognized raw command :%s", s)
}
