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

//TODO: Handle conversion to cert config instances via interface
//TODO: Generalize binary into own json file to incorporate NULL etc.
//TODO: Same goes for generalNames.

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

			if found {
				return nil, fmt.Errorf("field '%v' contains extension, although we already parsed one",
					innerStructTyp.Name)
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

// Handles common tasks for (almost) all extensions.
// Calling this method ensures that Raw and Binary values
// are properly handled, if necessary. After that, only
// special handling regarding the Content have to be made
// If the extension was handled, a builder is returned.
// If the extension must be handled separately, nil is returned.
func commonExtensionHandler(extStruct any) (cert.ExtensionBuilder, error) {
	if reflect.ValueOf(extStruct).Kind() != reflect.Struct {
		return nil, fmt.Errorf("object is not a struct")
	}
	//raw and content exist?
	extStructVal := reflect.ValueOf(extStruct)
	rawVal := extStructVal.FieldByName("Raw")
	ctVal := extStructVal.FieldByName("Content")

	//ensure that raw exists
	kind := rawVal.Kind()
	if kind != reflect.String {
		return nil, errors.New("no 'raw String' field. illegal struct")
	}

	//get content, if it exists
	var ctStr = ""
	if ctVal.Kind() == reflect.String {
		ctStr = ctVal.String()
	}

	ctExists := ctVal.Kind() != reflect.Invalid && !ctVal.IsZero()

	rawStr := rawVal.String()

	//both empty? error
	if len(rawStr) == 0 && !ctExists {
		return config.OverrideNeededBuilder{}, nil
	}

	//both set? error
	if len(rawStr) > 0 && ctExists {
		return nil, errors.New("both 'raw' and 'content are set")
	}

	//fetch critical flag
	critVal := extStructVal.FieldByName("Critical")
	if critVal.Kind() != reflect.Bool {
		return nil, errors.New("no 'Critical bool' value. illegal struct")
	}

	//cast to interface to access oid
	var extPointer any = extStruct
	castedExtConfig, ok := extPointer.(config.ExtensionConfig)
	if !ok {
		return nil, errors.New("struct does not implement config.Extconfig. illegal struct")
	}

	critical := critVal.Bool()
	//handle raw, if possible
	if len(rawStr) > 0 {
		rawBytes, err := readRawString(rawStr)
		if err != nil {
			return nil, err
		}

		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       castedExtConfig.Oid(),
				Critical: critical,
				Value:    rawBytes,
			},
		}, nil
	}

	//handle content, if possible
	if len(ctStr) > 0 && strings.HasPrefix(ctStr, binaryPrefix) {
		rawBytes, err := readRawString(ctStr)
		if err != nil {
			return nil, errors.New("malformed binary string in content field")
		}

		return config.ConstantBuilder{
			Extension: pkix.Extension{
				Id:       castedExtConfig.Oid(),
				Critical: critical,
				Value:    rawBytes,
			},
		}, nil
	}

	return nil, nil
}

// JSON/YAML representation for this extension.
// Also implements [config.ExtensionConfig]
type SubjectKeyIdentifier struct {
	Raw      string `json:"raw"`
	Critical bool   `json:"critical"`
	Content  string `json:"content"`
}

func (s SubjectKeyIdentifier) Oid() asn1.ObjectIdentifier {
	return cert.ExpectOid(cert.OidExtensionSubjectKeyId)
}

func (s SubjectKeyIdentifier) Builder() (cert.ExtensionBuilder, error) {
	builder, err := commonExtensionHandler(s)
	if builder != nil || err != nil {
		return builder, err
	}

	//handle special cases
	switch s.Content {
	case "hash":
		return config.FunctionBuilder{
			Function: func(ctx *cert.CertificateContext) (*pkix.Extension, error) {
				return cert.NewSubjectKeyIdentifier(s.Critical, ctx)
			},
		}, nil
	default:
		return nil, fmt.Errorf(
			"malformed content for subjectKeyId: '%s'", s.Content)
	}
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

func (k KeyUsage) Oid() asn1.ObjectIdentifier {
	return cert.ExpectOid(cert.OidExtensionKeyUsage)
}

func (k KeyUsage) Builder() (cert.ExtensionBuilder, error) {
	builder, err := commonExtensionHandler(k)
	if builder != nil || err != nil {
		return builder, err
	}

	usageFlags := cert.KeyUsage(0)
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

func (s SubjectAltName) Oid() asn1.ObjectIdentifier {
	return cert.ExpectOid(cert.OidExtensionSubjectAltName)
}

func (s SubjectAltName) Builder() (cert.ExtensionBuilder, error) {
	builder, err := commonExtensionHandler(s)
	if builder != nil || err != nil {
		return builder, err
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

func (b BasicConstraints) Oid() asn1.ObjectIdentifier {
	return cert.ExpectOid(cert.OidExtensionBasicConstraints)
}

func (b BasicConstraints) Builder() (cert.ExtensionBuilder, error) {
	builder, err := commonExtensionHandler(b)
	if builder != nil || err != nil {
		return builder, err
	}

	return config.ConstantBuilder{
		Extension: cert.NewBasicConstraints(b.Critical, b.Content.Ca, b.Content.PathLen),
	}, nil
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

func (c CertPolicies) Oid() asn1.ObjectIdentifier {
	return cert.ExpectOid(cert.OidExtensionCertificatePolicies)
}

func (c CertPolicies) Builder() (cert.ExtensionBuilder, error) {
	builder, err := commonExtensionHandler(c)
	if builder != nil || err != nil {
		return builder, err
	}

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

func (a AuthInfoAccess) Oid() asn1.ObjectIdentifier {
	return cert.ExpectOid(cert.OidExtensionAuthorityInfoAccess)
}

func (a AuthInfoAccess) Builder() (cert.ExtensionBuilder, error) {
	builder, err := commonExtensionHandler(a)
	if builder != nil || err != nil {
		return builder, err
	}

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

func (a AuthKeyId) Oid() asn1.ObjectIdentifier {
	return cert.ExpectOid(cert.OidExtensionAuthorityKeyId)
}

func (a AuthKeyId) Builder() (cert.ExtensionBuilder, error) {
	builder, err := commonExtensionHandler(a)
	if builder != nil || err != nil {
		return builder, err
	}
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

func (e ExtKeyUsage) Oid() asn1.ObjectIdentifier {
	return cert.ExpectOid(cert.OidExtensionExtendedKeyUsage)
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
	builder, err := commonExtensionHandler(e)
	if builder != nil || err != nil {
		return builder, err
	}

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

func (a AdmissionExtension) Oid() asn1.ObjectIdentifier {
	return cert.ExpectOid(cert.OidExtensionAdmission)
}

func (a AdmissionExtension) Builder() (cert.ExtensionBuilder, error) {
	builder, err := commonExtensionHandler(a)
	if builder != nil || err != nil {
		return builder, err
	}

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

type OcspNoCheckExtension struct {
	Raw      string `json:"raw"`
	Critical bool   `json:"critical"`
}

func (o OcspNoCheckExtension) Oid() asn1.ObjectIdentifier {
	return cert.ExpectOid(cert.OidExtensionOcspNoCheck)
}

func (o OcspNoCheckExtension) Builder() (cert.ExtensionBuilder, error) {
	builder, err := commonExtensionHandler(o)

	//no override possible with this extension
	if (builder != nil || err != nil) && len(o.Raw) > 0 {
		return builder, err
	}

	return config.ConstantBuilder{Extension: cert.NewOcspNoCheck(o.Critical)}, nil
}

// JSON/YAML representation for this custom extensions.
// Also implements [config.ExtensionConfig]
type CustomExtension struct {
	OidStr   string `json:"oid"`
	Raw      string `json:"raw"`
	Critical bool   `json:"critical"`
}

func (c CustomExtension) Oid() asn1.ObjectIdentifier {
	oid, err := cert.OidFromString(c.OidStr)
	if err != nil {
		panic(fmt.Sprintf(
			"oid %s does not have a valid format which went "+
				"undetected when parsing the config. this is a bug",
			c.OidStr,
		))
	}
	return oid
}

func (c CustomExtension) Builder() (cert.ExtensionBuilder, error) {
	builder, err := commonExtensionHandler(c)
	if builder != nil || err != nil {
		return builder, err
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
