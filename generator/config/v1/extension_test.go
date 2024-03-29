package v1

import (
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"reflect"
	"testing"
	"time"

	"github.com/wokdav/gopki/generator/cert"
	"github.com/wokdav/gopki/generator/config"

	"github.com/santhosh-tekuri/jsonschema"
)

var compiledExtensionSchema *jsonschema.Schema
var simpleCertContext *cert.CertificateContext

func init() {
	var err error
	compiledExtensionSchema, err = compileSchema(&schemaHierarchy{schemas, "extension.json"})
	if err != nil {
		panic(err)
	}

	testduration, err := time.ParseDuration("42000h")
	if err != nil {
		panic("tests are broken")
	}
	simpleCertContext = cert.NewCertificateContext(
		nil, nil, time.Now(), time.Now().Add(testduration))
	err = simpleCertContext.GeneratePrivateKey(cert.P224)
	if err != nil {
		panic("tests are broken")
	}

	simpleCertContext.SetIssuer(cert.AsIssuer(*simpleCertContext))
}

//go:embed extension_test.json
var extensionConfigSchemaTests string

func TestExtensionSchema(t *testing.T) {
	schemaTestJson(extensionConfigSchemaTests, compiledExtensionSchema, t)
}

func buildAndCompare(cfg config.ExtensionConfig, extExpect pkix.Extension, t *testing.T) {
	builder, err := cfg.Builder()
	if err != nil {
		panic(err.Error())
	}
	extGot, err := builder.Compile(simpleCertContext)
	if err != nil {
		t.Fatal(err.Error())
	}

	if !reflect.DeepEqual(extExpect, *extGot) {
		t.Fatalf("expected '%#v', got '%#v'", extExpect, *extGot)
	}
}

func TestParseAnyExtension(t *testing.T) {
	extStruct := AnyExtension{}

	_, err := parseExtensions([]AnyExtension{extStruct})
	if err == nil {
		t.Fatal("nilled AnyExtension should fail")
	}

	emptyArr, err := parseExtensions([]AnyExtension{})
	if err != nil {
		t.Fatal("error building empty AnyExtension array")
	}

	if len(emptyArr) != 0 {
		t.Fatalf("extconfig array should be empty, but contains %d items", len(emptyArr))
	}

	subjKeyId := AnyExtension{
		SubjectKeyIdentifier: &SubjectKeyIdentifier{
			Critical: true,
			Content:  "hash",
		},
	}

	parsedSKid, err := parseExtensions([]AnyExtension{subjKeyId})
	if err != nil {
		t.Fatalf("good case should succeed, but failed with '%v'",
			err.Error())
	}

	oid := parsedSKid[0].Oid()
	expectOid, _ := cert.GetOid(cert.OidExtensionSubjectKeyId)
	if !oid.Equal(expectOid) {
		t.Fatalf("expected oid to be '%#v', but is '%#v'",
			expectOid, oid)
	}

	keyUsage := AnyExtension{
		KeyUsage: &KeyUsage{
			Critical: true,
			Content:  []string{"digitalSignature", "crlSign"},
		},
	}

	_, err = parseExtensions([]AnyExtension{{
		SubjectKeyIdentifier: subjKeyId.SubjectKeyIdentifier,
		KeyUsage:             keyUsage.KeyUsage,
	}})
	if err == nil {
		t.Fatalf("ambiguous struct should fail")
	}
}

func TestFunctionBuilderNil(t *testing.T) {
	builder := config.FunctionBuilder{}
	_, err := builder.Compile(simpleCertContext)

	//this should not panic
	if err == nil {
		t.Fatalf("expected an error on null function pointer")
	}
}

func TestSubjKeyIdOid(t *testing.T) {
	var ext config.ExtensionConfig = SubjectKeyIdentifier{}
	oid := ext.Oid()

	expectOid := asn1.ObjectIdentifier{2, 5, 29, 14}
	if !oid.Equal(expectOid) {
		t.Fatal("subjectkeyidentifier: wrong oid")
	}
}

func TestSubjKeyIdBinaryContent(t *testing.T) {
	extCfg := SubjectKeyIdentifier{
		Critical: true,
		Content:  "!binary:AQIDBA==",
	}

	extExpect := pkix.Extension{
		Critical: true,
		Id:       asn1.ObjectIdentifier{2, 5, 29, 14},
		Value:    []byte{0x01, 0x02, 0x03, 0x04},
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestSubjKeyIdHashContent(t *testing.T) {
	extCfg := SubjectKeyIdentifier{
		Critical: true,
		Content:  "hash",
	}

	extExpect, _ := cert.NewSubjectKeyIdentifier(true, simpleCertContext)

	buildAndCompare(extCfg, *extExpect, t)
}

func TestSubjKeyIdRaw(t *testing.T) {
	//AQIDBA== (0x01020304)
	extCfg := SubjectKeyIdentifier{
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}

	oid, _ := cert.GetOid(cert.OidExtensionSubjectKeyId)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    []byte{0x01, 0x02, 0x03, 0x04},
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestSubjKeyIdNull(t *testing.T) {
	//AQIDBA== (0x01020304)
	extCfg := SubjectKeyIdentifier{
		Critical: true,
		Raw:      "!null",
	}

	oid, _ := cert.GetOid(cert.OidExtensionSubjectKeyId)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    asn1.NullBytes,
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestSubjKeyIdIdBadCustomId(t *testing.T) {
	extCfg := SubjectKeyIdentifier{
		Critical: true,
		Content:  "!binary:§`~",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with bad binary tag should fail")
	}
}

func TestSubjKeyNoContent(t *testing.T) {
	extCfg := SubjectKeyIdentifier{
		Critical: true,
	}
	b, err := extCfg.Builder()
	if err != nil {
		t.Fatal("this should yield an OverrideNeededBuilder")
	}

	_, ok := b.(config.OverrideNeededBuilder)
	if !ok {
		t.Fatal("this should yield an OverrideNeededBuilder")
	}
}

func TestSubjKeyBothContentTypes(t *testing.T) {
	extCfg := SubjectKeyIdentifier{
		Content:  "hash",
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}
	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with both content and raw should fail")
	}
}

func TestSubjKeyBadContent(t *testing.T) {
	extCfg := SubjectKeyIdentifier{
		Critical: true,
		Content:  "😂👌",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal content string should fail")
	}
}

func TestSubjKeyBadRaw(t *testing.T) {
	extCfg := SubjectKeyIdentifier{
		Critical: true,
		Raw:      "😂👌",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal raw string should fail")
	}
}

func TestKeyUsage(t *testing.T) {
	extCfg := KeyUsage{
		Critical: true,
		Content: []string{
			DigitalSignature,
			NonRepudiation,
			KeyEncipherment,
			KeyAgreement,
			DataEncipherment,
			KeyAgreement,
			KeyCertSign,
			CRLSign,
		},
	}

	extExpect := cert.NewKeyUsage(true,
		cert.DigitalSignature|cert.NonRepudiation|cert.KeyEncipherment|cert.KeyAgreement|
			cert.DataEncipherment|cert.KeyAgreement|cert.KeyCertSign|cert.CRLSign)

	buildAndCompare(extCfg, extExpect, t)
}

func TestKeyUsageOid(t *testing.T) {
	var ext config.ExtensionConfig = KeyUsage{}
	oid := ext.Oid()

	expectOid := asn1.ObjectIdentifier{2, 5, 29, 15}
	if !oid.Equal(expectOid) {
		t.Fatal("subjectkeyidentifier: wrong oid")
	}
}

func TestKeyUsageRaw(t *testing.T) {
	//AQIDBA== (0x01020304)
	extCfg := KeyUsage{
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}

	oid, _ := cert.GetOid(cert.OidExtensionKeyUsage)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    []byte{0x01, 0x02, 0x03, 0x04},
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestKeyUsageNull(t *testing.T) {
	extCfg := KeyUsage{
		Critical: true,
		Raw:      "!null",
	}

	oid, _ := cert.GetOid(cert.OidExtensionKeyUsage)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    asn1.NullBytes,
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestKeyUsageNoContent(t *testing.T) {
	extCfg := KeyUsage{
		Critical: true,
	}

	b, err := extCfg.Builder()
	if err != nil {
		t.Fatal("this should yield an OverrideNeededBuilder")
	}

	_, ok := b.(config.OverrideNeededBuilder)
	if !ok {
		t.Fatal("this should yield an OverrideNeededBuilder")
	}
}

func TestKeyUsageBothContentTypes(t *testing.T) {
	extCfg := KeyUsage{
		Content:  []string{DigitalSignature},
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with both content and raw should fail")
	}
}

func TestKeyUsageBadContent(t *testing.T) {
	extCfg := KeyUsage{
		Critical: true,
		Content:  []string{"😂👌"},
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal content should fail")
	}
}

func TestKeyUsageBadRaw(t *testing.T) {
	extCfg := KeyUsage{
		Critical: true,
		Raw:      "😂👌",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal raw string should fail")
	}
}

func TestSubjAltName(t *testing.T) {
	extCfg := SubjectAltName{
		Critical: true,
		Content: []SubjAltNameComponent{
			{Type: "dns", Name: "ur.mom"},
			{Type: "mail", Name: "admin@example.com"},
			{Type: "ip", Name: "127.0.0.1"},
		},
	}

	extExpect, _ := cert.NewSubjectAlternativeName(true,
		[]cert.GeneralName{
			cert.GeneralNameDNS("ur.mom"),
			cert.GeneralNameRFC822("admin@example.com"),
			cert.GeneralNameIP([4]byte{127, 0, 0, 1}),
		},
	)

	buildAndCompare(extCfg, *extExpect, t)
}

func TestSubjAltNameOid(t *testing.T) {
	var ext config.ExtensionConfig = SubjectAltName{}
	oid := ext.Oid()

	expectOid := asn1.ObjectIdentifier{2, 5, 29, 17}
	if !oid.Equal(expectOid) {
		t.Fatal("subjectaltname: wrong oid")
	}
}

func TestSubjAltNameIpLong(t *testing.T) {
	extCfg := SubjectAltName{
		Critical: true,
		Content: []SubjAltNameComponent{
			{Type: "ip", Name: "127.0.0.1.2"},
		},
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("ip that's too long should fail")
	}
}

func TestSubjAltNameBadIpShort(t *testing.T) {
	extCfg := SubjectAltName{
		Critical: true,
		Content: []SubjAltNameComponent{
			{Type: "ip", Name: "127.0.0"},
		},
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("ip that's too short should fail")
	}
}
func TestSubjAltNameBadIp(t *testing.T) {
	extCfg := SubjectAltName{
		Critical: true,
		Content: []SubjAltNameComponent{
			{Type: "ip", Name: "127.0.0.One"},
		},
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("malformed ip should fail")
	}
}

func TestSubjAltNameRaw(t *testing.T) {
	//AQIDBA== (0x01020304)
	extCfg := SubjectAltName{
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}

	oid, _ := cert.GetOid(cert.OidExtensionSubjectAltName)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    []byte{0x01, 0x02, 0x03, 0x04},
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestSubjAltNameNull(t *testing.T) {
	extCfg := SubjectAltName{
		Critical: true,
		Raw:      "!null",
	}

	oid, _ := cert.GetOid(cert.OidExtensionSubjectAltName)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    asn1.NullBytes,
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestSubjAltNameNoContent(t *testing.T) {
	extCfg := SubjectAltName{
		Critical: true,
	}

	b, err := extCfg.Builder()
	if err != nil {
		t.Fatal("this should yield an OverrideNeededBuilder")
	}

	_, ok := b.(config.OverrideNeededBuilder)
	if !ok {
		t.Fatal("this should yield an OverrideNeededBuilder")
	}
}

func TestSubjAltNameBothContentTypes(t *testing.T) {
	extCfg := SubjectAltName{
		Content: []SubjAltNameComponent{
			{Type: "dns", Name: "ur.mom"},
		},
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with both content and raw should fail")
	}
}

func TestSubjAltNameBadContent(t *testing.T) {
	extCfg := SubjectAltName{
		Critical: true,
		Content: []SubjAltNameComponent{
			{Type: "😂", Name: "👌"},
		},
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal content should fail")
	}
}

func TestSubjAltNameBadRaw(t *testing.T) {
	extCfg := SubjectAltName{
		Critical: true,
		Raw:      "😂👌",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal raw string should fail")
	}
}

func TestBasicConstraints(t *testing.T) {
	extCfg := BasicConstraints{
		Critical: true,
		Content:  &BasicConstraintsObj{true, 5},
	}

	extExpect := cert.NewBasicConstraints(true, true, 5)

	buildAndCompare(extCfg, extExpect, t)
}

func TestBasicConstraintsOid(t *testing.T) {
	var ext config.ExtensionConfig = BasicConstraints{}
	oid := ext.Oid()

	expectOid := asn1.ObjectIdentifier{2, 5, 29, 19}
	if !oid.Equal(expectOid) {
		t.Fatal("basicconstraints: wrong oid")
	}
}

func TestBasicConstraintsRaw(t *testing.T) {
	//AQIDBA== (0x01020304)
	extCfg := BasicConstraints{
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}

	oid, _ := cert.GetOid(cert.OidExtensionBasicConstraints)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    []byte{0x01, 0x02, 0x03, 0x04},
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestBasicConstraintsNull(t *testing.T) {
	extCfg := BasicConstraints{
		Critical: true,
		Raw:      "!null",
	}

	oid, _ := cert.GetOid(cert.OidExtensionBasicConstraints)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    asn1.NullBytes,
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestBasicConstraintsBadRaw(t *testing.T) {
	extCfg := SubjectAltName{
		Critical: true,
		Raw:      "😂👌",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal raw string should fail")
	}
}

func TestCertPolicies(t *testing.T) {
	extCfg := CertPolicies{
		Critical: true,
		Content:  []CertPolicy{{Oid: "1.2.3.4"}},
	}

	extExpect, _ := cert.NewCertificatePolicies(true,
		[]cert.PolicyInfo{{ObjectIdentifier: asn1.ObjectIdentifier{1, 2, 3, 4}}})

	buildAndCompare(extCfg, *extExpect, t)
}

func TestCertPoliciesOid(t *testing.T) {
	var ext config.ExtensionConfig = CertPolicies{}
	oid := ext.Oid()

	expectOid := asn1.ObjectIdentifier{2, 5, 29, 32}
	if !oid.Equal(expectOid) {
		t.Fatal("certpolicies: wrong oid")
	}
}

func TestCertPoliciesRaw(t *testing.T) {
	//AQIDBA== (0x01020304)
	extCfg := CertPolicies{
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}

	oid, _ := cert.GetOid(cert.OidExtensionCertificatePolicies)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    []byte{0x01, 0x02, 0x03, 0x04},
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestCertPoliciesNull(t *testing.T) {
	extCfg := CertPolicies{
		Critical: true,
		Raw:      "!null",
	}

	oid, _ := cert.GetOid(cert.OidExtensionCertificatePolicies)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    asn1.NullBytes,
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestCertPoliciesNoContent(t *testing.T) {
	extCfg := CertPolicies{
		Critical: true,
	}

	b, err := extCfg.Builder()
	if err != nil {
		t.Fatal("this should yield an OverrideNeededBuilder")
	}

	_, ok := b.(config.OverrideNeededBuilder)
	if !ok {
		t.Fatal("this should yield an OverrideNeededBuilder")
	}
}

func TestCertPoliciesBothContentTypes(t *testing.T) {
	extCfg := CertPolicies{
		Content:  []CertPolicy{{Oid: "1.2.3.4"}},
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with both content and raw should fail")
	}
}

func TestCertPoliciesBadContent(t *testing.T) {
	extCfg := CertPolicies{
		Critical: true,
		Content:  []CertPolicy{{Oid: "😂👌"}},
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal content should fail")
	}
}

func TestCertPoliciesBadRaw(t *testing.T) {
	extCfg := CertPolicies{
		Critical: true,
		Raw:      "😂👌",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal raw string should fail")
	}
}

func TestAia(t *testing.T) {
	extCfg := AuthInfoAccess{
		Critical: true,
		Content:  []SingleAuthInfo{{Ocsp: "ocsp.example.com"}},
	}

	extExpect, _ := cert.NewAuthorityInfoAccess(true,
		[]cert.AccessDescription{{
			AccessMethod:   cert.Ocsp,
			AccessLocation: cert.GeneralNameURI("ocsp.example.com")}})

	buildAndCompare(extCfg, *extExpect, t)
}

func TestAiaOid(t *testing.T) {
	var ext config.ExtensionConfig = AuthInfoAccess{}
	oid := ext.Oid()

	expectOid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	if !oid.Equal(expectOid) {
		t.Fatal("authorityinfoaccess: wrong oid")
	}
}

func TestAiaRaw(t *testing.T) {
	//AQIDBA== (0x01020304)
	extCfg := AuthInfoAccess{
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}

	oid, _ := cert.GetOid(cert.OidExtensionAuthorityInfoAccess)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    []byte{0x01, 0x02, 0x03, 0x04},
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestAiaNull(t *testing.T) {
	//AQIDBA== (0x01020304)
	extCfg := AuthInfoAccess{
		Critical: true,
		Raw:      "!null",
	}

	oid, _ := cert.GetOid(cert.OidExtensionAuthorityInfoAccess)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    asn1.NullBytes,
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestAiaNoContent(t *testing.T) {
	extCfg := AuthInfoAccess{
		Critical: true,
	}

	b, err := extCfg.Builder()
	if err != nil {
		t.Fatal("this should yield an OverrideNeededBuilder")
	}

	_, ok := b.(config.OverrideNeededBuilder)
	if !ok {
		t.Fatal("this should yield an OverrideNeededBuilder")
	}
}

func TestAiaBothContentTypes(t *testing.T) {
	extCfg := AuthInfoAccess{
		Content:  []SingleAuthInfo{{Ocsp: "ocsp.example.com"}},
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with both content and raw should fail")
	}
}

func TestAiaBadContent(t *testing.T) {
	extCfg := AuthInfoAccess{
		Critical: true,
		Content:  []SingleAuthInfo{{Ocsp: ""}},
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal content should fail")
	}
}

func TestAiaBadRaw(t *testing.T) {
	extCfg := AuthInfoAccess{
		Critical: true,
		Raw:      "😂👌",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal raw string should fail")
	}
}

func TestAuthKeyIdOid(t *testing.T) {
	var ext config.ExtensionConfig = AuthKeyId{}
	oid := ext.Oid()

	expectOid := asn1.ObjectIdentifier{2, 5, 29, 35}
	if !oid.Equal(expectOid) {
		t.Fatal("authkeyid: wrong oid")
	}
}

func TestAuthKeyIdHash(t *testing.T) {
	extCfg := AuthKeyId{
		Critical: true,
		Content:  AuthKeyIdContent{"hash"},
	}

	extExpect, err := cert.NewAuthorityKeyIdentifierHash(
		true, simpleCertContext,
	)
	if err != nil {
		t.Fatal(err.Error())
	}

	buildAndCompare(extCfg, *extExpect, t)
}

func TestAuthKeyIdCustomId(t *testing.T) {
	//AQIDBA== (0x01020304)
	extCfg := AuthKeyId{
		Critical: true,
		Content:  AuthKeyIdContent{"!binary:AQIDBA=="},
	}

	extExpect, _ := cert.NewAuthorityKeyIdentifierFromStruct(
		true, cert.AuthorityKeyIdentifier{
			KeyIdentifier: []byte{0x01, 0x02, 0x03, 0x04}},
	)

	buildAndCompare(extCfg, *extExpect, t)
}

func TestAuthKeyIdRaw(t *testing.T) {
	//AQIDBA== (0x01020304)
	extCfg := AuthKeyId{
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}

	oid, _ := cert.GetOid(cert.OidExtensionAuthorityKeyId)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    []byte{0x01, 0x02, 0x03, 0x04},
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestAuthKeyIdNull(t *testing.T) {
	extCfg := AuthKeyId{
		Critical: true,
		Raw:      "!null",
	}

	oid, _ := cert.GetOid(cert.OidExtensionAuthorityKeyId)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    asn1.NullBytes,
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestAuthKeyIdBadCustomId(t *testing.T) {
	extCfg := AuthKeyId{
		Critical: true,
		Content:  AuthKeyIdContent{"!binary:§`~"},
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with bad binary tag should fail")
	}
}

func TestAuthKeyIdNoContent(t *testing.T) {
	extCfg := AuthKeyId{
		Critical: true,
	}

	b, err := extCfg.Builder()
	if err != nil {
		t.Fatal("this should yield an OverrideNeededBuilder")
	}

	_, ok := b.(config.OverrideNeededBuilder)
	if !ok {
		t.Fatal("this should yield an OverrideNeededBuilder")
	}
}

func TestAuthKeyIdBothContentTypes(t *testing.T) {
	extCfg := AuthKeyId{
		Content:  AuthKeyIdContent{"hash"},
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with both content and raw should fail")
	}
}

func TestAuthKeyIdBadContent(t *testing.T) {
	extCfg := AuthKeyId{
		Critical: true,
		Content:  AuthKeyIdContent{"😂👌"},
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal content should fail")
	}
}

func TestAuthKeyIdBadRaw(t *testing.T) {
	extCfg := AuthKeyId{
		Critical: true,
		Raw:      "😂👌",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal raw string should fail")
	}
}

func TestExtKeyUsage(t *testing.T) {
	extCfg := ExtKeyUsage{
		Critical: true,
		Content: []string{
			ServerAuth,
			ClientAuth,
			CodeSigning,
			EmailProtection,
			TimeStamping,
			OcspSigning,
			"1.2.3.4",
		},
	}

	extKeyUsages := []cert.ExtKeyUsage{
		cert.ServerAuth,
		cert.ClientAuth,
		cert.CodeSigning,
		cert.EmailProtection,
		cert.TimeStamping,
		cert.OcspSigning,
	}

	oids := make([]asn1.ObjectIdentifier, len(extKeyUsages)+1)
	for i, ku := range extKeyUsages {
		oids[i], _ = cert.GetExtendedKeyUsage(ku)
	}

	oids[len(oids)-1] = asn1.ObjectIdentifier{1, 2, 3, 4}

	extExpect, _ := cert.NewExtendedKeyUsage(true, oids)

	buildAndCompare(extCfg, *extExpect, t)
}

func TestExtKeyUsageOid(t *testing.T) {
	var ext config.ExtensionConfig = ExtKeyUsage{}
	oid := ext.Oid()

	expectOid := asn1.ObjectIdentifier{2, 5, 29, 37}
	if !oid.Equal(expectOid) {
		t.Fatal("extkeyusage: wrong oid")
	}
}

func TestExtKeyUsageRaw(t *testing.T) {
	//AQIDBA== (0x01020304)
	extCfg := ExtKeyUsage{
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}

	oid, _ := cert.GetOid(cert.OidExtensionExtendedKeyUsage)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    []byte{0x01, 0x02, 0x03, 0x04},
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestExtKeyUsageNull(t *testing.T) {
	extCfg := ExtKeyUsage{
		Critical: true,
		Raw:      "!null",
	}

	oid, _ := cert.GetOid(cert.OidExtensionExtendedKeyUsage)
	extExpect := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    asn1.NullBytes,
	}

	buildAndCompare(extCfg, extExpect, t)
}

func TestExtKeyUsageNoContent(t *testing.T) {
	extCfg := ExtKeyUsage{
		Critical: true,
	}

	b, err := extCfg.Builder()
	if err != nil {
		t.Fatal("this should yield an OverrideNeededBuilder")
	}

	_, ok := b.(config.OverrideNeededBuilder)
	if !ok {
		t.Fatal("this should yield an OverrideNeededBuilder")
	}
}

func TestExtKeyUsageBothContentTypes(t *testing.T) {
	extCfg := ExtKeyUsage{
		Content:  []string{ServerAuth},
		Critical: true,
		Raw:      "!binary:AQIDBA==",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with both content and raw should fail")
	}
}

func TestExtKeyUsageBadContent(t *testing.T) {
	extCfg := ExtKeyUsage{
		Critical: true,
		Content:  []string{"😂👌"},
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal content should fail")
	}
}

func TestExtKeyUsageBadRaw(t *testing.T) {
	extCfg := ExtKeyUsage{
		Critical: true,
		Raw:      "😂👌",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal raw string should fail")
	}
}

func TestCustomExtension(t *testing.T) {
	extCfg := CustomExtension{
		Critical: true,
		OidStr:   "8.9.10.11",
		Raw:      "!binary:AQIDBA==",
	}

	extExpect := pkix.Extension{
		Id:       asn1.ObjectIdentifier{8, 9, 10, 11},
		Critical: true,
		Value:    []byte{0x01, 0x02, 0x03, 0x04},
	}
	buildAndCompare(extCfg, extExpect, t)
}

func TestCustomExtensionOid(t *testing.T) {
	var ext config.ExtensionConfig = CustomExtension{OidStr: "1.2.3.4"}
	oid := ext.Oid()

	expectOid := asn1.ObjectIdentifier{1, 2, 3, 4}
	if !oid.Equal(expectOid) {
		t.Fatal("customextension: wrong oid")
	}
}

func TestCustomExtensionNull(t *testing.T) {
	extCfg := CustomExtension{
		Critical: true,
		OidStr:   "8.9.10.11",
		Raw:      "!null",
	}

	extExpect := pkix.Extension{
		Id:       asn1.ObjectIdentifier{8, 9, 10, 11},
		Critical: true,
		Value:    asn1.NullBytes,
	}
	buildAndCompare(extCfg, extExpect, t)
}

func TestCustomExtensionEmpty(t *testing.T) {
	extCfg := CustomExtension{
		Critical: true,
		OidStr:   "8.9.10.11",
		Raw:      "!empty",
	}

	extExpect := pkix.Extension{
		Id:       asn1.ObjectIdentifier{8, 9, 10, 11},
		Critical: true,
		Value:    []byte{},
	}
	buildAndCompare(extCfg, extExpect, t)
}

func TestCustomExtensionBadBinary(t *testing.T) {
	extCfg := CustomExtension{
		Critical: true,
		OidStr:   "8.9.10.11",
		Raw:      "!binary:§`",
	}

	_, err := extCfg.Builder()
	if err == nil {
		t.Fatal("build with illegal raw string should fail")
	}
}

func TestAdmissionEmpty(t *testing.T) {
	extCfg := AdmissionExtension{
		Content: &Admission{},
	}

	_, err := extCfg.Builder()
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestAdmissionMinimumViable(t *testing.T) {
	extCfg := AdmissionExtension{
		Content: &Admission{
			Admissions: []SingleAdmission{
				{
					ProfessionInfos: []ProfessionInfo{
						{
							ProfessionItems: []string{"Versicherte/r"},
							ProfessionOids:  []string{"1.2.276.0.76.4.49"},
						},
					},
				},
			},
		},
	}

	_, err := extCfg.Builder()
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestOcspNoCheckCritical(t *testing.T) {
	extExpect := pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
		Critical: true,
		Value:    []byte{0x05, 0x00},
	}
	buildAndCompare(OcspNoCheckExtension{Critical: true}, extExpect, t)

	extExpect.Critical = false
	buildAndCompare(OcspNoCheckExtension{Critical: false}, extExpect, t)
}
