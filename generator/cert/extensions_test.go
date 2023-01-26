package cert

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGetOid(t *testing.T) {
	for i := 0; i < int(oidExtensionLen); i++ {
		oid, ok := GetOid(ExtensionOid(i))
		if oid == nil {
			//implicitly also checks if panic happens
			t.Fatal("GetOid should yield a result")
		}

		if !ok {
			t.Fatal("GetOid should work in this case")
		}
	}

	if len(oids) != int(oidExtensionLen) {
		t.Fatalf("malformed oid array")
	}
}

func TestGetOidOutOfBounds(t *testing.T) {
	oid, ok := GetOid(ExtensionOid(999999999))
	if ok {
		t.Fatalf("this oid should not be ok")
	}

	if oid != nil {
		//implicitly also checks if panic happens
		t.Fatalf("this should not yield a result")
	}
}

func TestGetExtKeyUsage(t *testing.T) {
	for i := 0; i < int(extKeyUsageLen); i++ {
		oid, ok := GetExtendedKeyUsage(ExtKeyUsage(i))
		if !ok {
			t.Fatalf("GetOid should be ok")
		}

		if oid == nil {
			//implicitly also checks if panic happens
			t.Fatalf("GetOid should yield a result")
		}
	}

	if len(extKeyUsages) != int(extKeyUsageLen) {
		t.Fatalf("malformed extKeyUsage array")
	}
}

func TestGetExtKeyUsageOutOfBounds(t *testing.T) {
	oid, ok := GetExtendedKeyUsage(ExtKeyUsage(999999999))
	if ok {
		t.Fatalf("this oid should not be ok")
	}

	if oid != nil {
		//implicitly also checks if panic happens
		t.Fatalf("this should not yield a result")
	}
}

func TestSubjectKeyIdNilError(t *testing.T) {
	_, err := NewSubjectKeyIdentifier(false, nil)
	if err == nil {
		t.Fatalf("this should fail")
	}
}

func TestSubjectKeyIdDifferent(t *testing.T) {
	//check that subjectKeyId is different for different keys
	tbs1, err := NewCertificateContext(nil, P224, nil, time.Now(), time.Now().Add(testduration))
	if err != nil {
		t.Fatalf(err.Error())
	}

	tbs2, err := NewCertificateContext(nil, P224, nil, time.Now(), time.Now().Add(testduration))
	if err != nil {
		t.Fatalf(err.Error())
	}

	kid1, err := NewSubjectKeyIdentifier(false, tbs1)
	if err != nil {
		t.Fatalf(err.Error())
	}

	kid2, err := NewSubjectKeyIdentifier(false, tbs2)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if reflect.DeepEqual(kid1.Value, kid2.Value) {
		t.Fatalf("key id should be different for different keys")
	}
}

func TestKeyUsage(t *testing.T) {
	type test struct {
		flags        KeyUsage
		expectedBits [8]bool
	}

	suite := []test{
		{DigitalSignature, [8]bool{true, false, false, false, false, false, false, false}},
		{NonRepudiation, [8]bool{false, true, false, false, false, false, false, false}},
		{KeyEncipherment, [8]bool{false, false, true, false, false, false, false, false}},
		{DataEncipherment, [8]bool{false, false, false, true, false, false, false, false}},
		{KeyAgreement, [8]bool{false, false, false, false, true, false, false, false}},
		{KeyCertSign, [8]bool{false, false, false, false, false, true, false, false}},
		{CRLSign, [8]bool{false, false, false, false, false, false, true, false}},
		{KeyUsage(1), [8]bool{false, false, false, false, false, false, false, false}},
		{KeyUsage(0), [8]bool{false, false, false, false, false, false, false, false}},
		{
			DigitalSignature | NonRepudiation | KeyEncipherment | DataEncipherment |
				KeyAgreement | KeyCertSign | CRLSign,
			[8]bool{true, true, true, true, true, true, true, false},
		},
	}

	for i, tst := range suite {
		t.Run(fmt.Sprintf("KeyUsage Test #%d", i+1), func(t *testing.T) {
			ku := NewKeyUsage(false, tst.flags)
			bs := asn1.BitString{}
			_, err := asn1.Unmarshal(ku.Value, &bs)
			if err != nil {
				t.Errorf(err.Error())
			}
			for k := 0; k < 8; k++ {
				if (bs.At(k) == 1) != (tst.expectedBits[k]) {
					t.Errorf("bit %d has an unexpected position (%d)", k+1, bs.At(k))
				}
			}
		})
	}
}

func TestSubjectAlternativeNameOid(t *testing.T) {
	ext, _ := NewSubjectAlternativeName(false,
		[]GeneralName{GeneralNameDNS("dontcare")},
	)

	if !ext.Id.Equal(oidExtensionSubjectAltName) {
		t.Fatalf("wrong extension oid: %#v", ext.Id)
	}
}

func TestSubjectAlternativeNameCritical(t *testing.T) {
	ext, _ := NewSubjectAlternativeName(true,
		[]GeneralName{GeneralNameDNS("dontcare")},
	)

	if !ext.Critical {
		t.Fatal("extension should be critical")
	}
}

func TestSubjectAlternativeNameMail(t *testing.T) {
	//taken from https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
	expectedName := "a@example.com"
	expectedNameASN1 := []byte{
		0x30, 0x0f,
		0x81, 0x0d, 0x61, 0x40, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
	}

	ext, _ := NewSubjectAlternativeName(false,
		[]GeneralName{GeneralNameRFC822(expectedName)},
	)

	if !reflect.DeepEqual(expectedNameASN1, ext.Value) {
		t.Fatalf("byte array does not conform: %v", hex.EncodeToString(ext.Value))
	}
}

func TestSubjectAlternativeNameDNS(t *testing.T) {
	//taken from https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
	expectedName := "example.com"
	expectedNameASN1 := []byte{
		0x30, 0x0d,
		0x82, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
	}

	ext, _ := NewSubjectAlternativeName(false,
		[]GeneralName{GeneralNameDNS(expectedName)},
	)

	if !reflect.DeepEqual(expectedNameASN1, ext.Value) {
		t.Fatalf("byte array does not conform: %v", hex.EncodeToString(ext.Value))
	}
}

func TestSubjectAlternativeNameUri(t *testing.T) {
	expectedName := "http://example.com"
	expectedNameASN1 := []byte{
		0x30, 0x14,
		0x86, 0x12, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x65, 0x78, 0x61,
		0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
	}

	ext, _ := NewSubjectAlternativeName(false,
		[]GeneralName{GeneralNameURI(expectedName)},
	)

	if !reflect.DeepEqual(expectedNameASN1, ext.Value) {
		t.Fatalf("byte array does not conform: %v", hex.EncodeToString(ext.Value))
	}
}

func TestSubjectAlternativeNameIP(t *testing.T) {
	expectedName := [4]byte{0xC0, 0xA8, 0x40, 0x1}
	expectedNameASN1 := []byte{
		0x30, 0x06,
		0x87, 0x04, 0xC0, 0xA8, 0x40, 0x01,
	}

	ext, _ := NewSubjectAlternativeName(false,
		[]GeneralName{GeneralNameIP(expectedName)},
	)

	if !reflect.DeepEqual(expectedNameASN1, ext.Value) {
		t.Fatalf("byte array does not conform: %v", hex.EncodeToString(ext.Value))
	}
}

func TestBasicConstraintsOid(t *testing.T) {
	ext := NewBasicConstraints(false, false, 0)
	if !ext.Id.Equal(oidExtensionBasicConstraints) {
		t.Fatalf("wrong extension oid: %#v", ext.Id)
	}
}

func TestBasicConstraintsCritical(t *testing.T) {
	if !NewBasicConstraints(true, false, 0).Critical {
		t.Fatal("extension should be critical")
	}
}

func TestBasicConstraintsNoCa(t *testing.T) {
	expected := []byte{0x30, 0x00}
	ext := NewBasicConstraints(false, false, 0)
	if !reflect.DeepEqual(ext.Value, expected) {
		t.Fatalf("byte array does not conform: %v", hex.EncodeToString(ext.Value))
	}
}

func TestBasicConstraintsCaInfinite(t *testing.T) {
	expected := []byte{0x30, 0x03, 0x01, 0x01, 0xFF}
	ext := NewBasicConstraints(false, true, 0)
	if !reflect.DeepEqual(ext.Value, expected) {
		t.Fatalf("byte array does not conform: %v", hex.EncodeToString(ext.Value))
	}
}

func TestBasicConstraintsCaThree(t *testing.T) {
	expected := []byte{0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x03}
	ext := NewBasicConstraints(false, true, 3)
	if !reflect.DeepEqual(ext.Value, expected) {
		t.Fatalf("byte array does not conform: %v", hex.EncodeToString(ext.Value))
	}
}

func TestCertificatePoliciesOid(t *testing.T) {
	ext, _ := NewCertificatePolicies(false, []PolicyInfo{})
	if !ext.Id.Equal(oidExtensionCertificatePolicies) {
		t.Fatalf("wrong extension oid: %#v", ext.Id)
	}
}

func TestCertificatePoliciesCritical(t *testing.T) {
	ext, _ := NewCertificatePolicies(true, []PolicyInfo{})
	if !ext.Critical {
		t.Fatal("extension should be critical")
	}
}

func TestCertificatePoliciesSimpleId(t *testing.T) {
	expected := []byte{0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x2A, 0x03, 0x04}
	ext, _ := NewCertificatePolicies(false, []PolicyInfo{
		{asn1.ObjectIdentifier{1, 2, 3, 4}, nil},
	})
	if !reflect.DeepEqual(expected, ext.Value) {
		t.Fatalf("byte array does not conform: %v", hex.EncodeToString(ext.Value))
	}
}

func TestCertificatePoliciesIdWithQualifiers(t *testing.T) {
	certPolB64 := "MIGxMAUGAyoDBDAGBgQtBgcIMIGfBgMrBQgwgZcwJwYIKwYBBQUHAgEWG2h0dHA6Ly9teS5ob3N0" +
		"LmV4YW1wbGUuY29tLzAnBggrBgEFBQcCARYbaHR0cDovL215LnlvdXIuZXhhbXBsZS5jb20vMEMG" +
		"CCsGAQUFBwICMDcwIQwRT3JnYW5pc2F0aW9uIE5hbWUwDAIBAQIBAgIBAwIBBAwSRXhwbGljaXQg" +
		"VGV4dCBIZXJl"
	dec := base64.NewDecoder(base64.StdEncoding, strings.NewReader(certPolB64))

	expected := make([]byte, len(certPolB64))
	n, err := dec.Read(expected)
	if err != nil {
		t.Fatal(err.Error())
	}
	expected = expected[:n]

	ext, err := NewCertificatePolicies(false, []PolicyInfo{
		{ObjectIdentifier: asn1.ObjectIdentifier{1, 2, 3, 4}},
		{ObjectIdentifier: asn1.ObjectIdentifier{1, 5, 6, 7, 8}},
		{ObjectIdentifier: asn1.ObjectIdentifier{1, 3, 5, 8}, Qualifiers: []PolicyQualifier{
			{QualifierId: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}, Cps: "http://my.host.example.com/"},
			{QualifierId: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}, Cps: "http://my.your.example.com/"},
			{QualifierId: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}, UserNotice: UserNotice{
				NoticeRef: NoticeReference{
					Organization:  "Organisation Name",
					NoticeNumbers: []int{1, 2, 3, 4},
				},
				ExplicitText: "Explicit Text Here"},
			},
		}},
	})

	if err != nil {
		t.Fatal(err.Error())
	}

	if !bytes.Equal(expected, ext.Value) {
		t.Error(hex.EncodeToString(expected))
		t.Fatalf("byte array does not conform: %v", hex.EncodeToString(ext.Value))
	}
}

func TestAiaOid(t *testing.T) {
	ext, _ := NewAuthorityInfoAccess(false, []AccessDescription{})
	if !ext.Id.Equal(oidExtensionAuthorityInfoAccess) {
		t.Fatalf("wrong extension oid: %#v", ext.Id)
	}
}

func TestAiaCritical(t *testing.T) {
	ext, _ := NewAuthorityInfoAccess(true, []AccessDescription{})
	if !ext.Critical {
		t.Fatal("extension should be critical")
	}
}

func TestAiaIllegalAccessMethod(t *testing.T) {
	_, err := NewAuthorityInfoAccess(true, []AccessDescription{
		{
			AccessMethod:   AccessMethod(34805),
			AccessLocation: GeneralNameURI("service.example.com"),
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown access method") {
		t.Fatal("this should fail due to an unknown access method")
	}
}

func TestAuthorityInfoAccessURI(t *testing.T) {
	expected := []byte{
		0x30, 0x25, 0x30, 0x23,
		0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01,
		0x86, 0x17, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f,
		0x63, 0x73, 0x70, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
		0x65, 0x2e, 0x63, 0x6f, 0x6d,
	}
	ext, _ := NewAuthorityInfoAccess(true, []AccessDescription{
		{AccessMethod: Ocsp, AccessLocation: GeneralNameURI("http://ocsp.example.com")},
	})
	if !reflect.DeepEqual(expected, ext.Value) {
		t.Fatalf("byte array does not conform: %v, %v", hex.EncodeToString(ext.Value), hex.EncodeToString(expected))
	}
}

func TestExtKeyUsageOid(t *testing.T) {
	ext, _ := NewExtendedKeyUsage(false, []asn1.ObjectIdentifier{})
	if !ext.Id.Equal(oidExtensionExtendedKeyUsage) {
		t.Fatalf("wrong extension oid: %#v", ext.Id)
	}
}

func TestExtKeyUsageCritical(t *testing.T) {
	ext, _ := NewExtendedKeyUsage(true, []asn1.ObjectIdentifier{})
	if !ext.Critical {
		t.Fatal("extension should be critical")
	}
}

func TestCertificatePoliciesClientAuth(t *testing.T) {
	expected := []byte{0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02}
	oid, _ := GetExtendedKeyUsage(ClientAuth)
	ext, _ := NewExtendedKeyUsage(false, []asn1.ObjectIdentifier{oid})
	if !reflect.DeepEqual(expected, ext.Value) {
		t.Fatalf("byte array does not conform: %v", hex.EncodeToString(ext.Value))
	}
}

func TestAuthKeyIdOid(t *testing.T) {
	ext, _ := NewAuthorityKeyIdentifierFromStruct(false, AuthorityKeyIdentifier{})
	if !ext.Id.Equal(oidExtensionAuthorityKeyId) {
		t.Fatalf("wrong extension oid: %#v", ext.Id)
	}

	ctx, _ := NewCertificateContext(nil, P224, nil, time.Now(), time.Now().Add(testduration))
	ext, err := NewAuthorityKeyIdentifierHash(false, ctx)
	if err != nil {
		t.Fatal(err.Error())
	}
	if !ext.Id.Equal(oidExtensionAuthorityKeyId) {
		t.Fatalf("wrong extension oid: %#v", ext.Id)
	}
}

func TestAuthKeyCritical(t *testing.T) {
	ext, _ := NewAuthorityKeyIdentifierFromStruct(true, AuthorityKeyIdentifier{})
	if !ext.Critical {
		t.Fatal("extension should be critical")
	}

	ctx, _ := NewCertificateContext(nil, P224, nil, time.Now(), time.Now().Add(testduration))
	ext, _ = NewAuthorityKeyIdentifierHash(true, ctx)
	if !ext.Critical {
		t.Fatal("extension should be critical")
	}
}

func TestAuthKeyNil(t *testing.T) {
	ctx, _ := NewCertificateContext(nil, P224, nil, time.Now(), time.Now().Add(testduration))
	ctx.Issuer.publicKeyRaw = nil
	_, err := NewAuthorityKeyIdentifierHash(true, ctx)
	if err == nil || !strings.Contains(err.Error(), "key is nil") {
		t.Fatal("expected error due to nil key")
	}

	ctx.Issuer = nil
	_, err = NewAuthorityKeyIdentifierHash(true, ctx)
	if err == nil || !strings.Contains(err.Error(), "key is nil") {
		t.Fatal("expected error due to nil key")
	}
}

func TestAuthKeyRawKeyId(t *testing.T) {
	expected := []byte{0x30, 0x06, 0x80, 0x04, 0x01, 0x02, 0x03, 0x04}
	ext, _ := NewAuthorityKeyIdentifierFromStruct(false, AuthorityKeyIdentifier{
		KeyIdentifier: []byte{0x01, 0x02, 0x03, 0x04},
	})
	if !reflect.DeepEqual(expected, ext.Value) {
		t.Fatalf("byte array does not conform: %v", hex.EncodeToString(ext.Value))
	}
}

func TestAuthKeyHashKeyId(t *testing.T) {
	expectedPrefix := []byte{0x30, 0x16, 0x80, 0x14}
	ctx, _ := NewCertificateContext(nil, P224, nil, time.Now(), time.Now().Add(testduration))
	ext, _ := NewAuthorityKeyIdentifierHash(true, ctx)
	if !bytes.HasPrefix(ext.Value, expectedPrefix) {
		t.Fatalf("byte array does not conform: %v", hex.EncodeToString(ext.Value))
	}
}
