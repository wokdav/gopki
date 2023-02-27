package config

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/wokdav/gopki/generator/cert"
)

func TestValidateSubject(t *testing.T) {
	type testProfile struct {
		ProfileSubjectAttributes
		expectSuccess bool
	}

	tests := map[string]testProfile{
		"C=DE": {
			ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "C", Optional: false},
				},
			}, true},
		"C=DE, O=Acme, OU=Admin, CN=Cert, SERIALNUMBER=123, L=Berlin, STREET=Street1, POSTALCODE=12345": {
			ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "C", Optional: false},
					{Attribute: "O", Optional: false},
					{Attribute: "OU", Optional: false},
					{Attribute: "CN", Optional: false},
					{Attribute: "SERIALNUMBER", Optional: false},
					{Attribute: "L", Optional: false},
					{Attribute: "STREET", Optional: false},
					{Attribute: "POSTALCODE", Optional: false},
				},
			}, true},
		"1.2.3.4=CustomOidTest": {
			ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "1.2.3.4", Optional: false},
				},
			}, true},
		"O=Missing": {
			ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "CN", Optional: false},
				},
			}, false},
		"O=Missing, CN=Acme": {
			ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "CN", Optional: false},
				},
			}, false},
		"CN=Acme, O=Missing": {
			ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "CN", Optional: false},
				},
			}, false},
		"CN=Acme, O=Order": {
			ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "O", Optional: false},
					{Attribute: "CN", Optional: false},
				},
			}, false},
		"CN=Optional": {
			ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "CN", Optional: true},
				},
			}, true},
		"O=NotOptional": {
			ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "CN", Optional: false},
					{Attribute: "O", Optional: true},
				},
			}, false},
		"O=NotOptional2": {
			ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "O", Optional: false},
					{Attribute: "CN", Optional: true},
				},
			}, true},
		"O=Optional, CN=Ordering": {
			ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "CN", Optional: true},
					{Attribute: "O", Optional: true},
				},
			}, false},
		"CN=AllowOther": {
			ProfileSubjectAttributes{
				AllowOther: true,
				Attributes: []ProfileSubjectAttribute{},
			}, true},
		"CN=AllowOtherOptional": {
			ProfileSubjectAttributes{
				AllowOther: true,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "O", Optional: true},
				},
			}, true},
		"CN=AllowOtherMandatory, O=Back": {
			ProfileSubjectAttributes{
				AllowOther: true,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "O", Optional: false},
				},
			}, true},
		"O=Front, CN=AllowOtherMandatory": {
			ProfileSubjectAttributes{
				AllowOther: true,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "O", Optional: false},
				},
			}, true},
		"O=Wrong, CN=Ordering, L=Allowed": {
			ProfileSubjectAttributes{
				AllowOther: true,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "CN", Optional: false},
					{Attribute: "O", Optional: false},
				},
			}, true},
		"O=Wrong, CN=Ordering, L=Optional": {
			ProfileSubjectAttributes{
				AllowOther: true,
				Attributes: []ProfileSubjectAttribute{
					{Attribute: "CN", Optional: true},
					{Attribute: "O", Optional: true},
				},
			}, true},
		"O=Empty": {
			ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []ProfileSubjectAttribute{},
			}, false},
	}

	for rdnString, test := range tests {
		t.Run(rdnString, func(t *testing.T) {
			subjectRdn, err := ParseRDNSequence(rdnString)
			if err != nil {
				t.Fatalf(err.Error())
			}
			if Validate(CertificateProfile{SubjectAttributes: test.ProfileSubjectAttributes},
				CertificateContent{Subject: subjectRdn}) != test.expectSuccess {
				t.Fatalf("expect return value to be %v, but it's the opposite", test.expectSuccess)
			}
		})
	}
}

func TestMergeValidity(t *testing.T) {
	type validity struct {
		from  time.Time
		until time.Time
	}
	validity1 := validity{time.Now(), time.Now().AddDate(20, 0, 0)}
	validity2 := validity{time.Now().AddDate(15, 0, 0), time.Now().AddDate(25, 0, 0)}

	type testVector struct {
		profile *validity
		certCfg validity
		expect  validity
	}

	not_set := validity{}

	tests := []testVector{
		{profile: &validity1, certCfg: not_set, expect: validity1},
		{profile: nil, certCfg: validity1, expect: validity1},
		{profile: &validity1, certCfg: validity2, expect: validity2},
		{profile: &validity1, certCfg: validity1, expect: validity1},
		{profile: &validity2, certCfg: validity1, expect: validity1},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("merge-validity-#%v", i), func(t *testing.T) {
			var prof CertificateProfile
			if test.profile == nil {
				prof = CertificateProfile{
					ValidFrom:  nil,
					ValidUntil: nil,
				}
			} else {
				prof = CertificateProfile{
					ValidFrom:  &test.profile.from,
					ValidUntil: &test.profile.until,
				}
			}

			content, err := Merge(
				prof,
				CertificateContent{
					ValidFrom:  test.certCfg.from,
					ValidUntil: test.certCfg.until,
				},
			)
			if err != nil {
				t.Fatal(err.Error())
			}

			if !content.ValidFrom.Equal(test.expect.from) ||
				!content.ValidUntil.Equal(test.expect.until) {
				t.Fatalf("expected date to be [from=%v,until=%v] bit it was [from=%v,until=%v] instead",
					test.expect.from, test.expect.until,
					content.ValidFrom, content.ValidUntil,
				)
			}
		})
	}
}

type testExt struct {
	Content string
	asn1.ObjectIdentifier
}

func (t testExt) Oid() (asn1.ObjectIdentifier, error) {
	return t.ObjectIdentifier, nil
}

func (t testExt) ContentEquals(other ExtensionConfig) bool {
	otherCasted, ok := other.(testExt)
	if !ok {
		return false
	}

	return t.Content == otherCasted.Content
}

func (t testExt) Builder() (cert.ExtensionBuilder, error) {
	return ConstantBuilder{
		Extension: pkix.Extension{
			Id:       t.ObjectIdentifier,
			Critical: false,
			Value:    []byte(t.Content),
		},
	}, nil
}

func TestMergeExtensions(t *testing.T) {
	type testVector struct {
		profile    []ProfileExtension
		certConfig []ExtensionConfig
		result     []ExtensionConfig
	}

	ext := testExt{ObjectIdentifier: asn1.ObjectIdentifier{1, 2, 3, 4}}

	extProf := ProfileExtension{ext, ExtensionProfile{}}
	extOverride := ProfileExtension{ext, ExtensionProfile{Override: true}}
	extOptional := ProfileExtension{ext, ExtensionProfile{Optional: true}}

	extDifferentContent := ext
	extDifferentContent.Content = "im different"

	ext2 := testExt{ObjectIdentifier: asn1.ObjectIdentifier{5, 6, 7, 8}}

	ext2Override := ProfileExtension{ext2, ExtensionProfile{Override: true}}

	tests := []testVector{
		{
			profile:    []ProfileExtension{},
			certConfig: []ExtensionConfig{},
			result:     []ExtensionConfig{},
		}, {
			//if cert does not have it, add it
			profile:    []ProfileExtension{extProf},
			certConfig: []ExtensionConfig{},
			result:     []ExtensionConfig{ext},
		}, {
			//check that identical extensions are not added
			profile:    []ProfileExtension{extProf},
			certConfig: []ExtensionConfig{ext},
			result:     []ExtensionConfig{ext},
		}, {
			//different ones with the same oid should be replaced
			profile:    []ProfileExtension{extOverride},
			certConfig: []ExtensionConfig{extDifferentContent},
			result:     []ExtensionConfig{extDifferentContent},
		}, {
			//except when they are not to be overwritten
			//then they are added with profile extensions at the top
			profile:    []ProfileExtension{extProf},
			certConfig: []ExtensionConfig{extDifferentContent},
			result:     []ExtensionConfig{ext, extDifferentContent},
		}, {
			//leave other extensions unaffected
			profile:    []ProfileExtension{extProf},
			certConfig: []ExtensionConfig{ext2},
			result:     []ExtensionConfig{ext, ext2},
		}, {
			//leave other extensions unaffected on override
			profile:    []ProfileExtension{extProf, ext2Override},
			certConfig: []ExtensionConfig{ext2},
			result:     []ExtensionConfig{ext, ext2},
		}, {
			//accept override even if it does not immediately follow
			profile:    []ProfileExtension{extOverride},
			certConfig: []ExtensionConfig{ext2, ext},
			result:     []ExtensionConfig{ext2, ext},
		}, {
			//accept override even if order is different
			profile:    []ProfileExtension{extOverride, ext2Override},
			certConfig: []ExtensionConfig{ext2, ext},
			result:     []ExtensionConfig{ext2, ext},
		}, {
			//handle multiples part
			profile:    []ProfileExtension{extProf, extProf, extProf},
			certConfig: []ExtensionConfig{ext},
			result:     []ExtensionConfig{ext, ext, ext},
		}, {
			//handle optionals I
			profile:    []ProfileExtension{extOptional},
			certConfig: []ExtensionConfig{},
			result:     []ExtensionConfig{},
		},
		{
			//handle optionals III
			profile:    []ProfileExtension{extOptional},
			certConfig: []ExtensionConfig{ext},
			result:     []ExtensionConfig{ext},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("merge-extensions-#%v", i), func(t *testing.T) {
			profile := CertificateProfile{Extensions: test.profile}
			certConfig := CertificateContent{Extensions: test.certConfig}
			merged := CertificateContent{Extensions: test.result}

			got, err := Merge(profile, certConfig)
			if err != nil {
				t.Fatal(err.Error())
			}

			if !reflect.DeepEqual(merged.Extensions, got.Extensions) {
				t.Fatalf("expected merged config to look like %v instead of %v", merged.Extensions, got.Extensions)
			}
		})
	}
}

func TestConstantBuilder(t *testing.T) {
	ext := pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 2, 3},
		Critical: true,
		Value:    []byte{6, 7, 8, 9},
	}
	b := ConstantBuilder{
		Extension: ext,
	}

	extGot, _ := b.Compile(nil)
	if !reflect.DeepEqual(ext, *extGot) {
		t.Fatal("extensions are different")
	}
}

func TestParseRdnSequence(t *testing.T) {
	type testVector struct {
		string
		compareString string
	}
	tests := []testVector{
		{"CN=Test", ""},
		{"CN=Test,O=TestO,OU=TestOU,CN=TestCN,SERIALNUMBER=123," +
			"L=TestL,ST=TestST,STREET=TestSTREET,POSTALCODE=TestPOSTALCODE", ""},
		{"1.2.3.4=TestOid", "1.2.3.4=#1307546573744f6964"},
		{`CN=Test\,Comma\,Escape`, `CN=Test\\\,Comma\\\,Escape`},
		{`CN="`, `CN=\"`},
		{`CN=<`, `CN=\<`},
		{`CN=>`, `CN=\>`},
		{`CN=+`, `CN=\+`},
		{`CN=\`, `CN=\\`},
		{`CN=;`, `CN=\;`},
	}

	for _, test := range tests {
		t.Run(test.string, func(t *testing.T) {
			rdnObj, err := ParseRDNSequence(test.string)
			if err != nil {
				t.Fatal(err.Error())
			}

			expected := test.string
			if len(test.compareString) > 0 {
				expected = test.compareString
			}

			got := rdnObj.String()
			if got != expected {
				t.Fatalf("expected '%s', got '%s'", expected, got)
			}
		})
	}
}

func TestCertContentHashSum(t *testing.T) {
	subject, err := ParseRDNSequence("CN=Test")
	if err != nil {
		t.Fatal(err.Error())
	}

	cert := CertificateContent{
		Subject:    subject,
		Extensions: []ExtensionConfig{testExt{ObjectIdentifier: asn1.ObjectIdentifier{5, 6, 7, 8}}},
	}

	// hash should be the same for the same content
	hash1, err := cert.HashSum()
	if err != nil {
		t.Fatal(err.Error())
	}
	hash2, err := cert.HashSum()
	if err != nil {
		t.Fatal(err.Error())
	}
	if !reflect.DeepEqual(hash1, hash2) {
		t.Fatal("hashes are different")
	}

	// hash should be different for different subject
	cert.Subject, err = ParseRDNSequence("CN=Test2")
	if err != nil {
		t.Fatal(err.Error())
	}
	hash3, err := cert.HashSum()
	if err != nil {
		t.Fatal(err.Error())
	}
	if reflect.DeepEqual(hash1, hash3) {
		t.Fatal("hashes are the same")
	}

	// hash should be different for different extension
	cert.Extensions = []ExtensionConfig{testExt{ObjectIdentifier: asn1.ObjectIdentifier{5, 6, 7, 9}}}
	hash4, err := cert.HashSum()
	if err != nil {
		t.Fatal(err.Error())
	}
	if reflect.DeepEqual(hash3, hash4) {
		t.Fatal("hashes are the same")
	}
}
