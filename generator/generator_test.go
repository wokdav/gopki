package generator

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/wokdav/gopki/generator/config"
	v1 "github.com/wokdav/gopki/generator/config/v1"
)

var testduration time.Duration

func init() {
	var err error
	testduration, err = time.ParseDuration("42000h")
	if err != nil {
		panic("tests are broken")
	}
}

var dummySubject pkix.RDNSequence = pkix.RDNSequence{
	pkix.RelativeDistinguishedNameSET{
		pkix.AttributeTypeAndValue{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
			Value: "Dummy Certificate"}},
}

func TestGenerateMinimal(t *testing.T) {
	cfg := config.CertificateContent{
		Subject: dummySubject,
	}

	ctx, err := BuildCertBody(cfg, nil, nil)
	if err != nil {
		t.Fatal(err.Error())
	}

	//remember: string representations are reversed
	expected := "CN=Dummy Certificate"
	if ctx.TbsCertificate.Subject.String() != expected {
		t.Fatalf("unexpected subject name. expected '%v', got '%v'",
			expected, ctx.TbsCertificate.Subject.String())
	}
}

func TestGenerateExtensions(t *testing.T) {
	cfg := config.CertificateContent{
		Subject: dummySubject,
		Extensions: []config.ExtensionConfig{
			v1.SubjectKeyIdentifier{
				Content: "hash",
			},
		},
	}

	ctx, err := BuildCertBody(cfg, nil, nil)
	if err != nil {
		t.Fatal(err.Error())
	}

	if len(ctx.Extensions) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(ctx.Extensions))
	}
}

func TestGenerateExtensionsFail(t *testing.T) {
	cfg := config.CertificateContent{
		Subject: dummySubject,
		Extensions: []config.ExtensionConfig{
			v1.SubjectKeyIdentifier{
				Content: "😂👌",
			},
		},
	}

	_, err := BuildCertBody(cfg, nil, nil)
	if err == nil {
		t.Fatal("this should fail")
	}
}

func TestGenerateEmpty(t *testing.T) {
	_, err := BuildCertBody(config.CertificateContent{}, nil, nil)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestGenerateFail(t *testing.T) {
	c := config.CertificateContent{}
	c.KeyAlgorithm = 0xACDC
	_, err := BuildCertBody(c, nil, nil)
	if err == nil {
		t.Fatalf("this should fail")
	}
}
