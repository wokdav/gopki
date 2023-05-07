package generator

import (
	"strings"
	"testing"
	"time"

	"github.com/wokdav/gopki/generator/cert"
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

func contextFromConfig(s string) (*cert.CertificateContext, error) {
	cfg, err := config.ParseConfig(strings.NewReader(s))
	if err != nil {
		return nil, err
	}

	certCfg := cfg.(*config.CertificateContent)

	ctx, err := BuildCertBody(*certCfg, nil, nil)
	if err != nil {
		return nil, err
	}

	return ctx, nil
}

func TestGenerateMinimal(t *testing.T) {
	cert, err := contextFromConfig("version: 1\nsubject: C=DE, CN=MyCertificate")
	if err != nil || cert == nil {
		t.Fatalf("error happened (%v) or cert is null", err)
	}

	//remember: string representations are reversed
	expected := "C=DE,CN=MyCertificate"
	if cert.TbsCertificate.Subject.String() != expected {
		t.Fatalf("unexpected subject name. expected '%v', got '%v'",
			expected, cert.TbsCertificate.Subject.String())
	}
}

func TestGenerateExtensions(t *testing.T) {
	cert, err := contextFromConfig("version: 1\nsubject: CN=Test\nextensions:\n  - subjectKeyIdentifier:\n      content: hash\n")
	if err != nil || cert == nil {
		t.Fatalf("error happened (%v) or cert is null", err)
	}
}

func TestGenerateExtensionsFail(t *testing.T) {
	cfg, err := config.ParseConfig(strings.NewReader(
		"version: 1\nsubject: CN=Test\nextensions:\n  - subjectKeyIdentifier:\n      content: hash\n",
	))
	if err != nil {
		t.Fatal(err.Error())
	}

	certCfg, ok := cfg.(*config.CertificateContent)
	if !ok {
		t.Fatal("cannot parse data as certificate")
	}

	subjkeyid := certCfg.Extensions[0].(v1.SubjectKeyIdentifier)
	subjkeyid.Raw = "!binary:AQIDBA=="
	certCfg.Extensions[0] = subjkeyid

	_, err = BuildCertBody(*certCfg, nil, nil)
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
