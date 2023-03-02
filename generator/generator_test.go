package generator

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
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

func certFromConfig(s string) (*cert.CertificateContext, error) {
	cfg, err := config.ParseConfig(strings.NewReader(s))
	if err != nil {
		return nil, err
	}

	certCfg := cfg.(*config.CertificateContent)

	cert, err := BuildCertBody(*certCfg, nil)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func TestGenerateMinimal(t *testing.T) {
	cert, err := certFromConfig("version: 1\nsubject: C=DE, CN=MyCertificate")
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
	cert, err := certFromConfig("version: 1\nsubject: CN=Test\nextensions:\n  - subjectKeyIdentifier:\n      content: hash\n")
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

	_, err = BuildCertBody(*certCfg, nil)
	if err == nil {
		t.Fatal("this should fail")
	}
}

func TestGenerateEmpty(t *testing.T) {
	_, err := BuildCertBody(config.CertificateContent{}, nil)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestGenerateFail(t *testing.T) {
	c := config.CertificateContent{}
	c.KeyAlgorithm = 0xACDC
	_, err := BuildCertBody(c, nil)
	if err == nil {
		t.Fatalf("this should fail")
	}
}

func TestGenerateDeterministic(t *testing.T) {
	type testvector struct {
		string
		cert.SignatureAlgorithm
	}
	testConfigs := []testvector{
		{"version: 1\nalias: testAlias\nsubject: CN=Test\nkeyAlgorithm: RSA-1024\nsignatureAlgorithm: RSAwithSHA1", cert.RSAwithSHA1},
		{"version: 1\nalias: testAlias\nsubject: CN=Test\nkeyAlgorithm: P-224\nsignatureAlgorithm: ECDSAwithSHA1", cert.ECDSAwithSHA1},
	}

	for _, test := range testConfigs {
		t.Run(test.string, func(t *testing.T) {
			cert1, err := certFromConfig(test.string)
			if err != nil || cert1 == nil {
				t.Fatalf("error happened (%v) or cert is null", err)
			}

			cert2, err := certFromConfig(test.string)
			if err != nil || cert2 == nil {
				t.Fatalf("error happened (%v) or cert is null", err)
			}

			signed1, err := cert1.Sign(test.SignatureAlgorithm)
			if err != nil {
				t.Fatal(err.Error())
			}

			signed2, err := cert2.Sign(test.SignatureAlgorithm)
			if err != nil {
				t.Fatal(err.Error())
			}

			marshal1, err := asn1.Marshal(*signed1)
			if err != nil {
				t.Fatal(err.Error())
			}
			marshal2, err := asn1.Marshal(*signed2)
			if err != nil {
				t.Fatal(err.Error())
			}

			if !bytes.Equal(marshal1, marshal2) {
				t.Errorf("cert 1: %v", hex.EncodeToString(marshal1))
				t.Errorf("cert 2: %v", hex.EncodeToString(marshal2))
				t.Fatal("certificates are not equal")
			}
		})
	}

}

func TestGenerateDeterministicConstantEC(t *testing.T) {
	t.Skip("determinism does not work cross-plarform yet")
	expectB64 := "MIIBCjCBsqADAgECAgMAx2QwCQYHKoZIzj0EATAPMQ0wCwYDVQQDEwRUZXN0MB4XDTIzMDIyODIzMDAwMFoXDTI4MDIyOTIzMDAwMFowDzENMAsGA1UEAxMEVGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNDqLxEgs1SVBysZ6zqMhD7kaix9CIgEikSX418kdvRKcCelCTQI5k9IgCeozWe4cn5tZFf7RnnGR+7SA+rjJHswCQYHKoZIzj0EAQNIADBFAiBdveBWoFw7fo/TN/iqg3pXnyAti58a6uocrjnQbldg6wIhAMSviufX2wcsOlmq47/rgmE/Pno9EnIt91yOsCGtR0fA"
	expect, err := base64.StdEncoding.DecodeString(expectB64)
	if err != nil {
		t.Fatal(err.Error())
	}

	cer, err := certFromConfig("version: 1\nalias: testAlias\nsubject: CN=Test\nkeyAlgorithm: P-256\nsignatureAlgorithm: ECDSAwithSHA256")
	if err != nil {
		t.Fatalf("error happened (%v) or cert is null", err)
	}

	signed, err := cer.Sign(cert.ECDSAwithSHA1)
	if err != nil {
		t.Fatal(err.Error())
	}

	marshal, err := asn1.Marshal(*signed)
	if err != nil {
		t.Fatal(err.Error())
	}

	if !bytes.Equal(marshal, expect) {
		t.Fatal("certificates are not equal")
	}
}

func TestGenerateDeterministicConstantRSA(t *testing.T) {
	t.Skip("determinism does not work cross-plarform yet")
	expectB64 := "MIIBjzCB+6ADAgECAgMAx2QwCwYJKoZIhvcNAQELMA8xDTALBgNVBAMTBFRlc3QwHhcNMjMwMjI4MjMwMDAwWhcNMjgwMjI5MjMwMDAwWjAPMQ0wCwYDVQQDEwRUZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0TfdFqJK9NuHg/tE6BXBUSmUlr4ljQ2laQnmHuH919RMAe44vUJwuqOv7w77zHfwlAabefY4TOLzYyOrf0aBuvycUlAqV+9gpZh3UqupYkn3/DxxNtLRJfDyM8ATNIoEnu2JBQaX0VINszJz+GTHOJQv1dv9+Jz80yDRkWoFBkQIDAQABMAsGCSqGSIb3DQEBCwOBgQBVc2c+DUqooS+1Mu3kNruazmYMYBGQILnbHD0HcY8i0sRjl/SKfHv9V2c5236CKKkYNrhReSQ+pWVNzJrUJEKcLbXa3NkH+xfs9wIfXyV2rq0+UE+dZXfa46Lk9HhbCSvE9RjXU17RnmZ4zjg0HWKo4H0xAhezvql0RAYQ2niUHQ=="
	expect, err := base64.StdEncoding.DecodeString(expectB64)
	if err != nil {
		t.Fatal(err.Error())
	}

	cer, err := certFromConfig("version: 1\nalias: testAlias\nsubject: CN=Test\nkeyAlgorithm: RSA-1024\nsignatureAlgorithm: RSAwithSHA256")
	if err != nil {
		t.Fatalf("error happened (%v) or cert is null", err)
	}

	signed, err := cer.Sign(cert.RSAwithSHA256)
	if err != nil {
		t.Fatal(err.Error())
	}

	marshal, err := asn1.Marshal(*signed)
	if err != nil {
		t.Fatal(err.Error())
	}

	if !bytes.Equal(marshal, expect) {
		t.Fatal("certificates are not equal")
	}
}
