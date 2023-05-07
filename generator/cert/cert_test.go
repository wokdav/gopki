package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"regexp"
	"testing"
	"time"
)

var testduration time.Duration

func init() {
	var err error
	testduration, err = time.ParseDuration("42000h")
	if err != nil {
		panic("tests are broken")
	}
}

func getQuickCert() *CertificateContext {
	out := NewCertificateContext(nil, nil, time.Now(), time.Now().Add(testduration))
	out.GeneratePrivateKey(P224)
	out.SetIssuer(AsIssuer(*out))

	return out
}

func TestNewTbsVersion3(t *testing.T) {
	if getQuickCert().TbsCertificate.Version != 2 {
		t.Fatal("expected to generate only x509v3 certificates")
	}
}

func TestNewTbsSerialNumberNotNull(t *testing.T) {
	if getQuickCert().TbsCertificate.SerialNumber == nil {
		t.Fatal("expected serial number not to be nil")
	}
}

func TestNewTbsSerialNumberDifferent(t *testing.T) {
	if getQuickCert().TbsCertificate.SerialNumber.Cmp(getQuickCert().TbsCertificate.SerialNumber) == 0 {
		t.Fatal("serial numbers shall be different every time")
	}
}

func TestNewTbsIssuerNotNull(t *testing.T) {
	if len(getQuickCert().TbsCertificate.Issuer) == 0 {
		t.Fatal("expected issuer to not be empty")
	}
}

func TestNewTbsEffectiveDateNotNull(t *testing.T) {
	grace, _ := time.ParseDuration("-1h")
	tbs := getQuickCert().TbsCertificate
	if tbs.Validity.NotBefore.Before(
		time.Now().Add(grace)) {
		t.Fatalf("expected effective date to begin now minus an hour at most, instead of way earlier (%v)", tbs.Validity.NotBefore)
	}
}

func TestNewTbsExpiryGreaterThanEffective(t *testing.T) {
	tbs := getQuickCert().TbsCertificate
	if !tbs.Validity.NotBefore.Before(tbs.Validity.NotAfter) {
		t.Fatalf("expected effective date (%v) to be earlier than the expiry date (%v)", tbs.Validity.NotBefore, tbs.Validity.NotAfter)
	}
}

func TestNewTbsValidityIsUTC(t *testing.T) {
	tbs := getQuickCert().TbsCertificate
	if tbs.Validity.NotBefore.Location() != time.UTC ||
		tbs.Validity.NotAfter.Location() != time.UTC {
		t.Fatalf("validity must be set in UTC time")
	}
}

func TestNewTbsSubjectNotNull(t *testing.T) {
	if len(getQuickCert().TbsCertificate.Subject) == 0 {
		t.Fatal("expected subject to not be empty")
	}
}

func TestNewTbsKeyOidNotEmpty(t *testing.T) {
	if len(getQuickCert().TbsCertificate.PublicKey.Algorithm.Algorithm) == 0 {
		t.Fatal("expected public key alg oid to not be empty")
	}
}

func TestNewTbsKeyBytesNotEmpty(t *testing.T) {
	if len(getQuickCert().TbsCertificate.PublicKey.PublicKey.Bytes) == 0 {
		t.Fatal("expected public key alg oid to not be empty")
	}
}

func TestNewTbsPrivateKeyNotEmpty(t *testing.T) {
	if getQuickCert().PrivateKey == nil {
		t.Fatal("expected private key to not be nil")
	}
}

func TestSignAlgNotNil(t *testing.T) {
	ctx := getQuickCert()
	cert, err := ctx.Sign(0xDEAF)
	if err == nil {
		t.Fatalf("expected certificate generation to fail")
	}

	if cert != nil {
		t.Fatalf("expected no certificate to be put out")
	}
}

func TestReadMarshalledIntoInternalLib(t *testing.T) {
	ctx := getQuickCert()
	cert, err := ctx.Sign(ECDSAwithSHA256)
	if err != nil {
		t.Fatalf(err.Error())
	}

	certBytes, err := asn1.Marshal(*cert)
	if err != nil {
		t.Fatalf(err.Error())
	}

	_, err = x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestVerifyMarshalledCertificate(t *testing.T) {
	ctx := getQuickCert()
	cert, _ := ctx.Sign(ECDSAwithSHA256)
	certBytes, _ := asn1.Marshal(*cert)
	certObj, _ := x509.ParseCertificate(certBytes)

	err := certObj.CheckSignature(certObj.SignatureAlgorithm, certObj.RawTBSCertificate, certObj.Signature)
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestUnknownKeyAlg(t *testing.T) {
	ctx := &CertificateContext{}
	err := ctx.GeneratePrivateKey(0xBEEF)

	if err == nil {
		t.Fatalf("this should fail")
	}
}

func TestUnknownIncompatibleECKeySign(t *testing.T) {
	ctx := NewCertificateContext(defaultSubject, nil, time.Now(), time.Now().Add(testduration))
	err := ctx.GeneratePrivateKey(P224)
	if err != nil {
		t.Fatalf("can't generate key: %v", err)
	}

	_, err = ctx.Sign(RSAwithSHA1)
	if err == nil {
		t.Fatalf("this should fail")
	}
}

func TestUnknownIncompatibleRSAKeySign(t *testing.T) {
	ctx := NewCertificateContext(defaultSubject, nil, time.Now(), time.Now().Add(testduration))
	err := ctx.GeneratePrivateKey(RSA1024)
	if err != nil {
		t.Fatalf("can't generate certificate body: %v", err)
	}

	_, err = ctx.Sign(ECDSAwithSHA1)
	if err == nil {
		t.Fatalf("this should fail")
	}
}

func TestAlgorithms(t *testing.T) {
	//run n+m tests instead of n*m tests to speed things up
	type test struct {
		keyAlg  KeyAlgorithm
		sigAlg  SignatureAlgorithm
		isShort bool
	}

	tests := []test{
		{RSA1024, RSAwithSHA1, true},
		{RSA2048, RSAwithSHA256, true},
		{RSA4096, RSAwithSHA384, false},
		{RSA8192, RSAwithSHA512, false},
		{P224, ECDSAwithSHA1, true},
		{P256, ECDSAwithSHA256, true},
		{P384, ECDSAwithSHA384, true},
		{P521, ECDSAwithSHA512, true},
		{BrainpoolP256r1, ECDSAwithSHA1, true},
		{BrainpoolP384r1, ECDSAwithSHA1, true},
		{BrainpoolP512r1, ECDSAwithSHA1, true},
		{BrainpoolP256t1, ECDSAwithSHA1, true},
		{BrainpoolP384t1, ECDSAwithSHA1, true},
		{BrainpoolP512t1, ECDSAwithSHA1, true},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%v+%v", test.keyAlg, test.sigAlg), func(t *testing.T) {
			if testing.Short() && !test.isShort {
				t.Skip()
			}
			ctx := NewCertificateContext(defaultSubject, nil, time.Now(), time.Now().Add(testduration))
			err := ctx.GeneratePrivateKey(test.keyAlg)
			if err != nil {
				t.Errorf("can't create certificate body for %v+%v", test.keyAlg, test.sigAlg)
			}
			if (ctx == nil) == (err == nil) {
				t.Errorf("error is nil and tbs is nil or vice versa")
			}

			ctx.SetIssuer(AsIssuer(*ctx))
			//test signing for algorithms as well
			cert, err := ctx.Sign(test.sigAlg)
			if err != nil {
				t.Errorf("can't create signed certificate for %v+%v", test.keyAlg, test.sigAlg)
			}
			if (cert == nil) == (err == nil) {
				t.Errorf("error is nil and tbs is nil or vice versa")
			}
		})
	}
}

func TestOidFromString(t *testing.T) {
	type test struct {
		string
		expectOid   asn1.ObjectIdentifier
		expectError bool
	}

	suite := []test{
		{"1.2.3.4.5", asn1.ObjectIdentifier{1, 2, 3, 4, 5}, false},
		{"1", asn1.ObjectIdentifier{1}, false},
		{"", asn1.ObjectIdentifier{}, false},
		{"1,2,3,4,5", nil, true},
		{"1. 2.", nil, true},
		{".1", nil, true},
		{"1.", nil, true},
		{".1.", nil, true},
		{"1.garbage.2", nil, true},
	}

	for i, testcase := range suite {
		oid, err := OidFromString(testcase.string)
		if (err == nil) == testcase.expectError {
			t.Errorf("test %d: unexpected error value ('%v')", i, err)
		}

		if (testcase.expectOid == nil) != (oid == nil) ||
			!testcase.expectOid.Equal(oid) {
			t.Errorf("test %d: expected oid '%#v' differs from received oid '%#v'", i, testcase.expectOid, oid)
		}
	}
}

func TestCertPemFormat(t *testing.T) {
	ctx := getQuickCert()

	cer, err := ctx.Sign(ECDSAwithSHA1)
	if err != nil {
		t.Fatal(err.Error())
	}

	bb := bytes.Buffer{}
	err = cer.WritePem(&bb)
	if err != nil {
		t.Fatal(err.Error())
	}

	validCertPem := regexp.MustCompile(`^-----BEGIN CERTIFICATE-----\n([a-zA-Z0-9+\/=]{64}\n)+[a-zA-Z0-9+\/=]+\n-----END CERTIFICATE-----(\n)?$`)
	if !validCertPem.Match(bb.Bytes()) {
		t.Log(bb.String())
		t.Fatalf("certificate pem does not match the pem format")
	}
}

func TestKeyPemFormat(t *testing.T) {
	ctx := getQuickCert()

	bb := bytes.Buffer{}
	err := WritePrivateKeyToPem(ctx.PrivateKey, &bb)
	if err != nil {
		t.Fatal(err.Error())
	}

	validCertPem := regexp.MustCompile(`^-----BEGIN PRIVATE KEY-----\n([a-zA-Z0-9+\/=]{64}\n)+[a-zA-Z0-9+\/=]+\n-----END PRIVATE KEY-----(\n)?$`)
	if !validCertPem.Match(bb.Bytes()) {
		t.Log(bb.String())
		t.Fatalf("key pem does not match the pem format")
	}
}

type nilwriter int

func (ni nilwriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func TestIllegalKeyPemFail(t *testing.T) {
	brokenKey := any("😂👌")

	err := WritePrivateKeyToPem(brokenKey, nilwriter(0))
	if err == nil {
		t.Fatal("this should fail")
	}
}

var testrootcert string = `-----BEGIN CERTIFICATE-----
MIIBFDCBvKADAgECAgJOVTAKBggqhkjOPQQDAjAUMRIwEAYDVQQDEwlUZXN0IFJv
b3QwHhcNMjIxMjEzMTg1MDU0WhcNMjcxMjEzMTg1MDU0WjAUMRIwEAYDVQQDEwlU
ZXN0IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNtscTl0w3Yrz1eLFB
AWX9v0oXv5Z1S7ye0vWoPHeDhH3vXSXg89kn9aCEvetSDi//NyxMQ/jRRUeXLio/
LsmgMAoGCCqGSM49BAMCA0cAMEQCIE3U8Bz6zfmVoRUcGa/58jErqDc9GrzDe3DN
EVViQ+boAiBJ30DGDE9O2FfsLxk7pzeucfXoUV1NLDURlCP0bxaPFA==
-----END CERTIFICATE-----
`

var testrootkey string = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxBZoTr/R7fEf9hRL
s+lkvFGbsJmVv8VNRL5YZOvUzbmhRANCAASNtscTl0w3Yrz1eLFBAWX9v0oXv5Z1
S7ye0vWoPHeDhH3vXSXg89kn9aCEvetSDi//NyxMQ/jRRUeXLio/Lsmg
-----END PRIVATE KEY-----
`

func TestAsIssuer(t *testing.T) {
	subject := defaultSubject
	ctx := NewCertificateContext(
		subject, nil, time.Now(), time.Now().AddDate(1, 0, 0))

	err := ctx.GeneratePrivateKey(P224)
	if err != nil {
		t.Fatal(err.Error())
	}

	issuerCtx := AsIssuer(*ctx)
	if issuerCtx.IssuerDn.String() != ctx.Subject.String() {
		t.Fatalf("differnt issuer dn - expected '%s', got '%x'",
			ctx.Subject.String(), issuerCtx.IssuerDn.String())
	}

	subKey := ctx.PrivateKey.(*ecdsa.PrivateKey)
	issKey := issuerCtx.PrivateKey.(*ecdsa.PrivateKey)
	if !subKey.Equal(issKey) {
		t.Fatal("private keys are different")
	}

	if !bytes.Equal(issuerCtx.PublicKeyRaw, ctx.PublicKey.PublicKey.Bytes) {
		t.Fatal("raw public keys are different")
	}
}

var testrequest string = `-----BEGIN CERTIFICATE REQUEST-----
MIIBczCB3QIBADAPMQ0wCwYDVQQDEwR0ZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQC5PbxMGVJ8aLF9lq/EvGObXTRMB7ieiZL9N+DJZg1n/ECCnZLIvYrr
ZmmDV7YZsClgxKGfjJB0RQFFyZElFM9EfHEs8NJdidDKCRdIhDXQWRyhXKevHvdm
CQNKzUeoxvdHpU/uscSkw6BgUzPyLyTx9A6ye2ix94z8Y9hGOBO2DQIDAQABoCUw
IwYJKoZIhvcNAQkOMRYwFDAIBgIqAwQCBQAwCAYCKgMEAgUAMA0GCSqGSIb3DQEB
CwUAA4GBAHROEsE7URk1knXmBnQtIHwoq663vlMcX3Hes58pUy020rWP8QkocA+X
VF18/phg3p5ILlS4fcbbP2bEeV0pePo2k00FDPsJEKCBAX2LKxbU7Vp2OuV2HM2+
VLOVx0i+/Q7fikp3hbN1JwuMTU0v2KL/IKoUcZc02+5xiYrnOIt5
-----END CERTIFICATE REQUEST-----`

func TestReadPem(t *testing.T) {
	t.Run("cert", func(t *testing.T) {
		out, err := ReadPem([]byte(testrootcert))
		if err != nil {
			t.Fatal(err.Error())
		}

		if out.Certificate == nil {
			t.Fatal("this should return a certificate")
		}
	})

	t.Run("key", func(t *testing.T) {
		out, err := ReadPem([]byte(testrootkey))
		if err != nil {
			t.Fatal(err.Error())
		}

		if out.PrivateKey == nil {
			t.Fatal("this should return a key")
		}
	})

	t.Run("request", func(t *testing.T) {
		out, err := ReadPem([]byte(testrequest))
		if err != nil {
			t.Fatal(err.Error())
		}

		if out.Request == nil {
			t.Fatal("this should return a request")
		}
	})
}

func TestReadPemBroken(t *testing.T) {
	t.Run("cert", func(t *testing.T) {
		brokencert := "-----+-*8+-8+*87+*8+954+6468" + testrootcert
		out, err := ReadPem([]byte(brokencert))
		if err == nil {
			t.Fatal("this should fail")
		}

		if out.Certificate != nil {
			t.Fatal("this should not return a certificate")
		}
	})

	t.Run("key", func(t *testing.T) {
		brokenkey := "-----+-*8+-8+*87+*8+954+6468" + testrootkey
		out, err := ReadPem([]byte(brokenkey))
		if err == nil {
			t.Fatal("this should fail")
		}

		if out.PrivateKey != nil {
			t.Fatal("this should not return a private key")
		}
	})

	t.Run("request", func(t *testing.T) {
		brokenreq := "-----+-*8+-8+*87+*8+954+6468" + testrequest
		out, err := ReadPem([]byte(brokenreq))
		if err == nil {
			t.Fatal("this should fail")
		}

		if out.Request != nil {
			t.Fatal("this should not return a request")
		}
	})
}

func TestReadAllPemTypes(t *testing.T) {
	input := testrootcert + testrootkey + testrequest

	out, err := ReadPem([]byte(input))

	if err != nil {
		t.Fatal(err.Error())
	}

	if out.Certificate == nil {
		t.Fatal("this should return a certificate")
	}

	if out.PrivateKey == nil {
		t.Fatal("this should return a key")
	}

	if out.Request == nil {
		t.Fatal("this should return a request")
	}
}
