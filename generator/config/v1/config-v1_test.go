package v1

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"gopki/generator"
	"gopki/generator/cert"
	"gopki/generator/config"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ghodss/yaml"
)

func fromDate(y int, m int, d int) *time.Time {
	date := time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.Local)
	return &date
}

func TestMain(m *testing.M) {
	// include init function in test coverage
	os.Exit(m.Run())
}

func TestInit(t *testing.T) {
	if durationRx == nil {
		t.Fatalf("durationRx is not initialized")
	}
}

func TestParseRdn(t *testing.T) {
	type testVector struct {
		test      string
		expectNil bool
	}
	tests := map[string]testVector{
		"all": {
			"C=UK,O=testorg,OU=testunit,CN=commonname,SERIALNUMBER=123,L=city,ST=state,STREET=street,POSTALCODE=457",
			false,
		},
		"empty":   {"", true},
		"unknown": {"MYKEY=value", true},
		"ws1":     {"CN=my name", false},
		"ws2":     {"CN=my        name", false},
		"ws3":     {"    CN    =    my name   ", false},
		"ws4":     {"    CN    =    my name   ,   L   = looo  ca  ti o n    ", false},
	}

	for name, vector := range tests {
		t.Run(name, func(t *testing.T) {
			rdn, err := config.ParseRDNSequence(vector.test)
			if (rdn == nil) != vector.expectNil {
				t.Errorf("Test '%v': result does not match expectNil (expected: %v)", name, vector.expectNil)
			}
			if (rdn == nil) == (err == nil) {
				t.Errorf("test '%v': expect err to be nil, when return is not nil and vice versa.", name)
			}
		})
	}
}

func TestAlias(t *testing.T) {
	tests := map[string]bool{
		//testvector, expectSuccess
		"myAlias": true,
		"looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong": true,
		"😂👌": true,
		"1":  true,
		"":   false,
		"$":  false,
	}

	conf := V1Configurator{}
	for key := range tests {
		t.Run(fmt.Sprintf("Testing '%v'", key), func(t *testing.T) {
			obj, err := conf.ParseConfiguration(fmt.Sprintf(
				`{"version":1,"subject":"CN=testSubject","alias":"%s"}`, key),
			)
			if (err == nil) != tests[key] {
				t.Fatalf("unexpected error value: %v", err)
			}

			if err != nil {
				return
			}

			cert, ok := obj.(*config.CertificateContent)
			if !ok {
				t.Fatal("expected certificate type")
			}

			if obj != nil && cert.Alias != key {
				t.Fatalf("expected alias to be '%v', but got '%v'", key, cert.Alias)
			}
		})
	}
}

func TestTimespan(t *testing.T) {
	//input struct and the expected return values of the functions
	type timeTest struct {
		CertValidity
		t1       *time.Time
		t2       *time.Time
		errorNil bool
	}

	tests := []timeTest{
		{CertValidity{}, nil, nil, false},                    //no time given should fail
		{CertValidity{From: "2022-01-01"}, nil, nil, false},  //only from time given should fail
		{CertValidity{Until: "2022-01-01"}, nil, nil, false}, //from missing should fail
		{CertValidity{Duration: "1y"}, nil, nil, false},
		{CertValidity{Until: "2022-01-01", Duration: "1y"}, nil, nil, false},
		{CertValidity{From: "2022-01-01", Until: "2023-01-01", Duration: "1y"}, nil, nil, false}, //both end values given should fail
		{CertValidity{From: "2022-01-01", Until: "2023-01-01", Duration: "2y"}, nil, nil, false}, //especially when they are in conflict
		{CertValidity{From: "2022-01-1", Duration: "1y"}, nil, nil, false},                       //from date malformed
		{CertValidity{From: "2022-1-01", Duration: "1y"}, nil, nil, false},
		{CertValidity{From: "22-01-01", Duration: "1y"}, nil, nil, false},
		{CertValidity{From: "20220101", Duration: "1y"}, nil, nil, false},
		{CertValidity{From: "2022-01-01", Duration: "1yr"}, nil, nil, false}, //duration malformed
		{CertValidity{From: "2022-01-01", Duration: "1month"}, nil, nil, false},
		{CertValidity{From: "2022-01-01", Duration: "1day"}, nil, nil, false},
		{CertValidity{From: "2022-01-01", Duration: "1d1m1y"}, nil, nil, false},
		{CertValidity{From: "2022-01-01", Until: "2023-01-1"}, nil, nil, false}, //until malformed
		{CertValidity{From: "2022-01-01", Until: "2023-1-01"}, nil, nil, false},
		{CertValidity{From: "2022-01-01", Until: "23-1-01"}, nil, nil, false},
		{CertValidity{From: "2022-01-01", Until: "20230101"}, nil, nil, false},

		//good cases
		{CertValidity{From: "2022-01-01", Until: "2023-01-01"},
			fromDate(2022, 1, 1), fromDate(2023, 1, 1), true},
		{CertValidity{From: "2022-01-01", Duration: "1y"},
			fromDate(2022, 1, 1), fromDate(2023, 1, 1), true},
		{CertValidity{From: "2022-01-01", Duration: "1m"},
			fromDate(2022, 1, 1), fromDate(2022, 2, 1), true},
		{CertValidity{From: "2022-01-01", Duration: "1d"},
			fromDate(2022, 1, 1), fromDate(2022, 1, 2), true},
		{CertValidity{From: "2022-01-01", Duration: "1y1m1d"},
			fromDate(2022, 1, 1), fromDate(2022, 1, 2), true},
		{CertValidity{From: "2022-01-01", Duration: "15y4m20d"},
			fromDate(2022, 1, 1), fromDate(2037, 5, 21), true},
	}

	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t1, t2, err := test.CertValidity.extractTimespan()

			var tmpfail bool //re-use same error message

			tmpfail = false
			if (t1 == nil) != (test.t1 == nil) {
				tmpfail = true
			} else if t1 != nil && !t1.Equal(*test.t1) {
				tmpfail = true
			}
			if tmpfail {
				t.Errorf(`#%v: "From"-time different than expected. Expected "%v", got "%v"`, i, test.t1, t1)
			}

			tmpfail = false
			if (t2 == nil) != (test.t2 == nil) {
				tmpfail = true
			} else if t1 != nil && !t1.Equal(*test.t1) {
				tmpfail = true
			}

			if tmpfail {
				t.Errorf(`#%v: "To"-time different than expected. Expected "%v", got "%v"`, i, test.t2, t2)
			}

			if (err == nil) != test.errorNil {
				t.Errorf("#%v: Error differs from expectation. Expected: %v, got %v", i, test.errorNil, err == nil)
			}
		})
	}
}

func TestCertificateSchemaParsed(t *testing.T) {
	d := json.NewDecoder(strings.NewReader(certificateConfigSchemaTests))
	var ts certificateSchemaTestSuite
	err := d.Decode(&ts)
	if err != nil {
		t.Fatalf("can't decode testsuite: %v", err)
	}

	conf := V1Configurator{}
	for _, testCase := range ts {
		t.Run(testCase.Name, func(t *testing.T) {
			sb := strings.Builder{}
			enc := json.NewEncoder(&sb)
			err = enc.Encode(testCase.Test)
			if err != nil {
				t.Fatalf("can't re-encode test vector")
			}

			_, err := conf.ParseConfiguration(sb.String())
			if (err == nil) != testCase.ExpectSuccess {
				t.Fatalf("error='%v' although expectSuccess='%v'", err, testCase.ExpectSuccess)
			}
		})
	}
}

func TestBugYamlTruthValues(t *testing.T) {
	//the last yaml lib I used was api compatible, but only recognised
	//'true' and 'false' as boolean, so this test makes sure, other truth
	//values work as well
	truthValues := map[string]bool{
		"true":  true,
		"false": false,
		"yes":   true,
		"no":    false,
		"on":    true,
		"off":   false,
		"y":     true,
		"n":     false,
		"Y":     true,
		"N":     false,
	}

	for test, expectedBoolean := range truthValues {
		t.Run(fmt.Sprintf("yaml truth value '%s'", test), func(t *testing.T) {
			var val bool
			err := yaml.Unmarshal([]byte(test), &val)
			if err != nil {
				t.Fatal(err.Error())
			}

			if val != expectedBoolean {
				t.Errorf("expected parsed value to be '%v' instead of '%v'", expectedBoolean, val)
			}
		})
	}
}

func TestParseExampleProfile(t *testing.T) {
	conf := V1Configurator{}
	cfg, err := conf.ParseConfiguration(profileExample)
	if err != nil {
		t.Fatal(err.Error())
	}

	_, ok := cfg.(*config.CertificateProfile)
	if !ok {
		t.Fatalf("expected to receive a CertificateProfile type")
	}
}

func TestParseExampleCertificate(t *testing.T) {
	conf := V1Configurator{}
	cer, err := conf.ParseConfiguration(certificateExample)
	if err != nil {
		t.Fatal(err.Error())
	}

	_, ok := cer.(*config.CertificateContent)
	if !ok {
		t.Fatalf("expected to receive a CertificateContent type")
	}
}

func TestGenerateExample(t *testing.T) {
	//parse both configurations
	conf := V1Configurator{}
	cfg, err := conf.ParseConfiguration(profileExample)
	if err != nil {
		t.Fatal(err.Error())
	}

	cer, err := conf.ParseConfiguration(certificateExample)
	if err != nil {
		t.Fatal(err.Error())
	}

	prof, ok := cfg.(*config.CertificateProfile)
	if !ok {
		t.Fatalf("expected to receive a CertificateProfile type")
	}

	cerCfg, ok := cer.(*config.CertificateContent)
	if !ok {
		t.Fatalf("expected to receive a CertificateContent type")
	}

	//validate config against profile
	if !config.Validate(*prof, *cerCfg) {
		t.Fatalf("example certificate does not validate against example profile")
	}

	//merge extensions from profile
	cerCfg, err = config.Merge(*prof, *cerCfg)
	if err != nil {
		t.Fatal(err.Error())
	}

	//generate tbsCertificate
	ctx, err := generator.BuildCertBody(*cerCfg)
	if err != nil {
		t.Fatal(err.Error())
	}

	//self-sign certificate
	certificate, err := ctx.Sign(cert.ECDSAwithSHA256)
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Logf("%#v", certificate)
}

func TestValidateSubject(t *testing.T) {
	type testProfile struct {
		config.ProfileSubjectAttributes
		expectSuccess bool
	}

	tests := map[string]testProfile{
		"C=DE": {
			config.ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "C", Optional: false},
				},
			}, true},
		"C=DE, O=Acme, OU=Admin, CN=Cert, SERIALNUMBER=123, L=Berlin, STREET=Street1, POSTALCODE=12345": {
			config.ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []config.ProfileSubjectAttribute{
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
		"O=Missing": {
			config.ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "CN", Optional: false},
				},
			}, false},
		"O=Missing, CN=Acme": {
			config.ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "CN", Optional: false},
				},
			}, false},
		"CN=Acme, O=Missing": {
			config.ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "CN", Optional: false},
				},
			}, false},
		"CN=Acme, O=OrderCorrect": {
			config.ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "CN", Optional: false},
					{Attribute: "O", Optional: false},
				},
			}, true},
		"CN=Acme, O=OrderWrong": {
			config.ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "O", Optional: false},
					{Attribute: "CN", Optional: false},
				},
			}, false},
		"CN=Optional": {
			config.ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "CN", Optional: true},
				},
			}, true},
		"O=NotOptional": {
			config.ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "CN", Optional: false},
					{Attribute: "O", Optional: true},
				},
			}, false},
		"O=NotOptional2": {
			config.ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "O", Optional: false},
					{Attribute: "CN", Optional: true},
				},
			}, true},
		"O=Optional, CN=Ordering": {
			config.ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "CN", Optional: true},
					{Attribute: "O", Optional: true},
				},
			}, false},
		"CN=AllowOther": {
			config.ProfileSubjectAttributes{
				AllowOther: true,
				Attributes: []config.ProfileSubjectAttribute{},
			}, true},
		"CN=AllowOtherOptional": {
			config.ProfileSubjectAttributes{
				AllowOther: true,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "O", Optional: true},
				},
			}, true},
		"CN=AllowOtherMandatory, O=Back": {
			config.ProfileSubjectAttributes{
				AllowOther: true,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "O", Optional: false},
				},
			}, true},
		"O=Front, CN=AllowOtherMandatory": {
			config.ProfileSubjectAttributes{
				AllowOther: true,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "O", Optional: false},
				},
			}, true},
		"O=Wrong, CN=Ordering, L=Allowed": {
			config.ProfileSubjectAttributes{
				AllowOther: true,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "CN", Optional: false},
					{Attribute: "O", Optional: false},
				},
			}, true},
		"O=Wrong, CN=Ordering, L=Optional": {
			config.ProfileSubjectAttributes{
				AllowOther: true,
				Attributes: []config.ProfileSubjectAttribute{
					{Attribute: "CN", Optional: true},
					{Attribute: "O", Optional: true},
				},
			}, true},
		"O=Empty": {
			config.ProfileSubjectAttributes{
				AllowOther: false,
				Attributes: []config.ProfileSubjectAttribute{},
			}, false},
	}

	for rdnString, test := range tests {
		t.Run(rdnString, func(t *testing.T) {
			rdn, err := config.ParseRDNSequence(rdnString)
			if err != nil {
				t.Fatal(err.Error())
			}
			if config.Validate(config.CertificateProfile{SubjectAttributes: test.ProfileSubjectAttributes},
				config.CertificateContent{Subject: rdn}) != test.expectSuccess {
				t.Fatalf("expect return value to be %v, but it's the opposite", test.expectSuccess)
			}
		})
	}
}

func TestParseAnyExtension(t *testing.T) {
	type testVector struct {
		test   AnyExtension
		expect config.ExtensionConfig
	}

	extprof := config.ExtensionProfile{
		Optional: true, Override: true,
	}

	subjKeyId := AnyExtension{
		SubjectKeyIdentifier: &SubjectKeyIdentifier{
			Critical:         true,
			ExtensionProfile: extprof,
			Content:          "hash",
		},
	}

	keyUsage := AnyExtension{
		KeyUsage: &KeyUsage{
			Critical:         true,
			ExtensionProfile: extprof,
			Content:          []string{"digitalSignature", "crlSign"},
		},
	}

	subjAltName := AnyExtension{
		SubjectAltName: &SubjectAltName{
			Critical:         true,
			ExtensionProfile: extprof,
			Content:          []SubjAltNameComponent{{Type: "CN", Name: "Foo"}},
		},
	}

	basicConstraints := AnyExtension{
		BasicConstraints: &BasicConstraints{
			Critical:         true,
			ExtensionProfile: extprof,
			Content:          &BasicConstraintsObj{true, 2},
		},
	}

	certPolicies := AnyExtension{
		CertPolicies: &CertPolicies{
			Critical:         true,
			ExtensionProfile: extprof,
			Content:          []CertPolicy{{Oid: "1.2.3.4"}},
		},
	}

	aia := AnyExtension{
		AuthInfoAccess: &AuthInfoAccess{
			Critical:         true,
			ExtensionProfile: extprof,
			Content:          []SingleAuthInfo{{Ocsp: "ocsp.acme.com"}},
		},
	}

	authKid := AnyExtension{
		AuthKeyId: &AuthKeyId{
			Critical:         true,
			ExtensionProfile: extprof,
			Content:          AuthKeyIdContent{Id: "hash"},
		},
	}

	extKeyUsage := AnyExtension{
		ExtKeyUsage: &ExtKeyUsage{
			Critical:         true,
			ExtensionProfile: extprof,
			Content:          []string{"serverAuth"},
		},
	}

	custom := AnyExtension{
		CustomExtension: &CustomExtension{
			Critical:         true,
			ExtensionProfile: extprof,
			Raw:              "!binary:AQIDBA==",
		},
	}

	//boolean values are true, since this is the non-default
	tests := []testVector{
		{
			test:   subjKeyId,
			expect: subjKeyId.SubjectKeyIdentifier,
		},
		{
			test:   keyUsage,
			expect: keyUsage.KeyUsage,
		},
		{
			test:   subjAltName,
			expect: subjAltName.SubjectAltName,
		},
		{
			test:   basicConstraints,
			expect: basicConstraints.BasicConstraints,
		},
		{
			test:   certPolicies,
			expect: certPolicies.CertPolicies,
		},
		{
			test:   aia,
			expect: aia.AuthInfoAccess,
		},
		{
			test:   authKid,
			expect: authKid.AuthKeyId,
		},
		{
			test:   extKeyUsage,
			expect: extKeyUsage.ExtKeyUsage,
		},
		{
			test:   custom,
			expect: custom.CustomExtension,
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-parse-anyextension-#%v", i), func(t *testing.T) {
			cfg, err := parseExtensions([]AnyExtension{test.test})

			if err != nil {
				t.Fatal(err.Error())
			}

			if !cfg[0].ContentEquals(test.expect) {
				t.Fatal("content not equal")
			}
		})
	}
}

func TestGetFileType(t *testing.T) {
	tests := map[string]CfgFileType{
		"":                    fileTypeIllegal,
		"name: myProfile":     fileTypeCertProfile,
		"subject: CN=MyCert":  fileTypeCertConfig,
		"wergbkhwlerguh: bla": fileTypeIllegal,
	}

	for test, expected := range tests {
		t.Run(test, func(t *testing.T) {
			result, err := getFileType(test)
			if (err == nil) == (result == fileTypeIllegal) {
				t.Fatalf("err == nil is %v, but result is %v; an error must be returned iff the result is fileTypeIllegal",
					err == nil, result)
			}
			if result != expected {
				t.Fatalf("expected result to be %v, but it is %v", expected, result)
			}
		})
	}
}
