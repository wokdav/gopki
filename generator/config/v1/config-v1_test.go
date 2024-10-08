package v1

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wokdav/gopki/generator/config"
)

func fromDate(y int, m int, d int) time.Time {
	date := time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.Local)
	return date
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
		test          string
		expectSuccess bool
	}
	tests := map[string]testVector{
		"good":  {"C=DE, CN=MyCert", true},
		"good2": {"C=DE,CN=MyCert", true},
		"good3": {"C=DE ,CN=MyCert", true},
		"good4": {"C=DE , CN=MyCert", true},
		"good5": {"C=DE , CN=MyCert, O=MyOrg", true},
		"good6": {"C=DE", true},
		"good7": {"C=DE,CN=#4D7943657274", true},
		"all": {
			"C=UK,O=testorg,OU=testunit,CN=commonname,SERIALNUMBER=123,L=city,ST=state,STREET=street,POSTALCODE=457",
			true,
		},
		"ws1": {"CN=my name", true},
		"ws2": {"CN=my        name", true},
		"ws3": {"    CN    =    my name   ", true},
		"ws4": {"    CN    =    my name   ,   L   = looo  ca  ti o n    ", true},
		"ws5": {"    CN   \t = \r\n   my name   ,   L   = looo  ca  ti o n    ", true},

		"empty":   {"", false},
		"unknown": {"MYKEY=value", false},
		"bad1":    {"C=,CN=MyCert", false},
		"bad2":    {"=DE,CN=MyCert", false},
		"bad3":    {"C=D,E, CN=MyCert", false},
		"bad4":    {"C=DE,", false},
		"bad5":    {",C=DE", false},
		"bad6":    {"=", false},
		"bad7":    {",", false},
		"bad8":    {"=,=", false},
	}

	for name, vector := range tests {
		cfg := V1Configurator{}
		t.Run(name, func(t *testing.T) {
			_, err := cfg.ParseConfiguration(fmt.Sprintf(`{"version":1,"subject":"%v"}`, vector.test))

			if (err == nil) != vector.expectSuccess {
				t.Errorf("test '%v': expect success=%v, but got err=%v", name, vector.expectSuccess, err)
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
		json     CertValidity
		cfg      *config.CertificateValidity
		errorNil bool
	}

	tests := []timeTest{
		//bad cases (mainly parsing errors)
		{CertValidity{Until: "2022-01-01", Duration: "1y"}, nil, false},
		{CertValidity{From: "2022-01-01", Until: "2023-01-01", Duration: "1y"}, nil, false}, //both end values given should fail
		{CertValidity{From: "2022-01-01", Until: "2023-01-01", Duration: "2y"}, nil, false}, //especially when they are in conflict
		{CertValidity{From: "2022-01-1", Duration: "1y"}, nil, false},                       //from date malformed
		{CertValidity{From: "2022-1-01", Duration: "1y"}, nil, false},
		{CertValidity{From: "22-01-01", Duration: "1y"}, nil, false},
		{CertValidity{From: "20220101", Duration: "1y"}, nil, false},
		{CertValidity{From: "2022-01-01", Duration: "1yr"}, nil, false}, //duration malformed
		{CertValidity{From: "2022-01-01", Duration: "1month"}, nil, false},
		{CertValidity{From: "2022-01-01", Duration: "1day"}, nil, false},
		{CertValidity{From: "2022-01-01", Duration: "1d1m1y"}, nil, false},
		{CertValidity{From: "2022-01-01", Until: "2023-01-1"}, nil, false}, //until malformed
		{CertValidity{From: "2022-01-01", Until: "2023-1-01"}, nil, false},
		{CertValidity{From: "2022-01-01", Until: "23-1-01"}, nil, false},
		{CertValidity{From: "2022-01-01", Until: "20230101"}, nil, false},

		//good cases
		{CertValidity{From: "2022-01-01", Until: "2023-01-01"},
			&config.CertificateValidity{From: fromDate(2022, 1, 1), Until: fromDate(2023, 1, 1), IsStatic: true, IsSet: true}, true},
		{CertValidity{From: "2022-01-01"},
			&config.CertificateValidity{From: fromDate(2022, 1, 1), Until: fromDate(2027, 1, 1), IsStatic: true, IsSet: true}, true},
		{CertValidity{},
			&config.CertificateValidity{IsStatic: false, IsSet: false}, true},
		{CertValidity{Until: "2050-01-01"},
			&config.CertificateValidity{Until: fromDate(2050, 1, 1), IsStatic: false, IsSet: true}, true},
		{CertValidity{From: "2022-01-01", Duration: "1y"},
			&config.CertificateValidity{From: fromDate(2022, 1, 1), Until: fromDate(2023, 1, 1), IsSet: true, IsStatic: true}, true},
		{CertValidity{From: "2022-01-01", Duration: "1m"},
			&config.CertificateValidity{From: fromDate(2022, 1, 1), Until: fromDate(2022, 2, 1), IsSet: true, IsStatic: true}, true},
		{CertValidity{From: "2022-01-01", Duration: "1d"},
			&config.CertificateValidity{From: fromDate(2022, 1, 1), Until: fromDate(2022, 1, 2), IsSet: true, IsStatic: true}, true},
		{CertValidity{From: "2022-01-01", Duration: "1y1m1d"},
			&config.CertificateValidity{From: fromDate(2022, 1, 1), Until: fromDate(2023, 2, 2), IsSet: true, IsStatic: true}, true},
		{CertValidity{From: "2022-01-01", Duration: "15y4m20d"},
			&config.CertificateValidity{From: fromDate(2022, 1, 1), Until: fromDate(2037, 5, 21), IsSet: true, IsStatic: true}, true},
	}

	undefinedTime := time.Time{}

	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			result, err := test.json.toTimeStruct()

			if (err == nil) != test.errorNil {
				t.Errorf("#%v: Error differs from expectation. Expected: %v, got %v", i, test.errorNil, err == nil)
			}

			if test.cfg == nil {
				return
			}

			if test.cfg.From != undefinedTime && result.From != test.cfg.From {
				t.Errorf(`#%v: "From"-time different than expected. Expected "%v", got "%v"`, i, test.cfg.From, result.From)
			}

			if test.cfg.Until != undefinedTime && result.Until != test.cfg.Until {
				t.Errorf(`#%v: "To"-time different than expected. Expected "%v", got "%v"`, i, test.cfg.Until, result.Until)
			}

			if result.IsSet != test.cfg.IsSet {
				t.Errorf(`#%v: IsSet flag different than expected. Expected "%v", got "%v"`, i, test.cfg.IsSet, result.IsSet)
			}

			if result.IsStatic != test.cfg.IsStatic {
				t.Errorf(`#%v: IsStatic flag different than expected. Expected "%v", got "%v"`, i, test.cfg.IsStatic, result.IsStatic)
			}

		})
	}
}

//go:embed certificate_test.json
var certificateConfigSchemaTests string

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
