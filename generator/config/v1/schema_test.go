package v1

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema"
)

func compileSingleSchema(name string) *jsonschema.Schema {
	schema, err := compileSchema(&schemaHierarchy{schemas, name})
	if err != nil {
		panic(err)
	}

	return schema
}

// Unit test helper for schema tests.
// Provide a test table with json-strings as keys and set the value to true, if
// the key shall validate against the schema, false otherwise. t will then
// fail if the expectation does not match. Any error during
// schema validation or json parsing will also result in a failure for t.
func schemaTest(testTable map[string]bool, schema *jsonschema.Schema, t *testing.T) {
	for test, expectSuccess := range testTable {
		unmarshalledData, err := jsonschema.DecodeJSON(strings.NewReader(test))

		if err != nil {
			t.Errorf("Can't decode json from test string '%v'", test)
		}

		//run as sub-test
		t.Run(test, func(t *testing.T) {
			err = schema.ValidateInterface(unmarshalledData)

			if (err == nil) != expectSuccess {
				if !expectSuccess {
					t.Errorf("Schema accepted '%v', but is not supposed to", test)
				} else {
					t.Errorf("Schema did not accept '%v' due to the following errors: %v", test, err)
				}
			}
		})

	}
}

type certificateSchemaTestSuite []certificateSchemaTestVector

type certificateSchemaTestVector struct {
	Name            string
	Test            any
	ExpectSuccess   bool
	SkipParserCheck bool
}

func schemaTestJson(testSuiteJson string, schema *jsonschema.Schema, t *testing.T) {
	d := json.NewDecoder(strings.NewReader(testSuiteJson))
	var ts certificateSchemaTestSuite
	err := d.Decode(&ts)
	if err != nil {
		t.Fatalf("can't decode testsuite: %v", err)
	}

	for _, testCase := range ts {
		t.Run(testCase.Name, func(t *testing.T) {
			//jsonschema expects to decode it's own data
			//so we encode the test vector to a string and
			//re-decode using jsonschema
			sb := strings.Builder{}
			enc := json.NewEncoder(&sb)
			err = enc.Encode(testCase.Test)
			if err != nil {
				t.Fatalf("can't re-encode test vector: %v", err)
			}

			schemaTest, err := jsonschema.DecodeJSON(strings.NewReader(sb.String()))
			if err != nil {
				if err != nil {
					t.Fatalf("can't re-decode test vector: %v", err)
				}
			}

			err = schema.ValidateInterface(schemaTest)
			if (err == nil) != testCase.ExpectSuccess {
				if !testCase.ExpectSuccess {
					t.Errorf("Schema accepted '%v', but is not supposed to", testCase.Name)
				} else {
					t.Errorf("Schema did not accept '%v' due to the following errors: %v", testCase.Name, err)
				}
			}
		})
	}
}

// StringWriter that fails, if set to false, succeeds otherwise
type failWriter bool

func (f failWriter) WriteString(s string) (n int, err error) {
	if f {
		return 0, errors.New("creating error on purpose")
	}
	return len(s), nil
}

func TestCompileNilSchema(t *testing.T) {
	sch, err := compileSchema(nil)
	if sch != nil || err == nil {
		t.Errorf("expected null schema to fail compilation")
	}
}

func TestCompileGarbageSchema(t *testing.T) {
	sch, err := compileSchema(
		&schemaHierarchy{schemas: []schemaElement{
			{name: "bla.json", schema: "wogih2039gj23p"},
		}, mainSchema: "bla.json"})
	if sch != nil || err == nil {
		t.Errorf("expected garbage schema to fail compilation")
	}
}

func TestCompileIncompleteSchema(t *testing.T) {
	sch, err := compileSchema(
		&schemaHierarchy{schemas: []schemaElement{
			{name: "bla.json", schema: `{"$ref": "blubb.json"}`},
		}, mainSchema: "bla.json"})
	if sch != nil || err == nil {
		t.Errorf("expected incomplete schema to fail compilation")
	}
}

func TestOid(t *testing.T) {
	var tests map[string]bool = map[string]bool{
		// good
		`"1"`:                  true,
		`"37459283"`:           true,
		`"1.2"`:                true,
		`"1.3.791.2"`:          true,
		`"430957.12591.12389"`: true,
		`"1.2.11.1.1.1.1.1.1.1.2.2.2.2.1.1.1.1.1.2.2.2.2.0.9.0"`: true,

		//bad
		`""`:                false,
		`"."`:               false,
		`"😇"`:               false,
		`"-5"`:              false,
		`"1."`:              false,
		`".1"`:              false,
		`"30587.1.2..42.1"`: false,
		`"1.2.3.four.5"`:    false,
	}

	schemaTest(tests, compileSingleSchema("oid.json"), t)
}

func TestDate(t *testing.T) {
	var tests map[string]bool = map[string]bool{
		// good
		`"2020-01-02"`: true,
		`"1305-12-31"`: true,
		`"0025-01-03"`: true,
		`"1234-01-21"`: true,

		//bad
		`""`:           false,
		`"--"`:         false,
		`"😇"`:          false,
		`"1-1-1"`:      false,
		`"1234-20-01"`: false,
	}

	schemaTest(tests, compileSingleSchema("date.json"), t)
}

func TestRelativeDate(t *testing.T) {
	var tests map[string]bool = map[string]bool{
		// good
		`"1d"`:      true,
		`"1m"`:      true,
		`"1y"`:      true,
		`"16816d"`:  true,
		`"65867m"`:  true,
		`"914757y"`: true,
		`"4m1d"`:    true,
		`"8y4m"`:    true,
		`"8y1d"`:    true,
		`"5y8m69d"`: true,

		//bad
		`"d"`:     false,
		`"m"`:     false,
		`"y"`:     false,
		`"1ym"`:   false,
		`"1md"`:   false,
		`"1d5y"`:  false,
		`"1d5m"`:  false,
		`"1m5y"`:  false,
		`"y8m8d"`: false,
		`"8y8md"`: false,
		`"8ym8d"`: false,
		`"😇"`:     false,
		`"ymd"`:   false,
	}

	schemaTest(tests, compileSingleSchema("duration.json"), t)
}

func TestValidity(t *testing.T) {
	var tests map[string]bool = map[string]bool{
		// good
		`{ "until": "2030-01-01" }`:                       true,
		`{ "duration": "10y" }`:                           true,
		`{ "from": "2020-01-01", "until": "2030-01-01" }`: true,
		`{ "from": "2020-01-01", "duration": "10y" }`:     true,

		//bad
		`{}`:                       false,
		`{ "from": "2020-01-01" }`: false,
		`{ "from": "2020-01-01", "until": "2030-01-01", "duration": "10y" }`: false,
		`{ "until": "2030-01-01", "duration": "10y" }`:                       false,
	}

	schemaTest(tests, compileSingleSchema("validity.json"), t)
}
