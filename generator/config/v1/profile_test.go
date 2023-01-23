package v1

import (
	"fmt"
	"testing"
)

func TestProfileMandatoryValues(t *testing.T) {
	var tests map[string]bool = map[string]bool{
		// good
		// note: extensions are tested elsewhere, so we keep them empty
		`{
			"version": 1,
			"name": "myProfile",
			"subjectAttributes": {
				"attributes": [
					{ "attribute": "C", "optional": true },
					{ "attribute": "CN" }
				],
				"allowOther": false
			},
			"validity": {
				"from": "2020-01-01",
				"duration": "5y"
			},
			"extensions": []
		}`: true,

		//bad
		//no version
		`{
			"name": "myProfile",
			"subjectAttributes": {
				"attributes": [
					{ "attribute": "C", "optional": true },
					{ "attribute": "CN" }
				],
				"allowOther": false
			},
			"validity": {
				"from": "2020-01-01",
				"duration": "5y"
			},
			"extensions": []
		}`: false,
		//no name
		`{
			"version": 1,
			"subjectAttributes": {
				"attributes": [
					{ "attribute": "C", "optional": true },
					{ "attribute": "CN" }
				],
				"allowOther": false
			},
			"validity": {
				"from": "2020-01-01",
				"duration": "5y"
			},
			"extensions": []
		}`: false,
		//empty
		`{}`: false,
	}

	schemaTest(tests, profileSchema, t)
}

func TestProfileVersion(t *testing.T) {
	base := `{
		"version": %v,
		"name": "myProfile",
		"subjectAttributes": {
			"attributes": [
				{ "attribute": "C", "optional": true },
				{ "attribute": "CN" }
			],
			"allowOther": false
		},
		"validity": {
			"from": "2020-01-01",
			"duration": "5y"
		},
		"extensions": []
	}`

	var tests map[string]bool = map[string]bool{
		// good
		// accept version 1 only
		fmt.Sprintf(base, "1"): true,

		//bad
		fmt.Sprintf(base, "2"):   false,
		fmt.Sprintf(base, "-1"):  false,
		fmt.Sprintf(base, `"1"`): false,
		fmt.Sprintf(base, "[1]"): false,
	}

	schemaTest(tests, profileSchema, t)
}

func TestProfileName(t *testing.T) {
	base := `{
		"version": 1,
		"name": %v,
		"subjectAttributes": {
			"attributes": [
				{ "attribute": "C", "optional": true },
				{ "attribute": "CN" }
			],
			"allowOther": false
		},
		"validity": {
			"from": "2020-01-01",
			"duration": "5y"
		},
		"extensions": []
	}`

	var tests map[string]bool = map[string]bool{
		// good
		// accept strings only
		fmt.Sprintf(base, `"myProfile"`): true,
		fmt.Sprintf(base, `"12392835"`):  true,

		//bad
		fmt.Sprintf(base, `1`):             false,
		fmt.Sprintf(base, `["myProfile"]`): false,
		fmt.Sprintf(base, `""`):            false, //don't accept empty strings
	}

	schemaTest(tests, profileSchema, t)
}

func TestProfileSubjectAttributes(t *testing.T) {
	base := `{
		"version": 1,
		"name": "myProfile",
		"subjectAttributes": %v,
		"validity": {
			"from": "2020-01-01",
			"duration": "5y"
		},
		"extensions": []
	}`

	var tests map[string]bool = map[string]bool{
		// good
		fmt.Sprintf(base, `{"attributes": [{ "attribute": "C" }]}`):                    true,
		fmt.Sprintf(base, `{"attributes": [{ "attribute": "C", "optional": false }]}`): true,
		fmt.Sprintf(base, `{"attributes": [{ "attribute": "C", "optional": true }]}`):  true,
		fmt.Sprintf(base, `{"attributes": [{ "attribute": "C"}],"allowOther": false}`): true,
		fmt.Sprintf(base, `{"attributes": [{ "attribute": "C"}],"allowOther": true}`):  true,

		//bad
		fmt.Sprintf(base, `{}`):                                                          false,
		fmt.Sprintf(base, `{"attributes": []}`):                                          false,
		fmt.Sprintf(base, `{"attributes": [{ "attribute": 1 }]}`):                        false,
		fmt.Sprintf(base, `{"attributes": [ "C" ]}`):                                     false,
		fmt.Sprintf(base, `{"attributes": [{ "attribute": 1 }]}`):                        false,
		fmt.Sprintf(base, `{"attributes": [{ "attribute": "C", "unknownKey": "CN" }]}`):  false,
		fmt.Sprintf(base, `{"attributes": [{ "attribute": "C", "optional": 1 }]}`):       false,
		fmt.Sprintf(base, `{"attributes": [{ "attribute": "C", "optional": "true" }]}`):  false,
		fmt.Sprintf(base, `{"attributes": [{ "attribute": "C", "optional": [true] }]}`):  false,
		fmt.Sprintf(base, `{"attributes": [{ "attribute": "C"}],"allowOther": 1}`):       false,
		fmt.Sprintf(base, `{"attributes": [{ "attribute": "C"}],"allowOther": "true"}`):  false,
		fmt.Sprintf(base, `{"attributes": [{ "attribute": "C"}],"allowOther": [false]}`): false,
	}

	schemaTest(tests, profileSchema, t)
}

func TestProfileValidityAttributes(t *testing.T) {
	base := `{
		"version": 1,
		"name": "myProfile",
		"subjectAttributes": {
			"attributes": [
				{ "attribute": "C", "optional": true },
				{ "attribute": "CN" }
			],
			"allowOther": false
		},
		"validity": %v,
		"extensions": []
	}`

	var tests map[string]bool = map[string]bool{
		// note: the data boundaries are checked in subschema_test
		// good
		fmt.Sprintf(base, `{"until": "2020-01-01"}`):                       true,
		fmt.Sprintf(base, `{"duration": "5y4m1d"}`):                        true,
		fmt.Sprintf(base, `{"from": "2015-01-01", "until": "2020-01-01"}`): true,
		fmt.Sprintf(base, `{"from": "2015-01-01", "duration": "5y4m1d"}`):  true,

		//bad
		fmt.Sprintf(base, `{}`):                     false,
		fmt.Sprintf(base, `{"from": "2015-01-01"}`): false,
		fmt.Sprintf(base, `{"from": "2015-01-01", "duration": "5y4m1d", "until": "2020-01-01"}`): false,
	}

	schemaTest(tests, profileSchema, t)
}
