package v1

import (
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema"
)

type schemaElement struct {
	name   string
	schema string
}

type schemaHierarchy struct {
	schemas    []schemaElement
	mainSchema string
}

//go:embed date.json
var dateSchemaString string

//go:embed duration.json
var DurationSchemaString string

//go:embed general_name.json
var generalNameSchemaString string

//go:embed oid.json
var oidSchemaString string

//go:embed rdn-attribute.json
var rdnSchemaString string

//go:embed validity.json
var validitySchemaString string

//go:embed extension_rawcontent.json
var extensionRawContentSchemaString string

//go:embed extension.json
var extensionSchemaString string

//go:embed profile.json
var profileSchemaString string

//go:embed certificate.json
var certificateSchemaString string

//go:embed profile-example.yaml
var profileExample string

//go:embed certificate-example.yaml
var certificateExample string

// it's important that the dependencies are added first,
// and the schemas that depend on them after that
var schemas []schemaElement = []schemaElement{
	{"date.json", dateSchemaString},
	{"general_name.json", generalNameSchemaString},
	{"oid.json", oidSchemaString},
	{"duration.json", DurationSchemaString},
	{"validity.json", validitySchemaString},
	{"rdn-attribute.json", rdnSchemaString},
	{"extension_rawcontent.json", extensionRawContentSchemaString},
	{"extension.json", extensionSchemaString},
	{"profile.json", profileSchemaString},
	{"certificate.json", certificateSchemaString},
}

func compileSchema(hierarchy *schemaHierarchy) (*jsonschema.Schema, error) {
	if hierarchy == nil {
		return nil, errors.New("schema: hierarchy must not be nil")
	}

	compiler := jsonschema.NewCompiler()
	for _, element := range hierarchy.schemas {
		err := compiler.AddResource(element.name, strings.NewReader(element.schema))
		if err != nil {
			return nil, fmt.Errorf(fmt.Sprintf("schema: error adding schema %v: %v",
				element.name, err))
		}
	}

	compiledSchema, err := compiler.Compile(hierarchy.mainSchema)
	if err != nil {
		return nil, fmt.Errorf("schema: error compiling schema %v: %v",
			hierarchy.mainSchema, err)
	}

	return compiledSchema, nil
}

var profileSchema *jsonschema.Schema
var certificateSchema *jsonschema.Schema

func init() {
	var err error
	profileSchema, err = compileSchema(&schemaHierarchy{schemas, "profile.json"})
	if err != nil {
		panic(err)
	}

	certificateSchema, err = compileSchema(&schemaHierarchy{schemas, "certificate.json"})
	if err != nil {
		panic(err)
	}
}
