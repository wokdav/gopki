package v1

import (
	"testing"

	"github.com/wokdav/gopki/generator/config"

	_ "embed"
)

//go:embed certificate_test.json
var certificateConfigSchemaTests string

func TestCertificateSchema(t *testing.T) {
	schemaTestJson(certificateConfigSchemaTests, certificateSchema, t)
}

func TestCertificateExample(t *testing.T) {
	v := V1Configurator{}
	cfg, err := v.ParseConfiguration(v.CertificateExample())
	if err != nil {
		t.Fatal(err.Error())
	}

	_, ok := cfg.(*config.CertificateContent)
	if !ok {
		t.Fatal("cannot cast into cert config")
	}
}
