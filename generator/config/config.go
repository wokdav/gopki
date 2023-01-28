// Package that provides certificate and profile configurations.
// It supports configuration versioning, having each implementation
// register themselves in this package.
// External parties should only use this package to for configuring
// and ignore the underlying implementations. Also this package
// must not import packages of it's implementations to avoid circular
// imports.
//
// This package assumes that each underlying implementation will be
// in YAML or JSON, with the topmost element being a map containg a
// property named 'version' that is set to an integer. All other
// details are set by the underlying implementation.
// This allows this package to decide automatically, which version
// applies to a config file, so the external party does not need to
// pre-parse config files.
//
// Additionally it provides several utility functions for profile
// verification and merging.

package config

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/wokdav/gopki/generator/cert"
	"github.com/wokdav/gopki/logging"

	"github.com/ghodss/yaml"
)

var configurators map[int]Configurator = make(map[int]Configurator, 1)

// Configuration implementations register themselves using this function.
// It is recommended to keep verion > 0 to avoid bugs regarding to uninitialized
// version numbers.
func AddConfigurator(version int, c Configurator) {
	configurators[version] = c
}

// Get configurator for the supplied version.
// Returns an error, if this version does not exist (yet).
func GetConfigurator(version int) (Configurator, error) {
	c, ok := configurators[version]
	if !ok {
		return nil, fmt.Errorf("config: unknown version: %d", version)
	}

	return c, nil
}

// This is the minimum requirement for config implementations.
// A test-marshal into this is done to determine the underlying config implementation.
type configProxy struct {
	Version int
}

// The main parsing function for configurations. This is the intended way to parse a
// config.
// It attempts to read the version integer from the config and then decide which version to
// use based on that. It returns either a [config.CertificateContent] or a [config.CertificateProfile]
// on success.
// It throws an error, if the provided stream does not conform to the assumptions this package
// makes (see package documentation), or if the version does not exist (yet).
func ParseConfig(r io.Reader) (any, error) {
	sb := new(strings.Builder)
	w, err := io.Copy(sb, r)
	if err != nil {
		return nil, fmt.Errorf("config: error reading certificate config buffer after %d bytes: %v", w, err)
	}
	cfgstr := sb.String()

	var proxy configProxy
	err = yaml.Unmarshal([]byte(cfgstr), &proxy)
	if err != nil {
		return nil, errors.New("config: top level must be a map containg a key called 'version' that contains an integer")
	}

	configurator, prs := configurators[proxy.Version]
	if !prs {
		return nil, fmt.Errorf("config: unknown version: %d", proxy.Version)
	}

	return configurator.ParseConfiguration(cfgstr)
}

// The interface each configuration version must implement.
type Configurator interface {
	ParseConfiguration(s string) (any, error)
	ProfileExample() string
	CertificateExample() string
}

// The general representation of a certificate configuration.
// Generation engines can use this to generate certificates.
type CertificateContent struct {
	Alias              string
	Profile            string
	Subject            pkix.RDNSequence
	Issuer             string
	ValidFrom          time.Time
	ValidUntil         time.Time
	KeyAlgorithm       cert.KeyAlgorithm
	SignatureAlgorithm cert.SignatureAlgorithm
	Extensions         []ExtensionConfig
}

type ProfileSubjectAttribute struct {
	Attribute string `json:"attribute"`
	Optional  bool   `json:"optional"`
}

type ProfileSubjectAttributes struct {
	AllowOther bool                      `json:"allowOther"`
	Attributes []ProfileSubjectAttribute `json:"attributes"`
}

// The general representation of a certificate profile.
type CertificateProfile struct {
	Name              string
	ValidFrom         *time.Time
	ValidUntil        *time.Time
	SubjectAttributes ProfileSubjectAttributes
	Extensions        []ExtensionConfig
}

// Each extension must have these values in order for a
// profile to correctly validate/merge extensions.
type ExtensionProfile struct {
	//this is used for extensions inside profiles
	//when parsing a certificate, these values are ignored.
	Optional bool `json:"optional"`
	Override bool `json:"override"`
}

// The interface each Extension needs to implement.
// The Oid is used to determine, whether extensions
// have the same "type" during a merge.
// The builder function is there so that the [cert]
// package can build the extension iteself.
type ExtensionConfig interface {
	Profile() ExtensionProfile
	ContentEquals(ExtensionConfig) bool
	Oid() (asn1.ObjectIdentifier, error)
	Builder() (cert.ExtensionBuilder, error)
}

var attributeTypeNames = map[string]asn1.ObjectIdentifier{
	"C":            {2, 5, 4, 6},
	"O":            {2, 5, 4, 10},
	"OU":           {2, 5, 4, 11},
	"CN":           {2, 5, 4, 3},
	"SERIALNUMBER": {2, 5, 4, 5},
	"L":            {2, 5, 4, 7},
	"ST":           {2, 5, 4, 8},
	"STREET":       {2, 5, 4, 9},
	"POSTALCODE":   {2, 5, 4, 17},
}

// Parses the string representation of a Relative Distinguished Name.
// The underlying data structure will be in reverse order so that it
// conforms to RFC4514#section-2.1. It supports custom OID attributes.
//
// To keep this function simple, there are some limitations:
//   - only shorthand string representations are recognized (e.g. CN instead of commonName)
//   - only C, O, OU, CN, SERIALNUMBER, L, ST, STREET, POSTALCODE are recognized as representations
//   - custom OIDs are supported, but the values is always interpreted as a string, and
//     not as #[DER-SEQUENCE] as RFC4514 demands. This is done for simplicity and ease of configuration
func ParseRDNSequence(s string) (pkix.RDNSequence, error) {
	assertions := make([]string, 0, strings.Count(s, ","))

	//split along commas, make sure to skip escapes
	assertBegin := 0
	for i, symbol := range s {
		if i == 0 {
			continue
		}

		//we know these specific chars are 1-byte values in utf-8
		//so comparing the byte directly is fine.
		if symbol == ',' && s[i-1] != '\\' {
			assertions = append(assertions, s[assertBegin:i])
			assertBegin = i + 1
		}
	}
	assertions = append(assertions, s[assertBegin:])

	out := make([]pkix.RelativeDistinguishedNameSET, len(assertions))

	//go backwards, because thats how string representations of RDNs
	//are supposed to be read
	for i, assertion := range assertions {
		assertion = strings.TrimSpace(assertion)
		parts := strings.Split(assertion, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("config: malformed DN key-value pair: '%v'", assertion)
		}

		searchKey := strings.TrimSpace(parts[0])
		oid, err := GetRdnAttributeOid(searchKey)
		if err != nil {
			//do we have a custom oid?
			oid, err = cert.OidFromString(searchKey)
			if err != nil {
				return nil, fmt.Errorf("config: '%s' is not a valid RDN component nor a valid oid", searchKey)
			}
		}

		outIndex := len(out) - i - 1
		if outIndex < 0 || outIndex >= len(out) {
			return nil, fmt.Errorf("config: can't write to index %d, we only have 0-%d", outIndex, len(out))
		}
		out[len(out)-i-1] = pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  oid,
				Value: parts[1],
			},
		}
	}

	return out, nil
}

// Helper function to get a RDN attribute OID based on it's shorthand
// string representation.
func GetRdnAttributeOid(attr string) (asn1.ObjectIdentifier, error) {
	oid, ok := attributeTypeNames[attr]
	if !ok {
		return nil, fmt.Errorf("config: attribute '%v' doesn't exist", attr)
	}

	return oid, nil
}

// Builder that implements [cert.ExtensionBuilder].
// This allows to arbitrarily set the extension itself for cases where
// the content is already defined at the time of config parsing.
type ConstantBuilder struct {
	pkix.Extension
}

func (c ConstantBuilder) Compile(ctx *cert.CertificateContext) (*pkix.Extension, error) {
	return &c.Extension, nil
}

// Builder that implements [cert.ExtensionBuilder].
// It will never yield an extension, but instead will return an error,
// that this extension needs to be replaced.
//
// This is useful when a certificate inherits an extension from its profile
// that is requred to be overrided, because the profile itself doesn't define
// the content of the extension.
type OverrideNeededBuilder struct{}

func (e OverrideNeededBuilder) Compile(ctx *cert.CertificateContext) (*pkix.Extension, error) {
	return nil, fmt.Errorf("need override for this extension")
}

// Builder that implements [cert.ExtensionBuilder].
// Builds an extension according to the provided function.
// The function will be executed when calling Compile(), so
// side effects may apply accordingly.
type FunctionBuilder struct {
	Function func(ctx *cert.CertificateContext) (*pkix.Extension, error)
}

func (f FunctionBuilder) Compile(ctx *cert.CertificateContext) (*pkix.Extension, error) {
	if f.Function == nil {
		return nil, errors.New("config: provided function is a null pointer")
	}
	return f.Function(ctx)
}

// Function to validate a certificate profile against a certificate configuration.
// It will check the constraints on the subject DN mandated by the profile.
// Extensions will not be checked here, since this is covered by the override errors
// when calling Compile().
func Validate(profile CertificateProfile, content CertificateContent) bool {
	//check subject attributes
	if profile.SubjectAttributes.Attributes != nil {
		//reverse subject, since we are comparing against a string representation
		subject := content.Subject
		for i, j := 0, len(subject)-1; i < j; i, j = i+1, j-1 {
			subject[i], subject[j] = subject[j], subject[i]
		}
		wantAttribute := 0
		haveAttribute := 0
		for {
			if wantAttribute >= len(profile.SubjectAttributes.Attributes) ||
				haveAttribute >= len(subject) {
				break
			}

			currentAttribute := profile.SubjectAttributes.Attributes[wantAttribute].Attribute
			wantAt, err := GetRdnAttributeOid(currentAttribute)
			if err != nil {
				//do we have a custom oid?
				oid, err := cert.OidFromString(currentAttribute)
				if err != nil {
					logging.Warningf("profile violation: can't resolve %v to a known attribute OID",
						currentAttribute)
					return false
				}
				wantAt = oid
			}

			if wantAt.Equal(subject[haveAttribute][0].Type) {
				wantAttribute++
				haveAttribute++
			} else {
				if profile.SubjectAttributes.AllowOther {
					haveAttribute++
				} else {
					logging.Warningf("profile violation: expected %v at this position, but got %v and allowOther is false",
						wantAt, subject[haveAttribute][0].Type)
					return false
				}
			}
		}

		if haveAttribute < len(content.Subject) && !profile.SubjectAttributes.AllowOther {
			logging.Warningf("profile violation: provided number of attributes larger than specified in profile while allowOther is false")
			return false
		}
	}

	return true
}

var uninitializedTime time.Time = time.Time{}

// Function to merge a certificate profile into a certificate configuration.
// The certificate will inherit the validity and the extensions, if it does not
// define it itself. One exception are non-optional extensions which will always be inherited.
//
// When merging extension the order will be preserverd. Inherited extensions will always be
// above the extensions set by the certificate.
func Merge(profile CertificateProfile, content CertificateContent) (*CertificateContent, error) {
	//copy
	out := content
	if profile.ValidFrom != nil && profile.ValidUntil != nil {
		if content.ValidFrom.Equal(uninitializedTime) {
			out.ValidFrom = *profile.ValidFrom
		}
		if content.ValidUntil.Equal(uninitializedTime) {
			out.ValidUntil = *profile.ValidUntil
		}
	}

	newExt := make([]ExtensionConfig, 0, len(profile.Extensions)+len(content.Extensions))

	certExtsHandled := make([]int, 0, len(content.Extensions))
	for _, profExt := range profile.Extensions {
		oidProf, err := profExt.Oid()
		if err != nil {
			return nil, err
		}

		handled := false
		for i, certExt := range content.Extensions {
			//check if we handled the content-extension already
			wasThisHandled := false
			for _, ix := range certExtsHandled {
				if ix == i {
					wasThisHandled = true
					break
				}
			}

			if wasThisHandled {
				continue
			}

			oidContent, err := certExt.Oid()
			if err != nil {
				return nil, err
			}

			if oidProf.Equal(oidContent) {
				handled = true
				certExtsHandled = append(certExtsHandled, i)

				if !profExt.Profile().Override && !profExt.ContentEquals(certExt) {
					newExt = append(newExt, profExt)
				}

				break
			}
		}

		if !handled && !profExt.Profile().Optional {
			newExt = append(newExt, profExt)
		}
	}

	newExt = append(newExt, content.Extensions...)
	out.Extensions = newExt

	return &out, nil
}
