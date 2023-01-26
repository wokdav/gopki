// Implements version 1 of the configuration parser.
//
// It applies some defaults to the configurations:
// - Default Key Algorithm: EC P-256
// - Default Signature Algorithm: ECDSAWithSHA256 for EC; RSAWIthSHA256 for RSA.
// - Default certificate validity: 5 years, starting from the current point in time.
package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"gopki/generator/cert"
	"gopki/generator/config"
	"gopki/logging"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ghodss/yaml"
)

var durationRx *regexp.Regexp

func init() {
	config.AddConfigurator(1, V1Configurator{})

	type tmpDuration struct {
		Pattern string
	}
	t := tmpDuration{}
	err := json.NewDecoder(strings.NewReader(DurationSchemaString)).Decode(&t)
	if err != nil {
		panic("config-v1: can't decode duration json schema")
	}

	durationRx = regexp.MustCompile(t.Pattern)
}

const (
	dateForm     = "2006-02-01"
	binaryPrefix = "!binary:"
	emptyPrefix  = "!empty"
	nullPrefix   = "!null"
)

// Struct for YAML/JSON marshaling.
type CertValidity struct {
	From     string `json:"from"`
	Until    string `json:"until"`
	Duration string `json:"duration"`
}

// Struct for YAML/JSON marshaling.
type CertConfig struct {
	Alias              string         `json:"alias"`
	Version            int            `json:"version"`
	Profile            string         `json:"profile"`
	Subject            string         `json:"subject"`
	Issuer             string         `json:"issuer"`
	Validity           CertValidity   `json:"validity"`
	KeyAlgorithm       string         `json:"keyAlgorithm"`
	SignatureAlgorithm string         `json:"signatureAlgorithm"`
	Extensions         []AnyExtension `json:"extensions"`
}

type CfgFileType int

const (
	fileTypeIllegal CfgFileType = iota
	fileTypeCertConfig
	fileTypeCertProfile
)

// The implementor of [config.Configurator] for version 1.
type V1Configurator struct{}

// calculate start and end time from string struct
func (c CertValidity) extractTimespan() (*time.Time, *time.Time, error) {
	var from time.Time
	var to time.Time

	//parse validity
	//determine start time
	if len(c.From) != 0 {
		t, err := time.ParseInLocation(dateForm, c.From, time.Local)
		if err != nil {
			return nil, nil, errors.New(`config-v1: "from" date is not conforming to YYYY-MM-DD`)
		}
		from = t
	} else {
		return nil, nil, errors.New(`config-v1: "from" date is missing`)
	}

	//determine expiration time
	if len(c.Until) != 0 && len(c.Duration) != 0 {
		return nil, nil, errors.New(`config-v1: "until" and "duration" were both specified, instead of just one`)
	} else {
		if len(c.Until) != 0 {
			t, err := time.ParseInLocation(dateForm, c.Until, time.Local)
			if err != nil {
				return nil, nil, errors.New(`config-v1: "until" date is not conforming to YYYY-MM-DD`)
			}
			to = t
		} else if len(c.Duration) != 0 {
			if !durationRx.MatchString(c.Duration) {
				return nil, nil, errors.New(`config-v1: "duration" is not conforming to schema`)
			}

			all := durationRx.FindStringSubmatch(c.Duration)

			// schema already tells us it's conforming, so we ignore errors here
			y, _ := strconv.Atoi(all[2])
			m, _ := strconv.Atoi(all[4])
			d, _ := strconv.Atoi(all[6])

			to = time.Now().AddDate(y, m, d)
		} else {
			return nil, nil, errors.New(`config-v1: "until" and "duration" both not given`)
		}
	}

	return &from, &to, nil
}

const (
	defaulSignatureAlgorithmEc  = cert.ECDSAwithSHA256
	defaulSignatureAlgorithmRsa = cert.RSAwithSHA256
	defaultKeyAlgorithm         = cert.P256
)

var keyAlgorithms map[string]cert.KeyAlgorithm = map[string]cert.KeyAlgorithm{
	"RSA-1024":        cert.RSA1024,
	"RSA-2048":        cert.RSA2048,
	"RSA-4096":        cert.RSA4096,
	"RSA-8192":        cert.RSA8192,
	"P-224":           cert.P224,
	"P-256":           cert.P256,
	"P-384":           cert.P384,
	"P-521":           cert.P521,
	"brainpoolP256r1": cert.BrainpoolP256r1,
	"brainpoolP384r1": cert.BrainpoolP256r1,
	"brainpoolP512r1": cert.BrainpoolP256r1,
	"brainpoolP256t1": cert.BrainpoolP256t1,
	"brainpoolP384t1": cert.BrainpoolP256t1,
	"brainpoolP512t1": cert.BrainpoolP256t1,
}

var sigAlgorithms map[string]cert.SignatureAlgorithm = map[string]cert.SignatureAlgorithm{
	"RSAwithSHA1":     cert.RSAwithSHA1,
	"RSAwithSHA256":   cert.RSAwithSHA256,
	"RSAwithSHA384":   cert.RSAwithSHA384,
	"RSAwithSHA512":   cert.RSAwithSHA512,
	"ECDSAwithSHA1":   cert.ECDSAwithSHA1,
	"ECDSAwithSHA256": cert.ECDSAwithSHA256,
	"ECDSAwithSHA384": cert.ECDSAwithSHA384,
	"ECDSAwithSHA512": cert.ECDSAwithSHA512,
}

func inferDefaults(v *CertValidity) bool {
	if len(v.Duration) == 0 && len(v.Until) == 0 && len(v.From) == 0 {
		return false
	}

	if len(v.From) == 0 {
		logging.Debug("'from' is missing. setting to current time")
		v.From = time.Now().Local().Format(dateForm)
	}

	if len(v.Until) == 0 && len(v.Duration) == 0 {
		logging.Debug("'until' and 'duration' are missing. setting to current time + 5y")
		v.Until = time.Now().Local().AddDate(5, 0, 0).Format(dateForm)
	}

	return true
}

// Struct for YAML/JSON marshaling.
type Profile struct {
	ProfileName       string                          `json:"name"`
	Version           int                             `json:"version"`
	Validity          CertValidity                    `json:"validity"`
	SubjectAttributes config.ProfileSubjectAttributes `json:"subjectAttributes"`
	Extensions        []AnyExtension                  `json:"extensions"`
}

func initProfile(p Profile) (*config.CertificateProfile, error) {
	out := config.CertificateProfile{}
	out.Name = p.ProfileName
	out.SubjectAttributes = p.SubjectAttributes

	var err error

	changed := inferDefaults(&p.Validity)
	if changed {
		out.ValidFrom, out.ValidUntil, err = p.Validity.extractTimespan()
		if err != nil {
			return nil, err
		}
	}

	logging.Debugf("effective 'from' time value: %v", out.ValidFrom)
	logging.Debugf("effective 'to' time value: %v", out.ValidUntil)

	out.Extensions, err = parseExtensions(p.Extensions)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

func getFileType(s string) (CfgFileType, error) {
	//has it "name"? -> profile
	//has it "subject"? -> certCfg
	type minCertCfg struct {
		Subject string `json:"subject"`
	}
	type minCertProfile struct {
		Name string `json:"name"`
	}

	errorText := strings.Builder{}
	errorText.WriteString("can't parse as cert config: ")

	b := []byte(s)

	var c minCertCfg
	err := yaml.Unmarshal(b, &c)
	if err != nil {
		errorText.WriteString(err.Error() + "\n")
	}

	if len(c.Subject) <= 0 {
		errorText.WriteString("subject length seems to be 0\n")
	} else {
		return fileTypeCertConfig, nil
	}

	var p minCertProfile
	err = yaml.Unmarshal(b, &p)
	errorText.WriteString("can't parse as cert profile: ")
	if err != nil {
		errorText.WriteString(err.Error() + "\n")
	}

	if len(p.Name) <= 0 {
		errorText.WriteString("profile name length seems to be 0\n")
	} else {
		return fileTypeCertProfile, nil
	}

	return fileTypeIllegal, errors.New(errorText.String())
}

// Implements ParseConfiguration from [config.Configurator].
// It unmarshals the provided string and generate the appropriate configuration object
// with the stated defaults.
func (v V1Configurator) ParseConfiguration(s string) (any, error) {
	//do we have a profile, or a certificate?
	typ, err := getFileType(s)
	if err != nil {
		return nil, err
	}

	js, err := yaml.YAMLToJSON([]byte(s))
	if err != nil {
		return nil, err
	}

	//certificate
	if typ == fileTypeCertConfig {
		err = certificateSchema.Validate(bytes.NewBuffer(js))
		if err != nil {
			return nil, err
		}

		certCfg := CertConfig{}
		err = yaml.Unmarshal(js, &certCfg)
		if err != nil {
			return nil, err
		}

		out, err := initCertificate(certCfg)
		if err != nil {
			return nil, err
		}

		return out, nil
	}

	//profile
	err = profileSchema.Validate(bytes.NewBuffer(js))
	if typ == fileTypeCertProfile {
		if err != nil {
			return nil, err
		}

		profileCfg := Profile{}
		err = yaml.Unmarshal(js, &profileCfg)
		if err != nil {
			return nil, err
		}

		out, err := initProfile(profileCfg)
		if err != nil {
			return nil, err
		}

		return out, nil
	}

	return nil, errors.New("config-v1: provided string neither compatible with profile nor with certificate config")
}

func initCertificate(c CertConfig) (*config.CertificateContent, error) {
	out := config.CertificateContent{}

	out.Profile = c.Profile

	dn, err := config.ParseRDNSequence(c.Subject)
	if err != nil {
		return nil, err
	}
	out.Subject = dn

	out.Alias = c.Alias
	out.Issuer = c.Issuer

	//fill in default values
	if len(c.Validity.From) == 0 {
		c.Validity.From = time.Now().Local().Format(dateForm)
	}
	changed := inferDefaults(&c.Validity)

	if !changed {
		return nil, errors.New("config-v1: not enough information to calculate defaults for validity")
	}

	from, to, err := c.Validity.extractTimespan()
	if err != nil {
		return nil, err
	}

	out.ValidFrom = *from
	out.ValidUntil = *to

	out.KeyAlgorithm = defaultKeyAlgorithm

	var ok bool
	if len(c.KeyAlgorithm) > 0 {
		out.KeyAlgorithm, ok = keyAlgorithms[c.KeyAlgorithm]
		if !ok {
			return nil, fmt.Errorf("config-v1: unknown key algorithm '%v'", c.KeyAlgorithm)
		}
	}

	if len(c.SignatureAlgorithm) > 0 {
		out.SignatureAlgorithm, ok = sigAlgorithms[c.SignatureAlgorithm]
		if !ok {
			return nil, fmt.Errorf("config-v1: unknown signature algorithm '%v'", c.SignatureAlgorithm)
		}
	} else {
		if strings.HasPrefix(c.KeyAlgorithm, "RSA") {
			out.SignatureAlgorithm = defaulSignatureAlgorithmRsa
		} else {
			out.SignatureAlgorithm = defaulSignatureAlgorithmEc
		}
	}

	out.Extensions, err = parseExtensions(c.Extensions)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

func (v V1Configurator) ProfileExample() string {
	return profileExample
}

func (v V1Configurator) CertificateExample() string {
	return certificateExample
}
