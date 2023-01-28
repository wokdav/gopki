// Package generator acts as the front-end for certificate generation and
// should always be the way external packages generate certificates.
//
// The proxy functions defined here take all measures necessary, so that a
// [config.CertificateContent] directly yields a [cert.CertificateContext].
// It also ensures that the intended defaults are applied as expected.
package generator

import (
	"github.com/wokdav/gopki/generator/cert"
	"github.com/wokdav/gopki/generator/config"
	"github.com/wokdav/gopki/logging"
)

// Returns a [cert.CertificateContext] that corresponds to the supplied
// [config.CertificateContent]. This entails calling the Builder() function
// for each supplied [config.ExtensionConfig], so the side offects of these
// functions also apply. The function will fail, if any call to Builder()
// or the certificate generation itself fails.
func BuildCertBody(c config.CertificateContent) (*cert.CertificateContext, error) {
	extBuild := make([]cert.ExtensionBuilder, len(c.Extensions))
	var err error
	for i, extCfg := range c.Extensions {
		extBuild[i], err = extCfg.Builder()
		if err != nil {
			logging.Errorf("can't build extension #%d for '%v': %v", i, c.Alias, err.Error())
			return nil, err
		}
	}
	ctx, err := cert.NewCertificateContext(c.Subject, c.KeyAlgorithm, extBuild,
		c.ValidFrom, c.ValidUntil)
	if err != nil {
		logging.Errorf("can't create certificate context for %v: %v", c.Alias, err.Error())
		return nil, err
	}

	if len(c.Alias) > 0 {
		ctx.Alias = c.Alias
	}

	return ctx, nil
}
