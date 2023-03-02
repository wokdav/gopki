// Package generator acts as the front-end for certificate generation and
// should always be the way external packages generate certificates.
//
// The proxy functions defined here take all measures necessary, so that a
// [config.CertificateContent] directly yields a [cert.CertificateContext].
// It also ensures that the intended defaults are applied as expected.
package generator

import (
	"crypto"
	"hash/crc32"

	"github.com/wokdav/gopki/generator/cert"
	"github.com/wokdav/gopki/generator/config"
	"github.com/wokdav/gopki/logging"
)

//TODO: add manipulation for other certificate fields (e.g. serial number)
//TODO: add support for CSRs
//TODO: collect certificates and configs concurrently via channels
//TODO: either fix cross-platform determinism or drop it altogether
//TODO: pkcs12 export

// Returns a [cert.CertificateContext] that corresponds to the supplied
// [config.CertificateContent]. This entails calling the Builder() function
// for each supplied [config.ExtensionConfig], so the side offects of these
// functions also apply. The function will fail, if any call to Builder()
// or the certificate generation itself fails.
func BuildCertBody(c config.CertificateContent, prk crypto.PrivateKey) (*cert.CertificateContext, error) {
	extBuild := make([]cert.ExtensionBuilder, len(c.Extensions))
	var err error
	for i, extCfg := range c.Extensions {
		extBuild[i], err = extCfg.Builder()
		if err != nil {
			logging.Errorf("can't build extension #%d for '%v': %v", i, c.Alias, err.Error())
			return nil, err
		}
	}

	//calculate crc32 of alias and put it into seed
	seed := int64(crc32.ChecksumIEEE([]byte(c.Alias + c.Subject.String())))

	ctx := cert.NewCertificateContext(c.Subject, extBuild,
		c.ValidFrom, c.ValidUntil, &seed)

	if prk == nil {
		err = ctx.GeneratePrivateKey(c.KeyAlgorithm)
	} else {
		ctx.SetPrivateKey(prk)
	}

	if err != nil {
		logging.Errorf("can't create private key for %v: %v", c.Alias, err.Error())
		return nil, err
	}

	ctx.SetIssuer(cert.AsIssuer(*ctx))

	return ctx, nil
}
