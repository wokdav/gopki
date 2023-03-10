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
	"math/big"

	"github.com/wokdav/gopki/generator/cert"
	"github.com/wokdav/gopki/generator/config"
	"github.com/wokdav/gopki/logging"
)

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

	if c.SerialNumber != 0 {
		ctx.SerialNumber = big.NewInt(c.SerialNumber)
	}
	ctx.IssuerUniqueId = c.IssuerUniqueId
	ctx.SubjectUniqueId = c.SubjectUniqueId

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

	if c.Manipulations.Version != nil {
		ctx.TbsCertificate.Version = *c.Manipulations.Version
	}
	if c.Manipulations.TbsSignature != nil {
		ctx.TbsCertificate.SignatureAlgorithm = *c.Manipulations.TbsSignature
	}
	if c.Manipulations.TbsPublicKeyAlgorithm != nil {
		ctx.TbsCertificate.PublicKey.Algorithm = *c.Manipulations.TbsPublicKeyAlgorithm
	}
	if c.Manipulations.TbsPublicKey != nil {
		ctx.TbsCertificate.PublicKey.PublicKey = *c.Manipulations.TbsPublicKey
	}

	return ctx, nil
}

// Returns a [cert.Certificate] using the suppliec [cert.CertificateContext].
// It also takes care of applying the [config.CertificateContent.Manipulations]
// to the certificate. The function will fail, if the signing fails.
func SignCertBody(ctx *cert.CertificateContext, cfg config.CertificateContent) (*cert.Certificate, error) {
	cert, err := ctx.Sign(cfg.SignatureAlgorithm)
	if err != nil {
		logging.Errorf("can't sign certificate for %v: %v", cfg.Alias, err.Error())
		return nil, err
	}

	if cfg.Manipulations.SignatureAlgorithm != nil {
		cert.SignatureAlgorithm = *cfg.Manipulations.SignatureAlgorithm
	}
	if cfg.Manipulations.SignatureValue != nil {
		cert.SignatureValue = *cfg.Manipulations.SignatureValue
	}

	return cert, nil
}
