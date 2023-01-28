// Generic certificate database package
//
// This provides functionality to read certificate configurations
// and generated content from any source.
//
// At this point in time it's tailored to one-shot filesystem generation,
// but this will change, once other sources (like e.g. REST-APIs) are added.
package db

import (
	"github.com/wokdav/gopki/generator/cert"
)

type CertificateDatabase interface {
	Open() error
	GetAll() ([]cert.CertificateContext, error)
	Update(UpdateStrategy) error
	Close() error
}

type UpdateStrategy uint8

const (
	GenerateNever       UpdateStrategy = 0
	GenerateMissing     UpdateStrategy = 1
	GenerateExpired     UpdateStrategy = 2
	GenerateNewerConfig UpdateStrategy = 4
	GenerateAlways      UpdateStrategy = 8
)
