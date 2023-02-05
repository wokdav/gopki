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
	UpdateNone        UpdateStrategy = 0
	UpdateMissing     UpdateStrategy = 1
	UpdateExpired     UpdateStrategy = 2
	UpdateNewerConfig UpdateStrategy = 4
	UpdateAll         UpdateStrategy = 8
)
