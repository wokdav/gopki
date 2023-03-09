// Generic certificate database package
//
// This provides functionality to read certificate configurations
// and generated content from any source.
//
// At this point in time it's tailored to one-shot filesystem generation,
// but this will change, once other sources (like e.g. REST-APIs) are added.
package db

import (
	"crypto"
	"fmt"
	"time"

	"github.com/wokdav/gopki/generator"
	"github.com/wokdav/gopki/generator/cert"
	"github.com/wokdav/gopki/generator/config"
	"github.com/wokdav/gopki/logging"
)

type UpdateStrategy uint8

const (
	UpdateNone        UpdateStrategy = 0
	UpdateMissing     UpdateStrategy = 1
	UpdateExpired     UpdateStrategy = 2
	UpdateNewerConfig UpdateStrategy = 4
	UpdateAll         UpdateStrategy = 8
)

type ConfigStore interface {
	Put(config.CertificateContent) error
	Get(string) *config.CertificateContent
}

type CertStore interface {
	Put(string, BuildArtifact) error
	Get(string) *BuildArtifact
}

type Database interface {
	Open() error
	Close() error

	PutEntity(DbEntity) error
	GetEntity(string) *DbEntity
	NumEntities() int

	RootEntities() []string
	GetSubscribers(string) []string

	AddProfile(config.CertificateProfile) error
	GetProfile(string) *config.CertificateProfile
}

type BuildArtifact struct {
	Certificate *cert.Certificate
	PrivateKey  crypto.PrivateKey
}

type DbEntity struct {
	LastBuild        time.Time
	Config           config.CertificateContent
	LastConfigUpdate time.Time
	BuildArtifact    BuildArtifact
}

func needsUpdate(backend Database, strat UpdateStrategy, alias string) bool {
	entity := backend.GetEntity(alias)
	if entity == nil {
		logging.Warningf("db: entity '%s' not found. no update possible", alias)
		return false
	}

	if strat&UpdateAll > 0 {
		logging.Debugf("%v needs update. reson: GenerateAlways is set", entity.Config.Alias)
		return true
	}

	issuer := backend.GetEntity(entity.Config.Issuer)
	if strat != UpdateNone && issuer != nil && issuer.LastBuild.After(entity.LastBuild) {
		logging.Debugf("%v needs update. reson: issuer %v was updated later", entity, issuer)
		return true
	}

	if strat&UpdateNewerConfig > 0 && entity.LastConfigUpdate.After(entity.LastBuild) {
		logging.Debugf("%v needs update. reson: config was updated", entity)
		return true
	}

	if strat&UpdateExpired > 0 && entity.BuildArtifact.Certificate != nil &&
		entity.BuildArtifact.Certificate.TBSCertificate.Validity.NotAfter.Before(time.Now()) &&
		entity.Config.ValidUntil.After(time.Now()) {
		logging.Debugf("%v needs update. reson: certificate is expired", entity)
		return true
	}

	if strat&UpdateMissing > 0 && (entity.BuildArtifact.Certificate == nil ||
		entity.BuildArtifact.PrivateKey == nil) {
		logging.Debugf("%v needs update. reson: certificate or private key is missing", entity)
		return true
	}

	return false
}

func validateAndMerge(backend Database, entity *DbEntity) error {
	if len(entity.Config.Profile) == 0 {
		return nil
	}

	profile := backend.GetProfile(entity.Config.Profile)
	if profile == nil {
		return fmt.Errorf("db: '%s' references unknown profile '%s'",
			entity.Config.Alias, entity.Config.Profile)
	}

	if !config.Validate(*profile, entity.Config) {
		return fmt.Errorf("db: '%s' does not validate against profile '%s'",
			entity.Config.Alias, entity.Config.Profile)
	}

	logging.Debug("validation was successful")

	newContent, err := config.Merge(*profile, entity.Config)
	if err != nil {
		return fmt.Errorf(
			"db: '%s' could not be merged with profile '%s': %v",
			entity.Config.Alias, entity.Config.Profile, err)
	}

	entity.Config = *newContent

	return nil
}

func IsConsistent(backend Database) bool {
	//check if all referenced issuers exist
	numEntries := 0
	todo := make([]string, 0, backend.NumEntities())
	todo = append(todo, backend.RootEntities()...)

	i := 0
	for i < len(todo) {
		numEntries++
		currentEntity := todo[i]
		todo = append(todo, backend.GetSubscribers(currentEntity)...)

		i++
	}

	if numEntries != backend.NumEntities() {
		logging.Errorf("db: inconsistent database. %v found through certificate chain, but %v exist in total",
			numEntries, backend.NumEntities())
	}

	return numEntries == backend.NumEntities()
}

func Update(backend Database, strat UpdateStrategy) (int, error) {
	todo := make([]string, 0, 1024)
	todo = append(todo, backend.RootEntities()...)
	certsGenerated := 0

	i := 0
	for i < len(todo) {
		currentEntity := todo[i]
		i++
		logging.Debugf("currently working on %v (item %v/%v of our to-do list)", currentEntity, i, len(todo))

		//add subscribers to todo list
		subs := backend.GetSubscribers(currentEntity)
		logging.Debugf("%v signs %v more certificates. adding them to our to-do list", currentEntity, len(subs))
		todo = append(todo, subs...)

		entityObj := backend.GetEntity(currentEntity)

		//check if we need to upgrade
		update := needsUpdate(backend, strat, entityObj.Config.Alias)

		var ctx *cert.CertificateContext
		var issuerCtx cert.IssuerContext
		var issuerEntity *DbEntity

		var err error
		if !update {
			logging.Debugf("%v does not need an update", currentEntity)
			continue
		}

		//validate and merge profile if applicable
		if err = validateAndMerge(backend, entityObj); err != nil {
			return certsGenerated, err
		}

		logging.Debugf("generating new certificate body for %v", currentEntity)
		ctx, err = generator.BuildCertBody(entityObj.Config,
			entityObj.BuildArtifact.PrivateKey)
		if err != nil {
			return certsGenerated, err
		}

		if len(entityObj.Config.Issuer) > 0 {
			logging.Debugf("issuer property for %v is set", currentEntity)
			issuerEntity = backend.GetEntity(entityObj.Config.Issuer)
			issuerCtx = cert.IssuerContext{
				PrivateKey:   issuerEntity.BuildArtifact.PrivateKey,
				PublicKeyRaw: issuerEntity.BuildArtifact.Certificate.TBSCertificate.PublicKey.PublicKey.Bytes,
				IssuerDn:     issuerEntity.BuildArtifact.Certificate.TBSCertificate.Issuer,
			}
		} else {
			issuerCtx = cert.AsIssuer(*ctx)
		}

		ctx.Issuer = &issuerCtx

		//sign
		logging.Debugf("signing certificate for %v", currentEntity)
		crt, err := generator.SignCertBody(ctx, entityObj.Config)
		if err != nil {
			return certsGenerated, err
		}

		entityObj.BuildArtifact = BuildArtifact{
			Certificate: crt,
			PrivateKey:  ctx.PrivateKey,
		}

		entityObj.LastBuild = time.Now()
		backend.PutEntity(*entityObj)
		certsGenerated++
	}

	logging.Infof("generation finished. %d certs generated", certsGenerated)
	return certsGenerated, nil
}
