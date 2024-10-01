// Generic certificate database package
//
// This provides functionality to read certificate configurations
// and generated content from any source.
//
// At this point in time it's tailored to one-shot filesystem generation,
// but this will change, once other sources (like e.g. REST-APIs) are added.
package db

import (
	"bytes"
	"crypto"
	"errors"
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
	UpdateChanged     UpdateStrategy = 8
	UpdateAll         UpdateStrategy = 16
)

type ChangeType uint8

const (
	ChangeNone ChangeType = iota
	ChangeCreate
	ChangeReplace
	ChangeDelete
)

type Database interface {
	// Prepare the database object to be able to run queries on
	Open() error

	// Close all handles and free all resources for this database
	Close() error

	// Return the number of certificate configurations we know of
	// and we know how to build
	NumEntities() int

	// Return all aliases that do not have an issuer different from
	// themselves
	RootEntities() []string

	// Return all aliases that have the given alias as an issuer
	GetSubscribers(string) []string

	// Add a Certificate Profile to the Database.
	// When this command terminates, it is expected to have the profile
	// ready to use.
	AddProfile(config.CertificateProfile) error

	// Return the profile under the given name.
	// If no such profile exists, return nil without returning an error.
	// Only return an error here if an actual error happens inside the
	// database.
	GetProfile(string) (*config.CertificateProfile, error)

	// Add a Certificate Configuration to the Database.
	// When this command terminates, it is expected to have the Configuration
	// ready to use.
	//
	// Important: Writing a Configuration must also update the metadata internally
	// where applicable.
	//
	PutConfig(string, config.CertificateContent) error

	// Return the configuration for the given alias.
	// If the alias is not known to the database, nil shall be returned without an error.
	// Only return an error here if an actual error happens inside the
	// database.
	GetConfig(string) (*config.CertificateContent, error) // if not present, both are nil

	// Add a Certificate Configuration to the Database.
	// When this command terminates, it is expected to have the Configuration
	// ready to use.
	//
	// Important: Writing an Artifact must also update the metadata internally
	// where applicable.
	PutBuildArtifact(string, BuildArtifact) error

	// Return the Artifact for the given alias.
	// If the alias is not known to the database, nil shall be returned without an error.
	// Only return an error here if an actual error happens inside the
	// database.
	//
	// If the Database knows of the entity under the given alias, but it
	// has not Build Artifact, then an empty Build Artifact shall be returned.
	// A nil artifact suggests that the alias is unknown.
	GetBuildArtifact(string) (*BuildArtifact, error)

	// Return the Metadata for the given alias.
	// If the alias is not known to the database, nil shall be returned without an error.
	// Only return an error here if an actual error happens inside the
	// database.
	GetMetadata(string) (*Metadata, error)

	// TODO: If we delete a CA, should we also delete everything below it?
	// Delete all data corresponding to the alias. After this command terminates
	// it is expected that the Database is in a state as if the entity has never
	// existed.
	//
	// This applies especially to Configs, Metadata and Build Artifacts.
	Delete(alias string) error
}

type Metadata struct {
	LastBuild        time.Time
	LastConfigHash   []byte
	LastConfigUpdate time.Time
}

type BuildArtifact struct {
	Certificate *cert.Certificate
	PrivateKey  crypto.PrivateKey
	Request     *cert.CertificateRequest
}

func needsUpdate(backend Database, strat UpdateStrategy, alias string, cfg *config.CertificateContent) bool {
	var err error
	if cfg == nil {
		cfg, err = backend.GetConfig(alias)
		if err != nil {
			logging.Errorf("db: entity '%s' not found. error during fetch: %v", alias, err)
			return false
		}
		if cfg == nil {
			logging.Warningf("db: entity '%s' not found. no update possible", alias)
			return false
		}
	}

	if strat&UpdateAll > 0 {
		logging.Debugf("%v needs update. reason: GenerateAlways is set", cfg.Alias)
		return true
	}

	issuerCfg, err := backend.GetConfig(cfg.Issuer)
	if err != nil {
		logging.Errorf("db: issuer of '%s' not found. error during fetch: %v", alias, err)
		return false
	}

	meta, err := backend.GetMetadata(alias)
	if err != nil {
		logging.Errorf("db: metadata of '%s' not found. error during fetch: %v", alias, err)
		return false
	}

	issuerMeta, err := backend.GetMetadata(cfg.Issuer)
	if err != nil {
		logging.Errorf("db: metadata for issuer of '%s' not found. error during fetch: %v", alias, err)
		return false
	}

	if strat != UpdateNone && issuerCfg != nil && issuerMeta.LastBuild.After(meta.LastBuild) {
		logging.Debugf("%v needs update. reason: issuer %v was updated later", alias, issuerCfg.Alias)
		return true
	}

	if strat&UpdateNewerConfig > 0 && meta.LastConfigUpdate.After(meta.LastBuild) {
		logging.Debugf("%v needs update. reason: config was updated", cfg.Alias)
		return true
	}

	build, err := backend.GetBuildArtifact(alias)
	if err != nil {
		logging.Errorf("db: build artifact for '%s' not found. error during fetch: %v", alias, err)
	}

	if strat&UpdateExpired > 0 && build.Certificate != nil &&
		build.Certificate.TBSCertificate.Validity.NotAfter.Before(time.Now()) &&
		cfg.Validity.Until.After(time.Now()) {
		logging.Debugf("%v needs update. reason: certificate is expired", cfg.Alias)
		return true
	}

	if strat&UpdateMissing > 0 && (build.Certificate == nil || build.PrivateKey == nil) {
		logging.Debugf("%v needs update. reason: certificate or private key is missing", cfg.Alias)
		return true
	}

	if meta != nil {
		logging.Debugf("configHash: %v, lastConfigHash: %v", cfg.HashSum(), meta.LastConfigHash)
	}

	if strat&UpdateChanged > 0 && meta.LastConfigHash != nil && !bytes.Equal(meta.LastConfigHash, cfg.HashSum()) {
		logging.Debugf("%v needs update. reason: current config differs from last applied config", cfg.Alias)
		return true
	}

	return false
}

// TODO: this should take a CertificateContent as an argument
func validateAndMerge(backend Database, alias string) (*config.CertificateContent, error) {
	cfg, err := backend.GetConfig(alias)
	if err != nil {
		return nil, fmt.Errorf("db: can't get config for alias '%v': %v", alias, err)
	}

	if cfg == nil {
		return nil, fmt.Errorf("db: alias '%v' does not exist", alias)
	}

	if len(cfg.Profile) == 0 {
		return cfg, nil
	}

	profile, err := backend.GetProfile(cfg.Profile)
	if err != nil {
		return nil, fmt.Errorf("db: error getting profile '%v': %v", cfg.Profile, err)
	}

	if profile == nil {
		return nil, fmt.Errorf("db: '%s' references unknown profile '%s'",
			cfg.Alias, cfg.Profile)
	}

	if !config.Validate(*profile, *cfg) {
		return nil, fmt.Errorf("db: '%s' does not validate against profile '%s'",
			cfg.Alias, cfg.Profile)
	}

	logging.Debug("validation was successful")

	newContent, err := config.Merge(*profile, *cfg)
	if err != nil {
		return nil, fmt.Errorf(
			"db: '%s' could not be merged with profile '%s': %v",
			cfg.Alias, cfg.Profile, err)
	}

	return newContent, nil
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

type Change struct {
	Alias           string
	EffectiveConfig config.CertificateContent
	Change          ChangeType
}

type ChangeList []Change

func PlanBulkUpdate(backend Database, strat UpdateStrategy) (ChangeList, error) {
	changes := make(ChangeList, 0, 1024)

	todo := make([]string, 0, 1024)
	todo = append(todo, backend.RootEntities()...)

	//hack to quickly find whether we update a specific alias
	//so that we can check, if we plan on updating the issuer
	//since we then need to update the issued certs as well
	updatedAliases := make(map[string]bool, 1024)

	i := 0
	for i < len(todo) {
		currentEntity := todo[i]
		i++
		logging.Debugf("currently checking %v (item %v/%v of our to-do list)", currentEntity, i, len(todo))

		//add subscribers to todo list
		subs := backend.GetSubscribers(currentEntity)
		logging.Debugf("%v signs %v more certificates. adding them to our to-do list", currentEntity, len(subs))
		todo = append(todo, subs...)

		//validate and merge profile if applicable
		newCfg, err := validateAndMerge(backend, currentEntity)
		if err != nil {
			return nil, err
		}

		var update bool
		if _, ok := updatedAliases[newCfg.Issuer]; ok {
			logging.Debugf("Entity '%v' will be update, because we plan on updating it's issuer", currentEntity)
			update = true
		} else {
			update = needsUpdate(backend, strat, currentEntity, newCfg)
		}

		if !update {
			logging.Debugf("Entity '%v' does not need an update", currentEntity)
		} else {
			updatedAliases[newCfg.Alias] = true
			changeTmp := Change{
				Alias:           currentEntity,
				EffectiveConfig: *newCfg,
			}

			build, err := backend.GetBuildArtifact(currentEntity)
			if err != nil {
				return nil, fmt.Errorf("db: can't fetch build artifact for '%v': %v", currentEntity, err)
			}

			if build.Certificate != nil {
				logging.Infof("Entity '%v' will be overwritten", currentEntity)
				changeTmp.Change = ChangeReplace
			} else {
				logging.Infof("Entity '%v' will be created", currentEntity)
				changeTmp.Change = ChangeCreate
			}

			changes = append(changes, changeTmp)
		}
	}

	return changes, nil
}

func GenerateArtifacts(backend Database, alias string) (*BuildArtifact, error) {
	var ctx *cert.CertificateContext
	var issuerCtx cert.IssuerContext
	var err error

	subjectConfig, err := backend.GetConfig(alias)
	if err != nil {
		return nil, err
	}

	if subjectConfig == nil {
		return nil, fmt.Errorf("db: alias '%v' does not exist", alias)
	}

	subjectArtifact, err := backend.GetBuildArtifact(alias)
	if err != nil {
		return nil, err
	}

	if subjectArtifact == nil {
		subjectArtifact = &BuildArtifact{}
	}

	logging.Debugf("generating new certificate body for %v", alias)
	//TODO: This possibly generates a key. if it does the request gets outdated
	ctx, err = generator.BuildCertBody(*subjectConfig,
		subjectArtifact.PrivateKey, subjectArtifact.Request)
	if err != nil {
		return nil, err
	}

	if len(subjectConfig.Issuer) > 0 {
		logging.Debugf("issuer property for %v is set", subjectConfig.Alias)
		issuerArtifact, err := backend.GetBuildArtifact(subjectConfig.Issuer)
		if err != nil {
			return nil, err
		}

		issuerCtx = cert.IssuerContext{
			PrivateKey:   issuerArtifact.PrivateKey,
			PublicKeyRaw: issuerArtifact.Certificate.TBSCertificate.PublicKey.PublicKey.Bytes,
			IssuerDn:     issuerArtifact.Certificate.TBSCertificate.Subject,
		}
	} else {
		issuerCtx = cert.AsIssuer(*ctx)
	}

	ctx.Issuer = &issuerCtx

	//sign
	logging.Debugf("signing certificate for %v", subjectConfig.Alias)
	crt, err := generator.SignCertBody(ctx, *subjectConfig)
	if err != nil {
		return nil, err
	}

	return &BuildArtifact{
		Certificate: crt,
		PrivateKey:  ctx.PrivateKey,
		Request:     subjectArtifact.Request,
	}, nil
}

func BulkUpdate(backend Database, changes ChangeList) (int, error) {
	certsGenerated := 0

	for _, change := range changes {
		if change.Change&(ChangeCreate|ChangeReplace) == 0 {
			continue
		}

		err := backend.PutConfig(change.Alias, change.EffectiveConfig)
		if err != nil {
			return certsGenerated, err
		}

		artifact, err := GenerateArtifacts(backend, change.Alias)
		if err != nil {
			return certsGenerated, err
		}

		err = backend.PutBuildArtifact(change.Alias, *artifact)
		if err != nil {
			return certsGenerated, err
		}
		certsGenerated++
	}

	logging.Infof("generation finished. %d certs generated", certsGenerated)
	return certsGenerated, nil
}

func AddAndSign(backend Database, config config.CertificateContent, overwrite bool) (*BuildArtifact, error) {
	if len(config.Alias) == 0 {
		return nil, errors.New("no alias given")
	}

	existingCfg, err := backend.GetConfig(config.Alias)
	if err != nil {
		return nil, fmt.Errorf("can't fetch alias '%v': %v", config.Alias, err)
	}

	if existingCfg != nil && !overwrite {
		return nil, fmt.Errorf("alias '%v' already exists in database", config.Alias)
	}

	err = backend.PutConfig(config.Alias, config)
	if err != nil {
		return nil, err
	}

	//merge
	newcfg, err := validateAndMerge(backend, config.Alias)
	if err != nil {
		return nil, err
	}

	//TODO: doing this 2 times just for validateAndMerge to look it up in DB is stupid
	err = backend.PutConfig(config.Alias, *newcfg)
	if err != nil {
		return nil, err
	}

	//sign
	artifact, err := GenerateArtifacts(backend, config.Alias)
	if err != nil {
		return nil, err
	}

	err = backend.PutBuildArtifact(config.Alias, *artifact)
	if err != nil {
		return nil, err
	}

	return artifact, nil
}
