package db

import (
	"testing"
	"time"

	"github.com/wokdav/gopki/generator/cert"
	"github.com/wokdav/gopki/generator/config"
	v1 "github.com/wokdav/gopki/generator/config/v1"
)

type InMemoryDatabase struct {
	//entities  map[string]DbEntity
	configs   map[string]config.CertificateContent
	artifacts map[string]BuildArtifact
	metadata  map[string]Metadata
	profiles  map[string]config.CertificateProfile
}

func (db *InMemoryDatabase) Open() error {
	db.configs = make(map[string]config.CertificateContent)
	db.artifacts = make(map[string]BuildArtifact)
	db.metadata = make(map[string]Metadata)
	db.profiles = make(map[string]config.CertificateProfile)
	return nil
}

func (db *InMemoryDatabase) Close() error {
	db.configs = nil
	db.artifacts = nil
	db.metadata = nil
	db.profiles = nil
	return nil
}

func (db *InMemoryDatabase) PutConfig(alias string, cfg config.CertificateContent) error {
	_, existed := db.configs[alias]
	db.configs[alias] = cfg

	if existed {
		meta := db.metadata[alias]
		meta.LastConfigUpdate = time.Now()
		db.metadata[alias] = meta
	} else {
		db.artifacts[alias] = BuildArtifact{}
		db.metadata[alias] = Metadata{
			LastConfigUpdate: time.Now(),
		}
	}

	return nil
}

func (db *InMemoryDatabase) GetConfig(alias string) (*config.CertificateContent, error) {
	out, ok := db.configs[alias]
	if !ok {
		return nil, nil
	}
	return &out, nil
}

func (db *InMemoryDatabase) PutBuildArtifact(alias string, artifact BuildArtifact) error {
	db.artifacts[alias] = artifact
	if artifact.Certificate != nil {
		meta := db.metadata[alias]
		meta.LastBuild = time.Now()
		db.metadata[alias] = meta
	}

	return nil
}

func (db *InMemoryDatabase) GetBuildArtifact(alias string) (*BuildArtifact, error) {
	out, ok := db.artifacts[alias]
	if !ok {
		return nil, nil
	}

	return &out, nil
}

func (db *InMemoryDatabase) GetMetadata(alias string) (*Metadata, error) {
	out, ok := db.metadata[alias]
	if !ok {
		return nil, nil
	}

	return &out, nil
}

// only since this is a test db
func (db *InMemoryDatabase) PutMetadata(alias string, meta Metadata) error {
	db.metadata[alias] = meta
	return nil
}

func (db *InMemoryDatabase) Delete(alias string) error {
	delete(db.configs, alias)
	delete(db.artifacts, alias)
	delete(db.metadata, alias)
	return nil
}

func (db *InMemoryDatabase) NumEntities() int {
	return len(db.configs)
}

func (db *InMemoryDatabase) RootEntities() []string {
	var roots []string
	for alias, cfg := range db.configs {
		if cfg.Issuer == "" {
			roots = append(roots, alias)
		}
	}
	return roots
}

func (db *InMemoryDatabase) GetSubscribers(alias string) []string {
	var subscribers []string
	for sub, cfg := range db.configs {
		if cfg.Issuer == alias {
			subscribers = append(subscribers, sub)
		}
	}
	return subscribers
}

func (db *InMemoryDatabase) AddProfile(profile config.CertificateProfile) error {
	db.profiles[profile.Name] = profile
	return nil
}

func (db *InMemoryDatabase) GetProfile(alias string) (*config.CertificateProfile, error) {
	if profile, ok := db.profiles[alias]; ok {
		return &profile, nil
	}
	return nil, nil
}

var simpleConfig = config.CertificateContent{
	Alias: "simple",
}

var simpleSubConfig = config.CertificateContent{
	Alias:  "simple",
	Issuer: "issuer",
}

var simpleIssuerConfig = config.CertificateContent{
	Alias: "issuer",
}

var simpleProfile = config.CertificateProfile{
	Name: "simple",
}

var minimumBuildableConfig = config.CertificateContent{
	Alias: "test",
}

func TestNeedsUpdateAlways(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	db.PutConfig(simpleConfig.Alias, simpleConfig)

	if needsUpdate(&db, UpdateAll, simpleConfig.Alias, nil) != true {
		t.Error("should be updated")
	}
}

func TestNeedsUpdateNewerIssuer(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	root := simpleIssuerConfig
	sub := simpleSubConfig

	rootMeta := Metadata{LastBuild: time.Now()}
	subMeta := Metadata{LastBuild: rootMeta.LastBuild}

	db.PutConfig(root.Alias, root)
	db.PutConfig(sub.Alias, sub)

	db.PutMetadata(root.Alias, rootMeta)
	db.PutMetadata(sub.Alias, subMeta)

	if needsUpdate(&db, UpdateNewerConfig, simpleConfig.Alias, nil) == true {
		t.Error("should not be updated")
	}

	subMeta.LastBuild = time.Now().AddDate(0, 0, -1)
	db.PutMetadata(sub.Alias, subMeta)
	if needsUpdate(&db, UpdateNewerConfig, simpleConfig.Alias, nil) != true {
		t.Error("should be updated")
	}

}

func TestNeedsUpdateNewerConfig(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	db.PutConfig(simpleConfig.Alias, simpleConfig)
	meta := Metadata{
		LastBuild:        time.Now().AddDate(0, 0, -1),
		LastConfigUpdate: time.Now(),
	}

	db.PutMetadata(simpleConfig.Alias, meta)

	if needsUpdate(&db, UpdateNewerConfig, simpleConfig.Alias, nil) != true {
		t.Error("should be updated")
	}
}

func TestNeedsUpdateCertExpired(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	cfg := simpleConfig
	cfg.Validity.Until = time.Now().AddDate(-1, 0, -1)
	build := BuildArtifact{
		Certificate: &cert.Certificate{},
	}

	build.Certificate.TBSCertificate.Validity.NotAfter = time.Now().AddDate(-1, 0, 0)

	db.PutConfig(cfg.Alias, cfg)
	db.PutBuildArtifact(cfg.Alias, build)

	if needsUpdate(&db, UpdateExpired, cfg.Alias, nil) == true {
		t.Error("should not be updated")
	}
}

func TestNeedsUpdateMissingCert(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	build := BuildArtifact{}
	build.Certificate = nil

	db.PutConfig(simpleConfig.Alias, simpleConfig)
	db.PutBuildArtifact(simpleConfig.Alias, build)

	if needsUpdate(&db, UpdateMissing, simpleConfig.Alias, nil) != true {
		t.Error("should be updated")
	}
}

func TestIsConsistent(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	db.PutConfig(simpleConfig.Alias, simpleConfig)

	if IsConsistent(&db) != true {
		t.Error("should be consistent")
	}
}

func TestIsNotConsisten(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	db.PutConfig(simpleSubConfig.Alias, simpleSubConfig)

	if IsConsistent(&db) == true {
		t.Error("should not be consistent")
	}
}

func TestValidateUnknownProfile(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	cfg := simpleConfig
	cfg.Profile = "unknown"
	db.PutConfig(cfg.Alias, cfg)

	if _, err := validateAndMerge(&db, cfg.Alias); err == nil {
		t.Error("should not be valid")
	}
}

func TestValidateProfileViolation(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	p := simpleProfile
	p.SubjectAttributes.Attributes = append(
		p.SubjectAttributes.Attributes,
		config.ProfileSubjectAttribute{Attribute: "CN", Optional: false},
	)

	var err error
	cfg := simpleConfig
	cfg.Profile = "simpleProfile"
	cfg.Subject, err = config.ParseRDNSequence("CN=Test")
	if err != nil {
		t.Fatal(err)
	}

	db.PutConfig(cfg.Alias, cfg)

	if _, err := validateAndMerge(&db, cfg.Alias); err == nil {
		t.Error("should not be valid")
	}
}

func TestValidateMergeExtensions(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	ext := v1.SubjectKeyIdentifier{Content: "hash"}
	extProf := config.ProfileExtension{ExtensionConfig: ext}

	p := simpleProfile
	p.Extensions = append(p.Extensions, extProf)
	db.AddProfile(p)

	cfg := simpleConfig
	cfg.Profile = simpleProfile.Name

	db.PutConfig(cfg.Alias, cfg)

	newcfg, err := validateAndMerge(&db, cfg.Alias)
	if err != nil {
		t.Fatal(err)
	}

	if len(newcfg.Extensions) != 1 {
		t.Fatal("extension not merged")
	}
}

func TestAddAndSign(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	artifact, err := AddAndSign(&db,
		minimumBuildableConfig,
		false,
	)

	if err != nil {
		t.Fatal(err)
	}

	if artifact == nil {
		t.Fatal("artifact should not be nil")
	}

	if artifact.Certificate == nil {
		t.Fatal("certificate should not be nil")
	}

	if artifact.PrivateKey == nil {
		t.Fatal("private key should not be nil")
	}
}

//TODO: Test that checks for a correct error message when trying to sign with a public key in a request
