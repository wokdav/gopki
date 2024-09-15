package db

import (
	"testing"
	"time"

	"github.com/wokdav/gopki/generator/cert"
	"github.com/wokdav/gopki/generator/config"
	v1 "github.com/wokdav/gopki/generator/config/v1"
)

type InMemoryDatabase struct {
	entities map[string]DbEntity
	profiles map[string]config.CertificateProfile
}

func (db *InMemoryDatabase) Open() error {
	db.entities = make(map[string]DbEntity)
	db.profiles = make(map[string]config.CertificateProfile)
	return nil
}

func (db *InMemoryDatabase) Close() error {
	db.entities = nil
	db.profiles = nil
	return nil
}

func (db *InMemoryDatabase) PutEntity(entity DbEntity) error {
	db.entities[entity.Config.Alias] = entity
	return nil
}

func (db *InMemoryDatabase) GetEntity(alias string) *DbEntity {
	if entity, ok := db.entities[alias]; ok {
		return &entity
	}
	return nil
}

func (db *InMemoryDatabase) NumEntities() int {
	return len(db.entities)
}

func (db *InMemoryDatabase) RootEntities() []string {
	var roots []string
	for alias, entity := range db.entities {
		if entity.Config.Issuer == "" {
			roots = append(roots, alias)
		}
	}
	return roots
}

func (db *InMemoryDatabase) GetSubscribers(alias string) []string {
	var subscribers []string
	for sub, entity := range db.entities {
		if entity.Config.Issuer == alias {
			subscribers = append(subscribers, sub)
		}
	}
	return subscribers
}

func (db *InMemoryDatabase) AddProfile(profile config.CertificateProfile) error {
	db.profiles[profile.Name] = profile
	return nil
}

func (db *InMemoryDatabase) GetProfile(alias string) *config.CertificateProfile {
	if profile, ok := db.profiles[alias]; ok {
		return &profile
	}
	return nil
}

var simpleEntity = DbEntity{
	Config: config.CertificateContent{
		Alias: "simple",
	},
}

var simpleSubEntity = DbEntity{
	Config: config.CertificateContent{
		Alias:  "simple",
		Issuer: "issuer",
	},
}

var simpleIssuerEntity = DbEntity{
	Config: config.CertificateContent{
		Alias: "issuer",
	},
}

var simpleProfile = config.CertificateProfile{
	Name: "simple",
}

func TestNeedsUpdateAlways(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	db.PutEntity(simpleEntity)

	if needsUpdate(&db, UpdateAll, simpleEntity.Config.Alias) != true {
		t.Error("should be updated")
	}
}

func TestNeedsUpdateNewerIssuer(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	root := simpleIssuerEntity
	sub := simpleSubEntity

	root.LastBuild = time.Now()
	sub.LastBuild = root.LastBuild

	db.PutEntity(root)
	db.PutEntity(sub)

	if needsUpdate(&db, UpdateNewerConfig, simpleEntity.Config.Alias) == true {
		t.Error("should not be updated")
	}

	sub.LastBuild = time.Now().AddDate(0, 0, -1)
	db.PutEntity(sub)
	if needsUpdate(&db, UpdateNewerConfig, simpleEntity.Config.Alias) != true {
		t.Error("should be updated")
	}

}

func TestNeedsUpdateNewerConfig(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	e := simpleEntity
	e.LastBuild = time.Now().AddDate(0, 0, -1)
	e.LastConfigUpdate = time.Now()

	db.PutEntity(e)

	if needsUpdate(&db, UpdateNewerConfig, e.Config.Alias) != true {
		t.Error("should be updated")
	}
}

func TestNeedsUpdateCertExpired(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	e := simpleEntity
	e.Config.Validity.Until = time.Now().AddDate(-1, 0, -1)
	e.BuildArtifact.Certificate = &cert.Certificate{}
	e.BuildArtifact.Certificate.TBSCertificate.Validity.NotAfter = time.Now().AddDate(-1, 0, 0)

	db.PutEntity(e)

	if needsUpdate(&db, UpdateExpired, e.Config.Alias) == true {
		t.Error("should not be updated")
	}
}

func TestNeedsUpdateMissingCert(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	e := simpleEntity
	e.BuildArtifact.Certificate = nil

	db.PutEntity(e)

	if needsUpdate(&db, UpdateMissing, e.Config.Alias) != true {
		t.Error("should be updated")
	}
}

func TestIsConsistent(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	db.PutEntity(simpleEntity)

	if IsConsistent(&db) != true {
		t.Error("should be consistent")
	}
}

func TestIsNotConsisten(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	db.PutEntity(simpleSubEntity)

	if IsConsistent(&db) == true {
		t.Error("should not be consistent")
	}
}

func TestValidateUnknownProfile(t *testing.T) {
	db := InMemoryDatabase{}
	db.Open()
	defer db.Close()

	e := simpleEntity
	e.Config.Profile = "unknown"

	if err := validateAndMerge(&db, &e); err == nil {
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
	e := simpleEntity
	e.Config.Profile = "simpleProfile"
	e.Config.Subject, err = config.ParseRDNSequence("CN=Test")
	if err != nil {
		t.Fatal(err)
	}

	if err := validateAndMerge(&db, &e); err == nil {
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

	e := simpleEntity
	e.Config.Profile = simpleProfile.Name

	err := validateAndMerge(&db, &e)
	if err != nil {
		t.Fatal(err)
	}

	if len(e.Config.Extensions) != 1 {
		t.Fatal("extension not merged")
	}
}
