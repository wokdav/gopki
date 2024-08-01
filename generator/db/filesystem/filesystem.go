// Database implementation for filesystems.
//
// This package allows walking recursively through a given path,
// collecting all configurations and profiles and generate certificates accordingly.
//
// To allow this in a convenient way, this package treats some elements of the
// configuration in a special way:
//
//   - Explicitly set aliases are ignored.
//
//   - The alias will be set to the config file base name
//     Example: Reading a config file in foo/bar/baz.yaml will result in the alias baz
//
//   - For each generated certificate, the certificate and the key will be stored
//     together in one .pem file next to the config file. To use the example above,
//     the certificate/key will be written to foo/bar/baz.pem
//
// This also means, that an alias must be unique, regardless whether it is explicitly set,
// or inherited from the filename. So either the filenames themselves must be unique or
// ambiguous config file names must set their alias to a unique one.
//
// This package also provides an in-memory file system abstraction for testing.
package filesystem

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing/fstest"
	"time"

	"github.com/wokdav/gopki/generator/cert"
	"github.com/wokdav/gopki/generator/config"
	"github.com/wokdav/gopki/generator/db"
	"github.com/wokdav/gopki/logging"

	_ "github.com/wokdav/gopki/generator/config/v1"
)

const writePermissions fs.FileMode = 0644

// Wrappers for fs.FS with some write functionality.
// If go adds this feature to fs.Fs, we can remove this code.
// It is also a superset of the fs.StatFs interface.
type Filesystem interface {
	FS() fs.FS
	WriteFile(name string, content []byte) error
	Stat(name string) (os.FileInfo, error)
}

type mapfs struct {
	fsobj fs.FS
	m     map[string]*fstest.MapFile
}

func (m mapfs) FS() fs.FS {
	return m.fsobj
}

func (m mapfs) Stat(name string) (os.FileInfo, error) {
	return fstest.MapFS(m.m).Stat(name)
}

func (m mapfs) WriteFile(name string, content []byte) error {
	m.m[name] = &fstest.MapFile{
		Data:    content,
		Mode:    writePermissions,
		ModTime: time.Now(),
	}
	return nil
}

// Generates a new [filesystem.Filesystem] based on [fstest.MapFS]. It always adds a working directory "."
func NewMapFs(m fstest.MapFS) Filesystem {
	switch m {
	case nil:
		f := fstest.MapFS{".": &fstest.MapFile{Mode: 0777 | fs.ModeDir}}
		return mapfs{m: f, fsobj: fstest.MapFS(f)}
	default:
		return mapfs{m, fstest.MapFS(m)}
	}
}

type nativefs struct {
	basepath string
	fsObj    fs.FS
}

func (n nativefs) FS() fs.FS {
	return n.fsObj
}

func (n nativefs) Stat(name string) (os.FileInfo, error) {
	return os.Stat(n.basepath + string(os.PathSeparator) + name)
}

func (n nativefs) WriteFile(name string, content []byte) error {
	if filepath.IsAbs(name) {
		return fmt.Errorf("filesystem: '%s' is an absolute path, rather than a part relative to the provided basename", name)
	}
	return os.WriteFile(n.basepath+string(os.PathSeparator)+name, content, writePermissions)
}

// Generates a new [filesystem.Filesystem] based on [os.DirFS], plus some write
// functionality taken from the [os] package.
func NewNativeFs(path string) Filesystem {
	return nativefs{basepath: path, fsObj: os.DirFS(path)}
}

type fsEntity struct {
	*db.DbEntity
	configFile        string
	lastArtifactWrite time.Time
}

// It effectively builds a graph of certificate nodes and issuer-relations as edges.
// This allows building certificate hierarchies without imposing an explicit structure
// on the file system, since everything is derived from the configuration files first.
// Generation can then happen, by going through all root nodes and looking up subscriber
// aliases for each one until all certificates have been added.
type FsDb struct {
	//filesystem fs.FS
	filesystem Filesystem
	entities   map[string]*fsEntity //greedily stores all cert nodes
	profiles   map[string]*config.CertificateProfile

	rootAliases   []string            //aliases of all root certificates
	subscribersOf map[string][]string //gets all subordinate aliases for the key alias
}

// Create a new file system database based on the provided implementation.
// This function pre-allocates about 2K+ KB of arrays to minimize re-allocation,
// so it should be used consciously.
func NewFilesystemDatabase(filesystem Filesystem) db.Database {
	return &FsDb{
		filesystem: filesystem,
		//certNodes must store pointers, because we want to change the content
		entities:      make(map[string]*fsEntity, 1024),
		profiles:      make(map[string]*config.CertificateProfile, 32),
		rootAliases:   make([]string, 0, 128),
		subscribersOf: make(map[string][]string, 1024),
	}
}

func (f fsEntity) artifactFileName() string {
	return f.configFile[:strings.LastIndex(f.configFile, ".")] + ".pem"
}

func (fsdb *FsDb) GetEntity(alias string) *db.DbEntity {
	e, ok := fsdb.entities[alias]
	if !ok {
		return nil
	}
	return e.DbEntity
}

func generateConfigFileNameFor(entity db.DbEntity) string {
	return entity.Config.Alias + ".yaml"
}

// TODO: Import feels so scattered now
// TODO: what if the entity is root? We need to add it to the root list?
func (fsdb *FsDb) PutEntity(entity db.DbEntity) error {
	if len(entity.Config.Alias) == 0 {
		return fmt.Errorf("cannot store entity without alias")
	}

	fsentity, ok := fsdb.entities[entity.Config.Alias]
	if !ok {
		fsentity = &fsEntity{
			DbEntity:   &entity,
			configFile: generateConfigFileNameFor(entity),
		}
		fsdb.entities[entity.Config.Alias] = fsentity
	} else {
		fsentity.DbEntity = &entity
	}

	var err error
	if fsentity.lastArtifactWrite.Before(fsentity.DbEntity.LastBuild) {
		err = fsdb.exportPemFile(*fsentity)
	}

	return err
}

func (fsdb *FsDb) NumEntities() int {
	return len(fsdb.entities)
}

func (fsdb *FsDb) RootEntities() []string {
	return fsdb.rootAliases
}

func (fsdb *FsDb) GetSubscribers(alias string) []string {
	return fsdb.subscribersOf[alias]
}

func (fsdb *FsDb) GetProfile(name string) *config.CertificateProfile {
	return fsdb.profiles[name]
}

func (fsdb *FsDb) AddProfile(profile config.CertificateProfile) error {
	fsdb.profiles[profile.Name] = &profile
	return nil
}

const hashPrefix string = "#HASH:"

func (fsdb *FsDb) exportPemFile(entity fsEntity) error {
	bb := bytes.Buffer{}

	_, err := bb.Write([]byte(hashPrefix + base64.StdEncoding.EncodeToString(entity.Config.HashSum()) + "\n"))
	if err != nil {
		logging.Errorf("error writing pem for %v: %v", entity.Config.Alias, err)
	}

	if entity.BuildArtifact.Certificate != nil {
		err = entity.BuildArtifact.Certificate.WritePem(&bb)
		if err != nil {
			return err
		}
	}
	if entity.BuildArtifact.PrivateKey != nil {
		err = cert.WritePrivateKeyToPem(entity.BuildArtifact.PrivateKey, &bb)
		if err != nil {
			return err
		}
	}
	if entity.BuildArtifact.Request != nil {
		err = entity.BuildArtifact.Request.WritePem(&bb)
		if err != nil {
			return err
		}
	}

	if bb.Len() > 0 {
		err = fsdb.filesystem.WriteFile(
			entity.artifactFileName(),
			bb.Bytes(),
		)
		if err != nil {
			return err
		}
	}

	entity.lastArtifactWrite = time.Now()

	return nil
}

func (fsdb *FsDb) importPem(content []byte) db.BuildArtifact {
	out := db.BuildArtifact{}

	pemFile, err := cert.ReadPem(content)
	if err != nil {
		logging.Infof("pem import failed: %v", err)
	}

	if pemFile.Certificate != nil {
		out.Certificate = pemFile.Certificate
	} else {
		logging.Infof("certificate import failed: no certificate found")
	}

	if pemFile.PrivateKey != nil {
		out.PrivateKey = pemFile.PrivateKey
	} else {
		if pemFile.Request != nil {
			out.Request = pemFile.Request
		} else {
			logging.Infof("private key import failed: no private key or certificate request found")
		}
	}

	return out
}

func (fsdb *FsDb) importCertConfig(certContent config.CertificateContent, configPath string) error {
	logging.Debugf("certificate recognized")

	//default alias is the filename
	if len(certContent.Alias) == 0 {
		newAlias := configPath[strings.LastIndex(configPath, "/")+1 : strings.LastIndex(configPath, ".")]
		certContent.Alias = newAlias
		logging.Debugf("alias is not set. setting it to '%v'", newAlias)
	}

	e, alreadyExists := fsdb.entities[certContent.Alias]
	if alreadyExists && e.configFile != configPath {
		logging.Errorf("alias %s already exists in database", certContent.Alias)
		logging.Errorf("either rename one of these config files to something unique or set a unique alias in the config")

		return fmt.Errorf("alias exists multiple times: %s. ", certContent.Alias)
	}

	if !alreadyExists {
		e = &fsEntity{
			configFile: configPath,
			DbEntity: &db.DbEntity{
				Config: certContent,
			},
		}
	}
	fsdb.entities[certContent.Alias] = e

	//get modtime for config file
	statfs, ok := fsdb.filesystem.FS().(fs.StatFS)
	if ok {
		stat, err := statfs.Stat(configPath)
		if err != nil {
			logging.Warningf("could not get modtime for %v: %v", configPath, err)
		} else {
			e.DbEntity.LastConfigUpdate = stat.ModTime()
		}
	} else {
		logging.Warningf("filesystem does not support statfs. cannot get modtime for %v. updates based on modtimes will be unreliable", configPath)
	}

	//get modtime for cert file
	var readableArtifactFound bool
	var certfiContent []byte
	certFile := e.artifactFileName()
	certfi, err := fsdb.filesystem.FS().Open(certFile)
	if err != nil {
		logging.Debugf("attempt to open %v failed: %v", certFile, err)
	} else {
		certfiContent, err = io.ReadAll(certfi)
		if err != nil {
			logging.Warningf("reading of %v failed: %v", certFile, err)
			certfi.Close()
		} else {
			readableArtifactFound = true
		}

		certfi.Close()
	}

	if readableArtifactFound {
		fi, err := fsdb.filesystem.Stat(certFile)
		if err != nil {
			logging.Warningf("could not get modtime for %v: %v", certFile, err)
		} else {
			e.lastArtifactWrite = fi.ModTime()
		}

		logging.Debugf("attempting to import cert/key for '%v' that we can reuse", certFile)

		//attempt to import certificate and key
		logging.Debugf("attempting to import cert/key for '%v' that we can reuse", certFile)
		e.DbEntity.BuildArtifact = fsdb.importPem(certfiContent)

		hashIx := bytes.Index(certfiContent, []byte(hashPrefix))

		if hashIx != -1 {
			hashEnd := bytes.IndexRune(certfiContent[hashIx:], '\n')
			if hashEnd != -1 {
				hashBytes, err := base64.StdEncoding.DecodeString(string(certfiContent[hashIx:hashEnd]))
				if err != nil {
					logging.Warningf("error decoding config hash for %v: %v", certFile, err)
				} else {
					e.DbEntity.LastConfigHash = hashBytes
				}
			}
		}
	}

	//populate root and subscriber lists
	if !alreadyExists {
		if len(certContent.Issuer) == 0 {
			logging.Debugf("we have a new root certificate. adding it to root list")
			fsdb.rootAliases = append(fsdb.rootAliases, certContent.Alias)
		} else {
			//has issuer? -> remember relation
			logging.Debugf("we have a non-root certificate [issuer alias=%v]", certContent.Issuer)
			_, exists := fsdb.subscribersOf[certContent.Issuer]
			if !exists {
				logging.Debugf("issuer '%v' is unknown (right now), so we initialize the issuer list", certContent.Issuer)
				fsdb.subscribersOf[certContent.Issuer] = make([]string, 0, 64)
			}

			logging.Debugf("'%v' ==is=signed=by==> '%v'", certContent.Alias, certContent.Issuer)
			fsdb.subscribersOf[certContent.Issuer] =
				append(fsdb.subscribersOf[certContent.Issuer], certContent.Alias)
		}
	}
	return nil
}

// Open will walk through the filesystem and collect all config files, building
// the certificate hierarchy.
func ImportFiles(backend db.Database, fsys fs.FS) error {
	logging.Debug("scanning folder for config files")

	fsdb, ok := backend.(*FsDb)
	if !ok {
		//TODO: create fsdb, if not compatible
		return errors.New("invalid database type")
	}

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		logging.Debugf("considering dir entry '%v'", path)
		if err != nil {
			return err
		}

		//directory? pass.
		if d.Type().IsDir() {
			logging.Debugf("skipping. reason: directory")
			return nil
		}

		//name not ending with known config files? pass.
		lname := strings.ToLower(d.Name())
		if !(strings.HasSuffix(lname, ".yaml") || strings.HasSuffix(lname, ".yml") ||
			strings.HasSuffix(lname, ".json")) {
			logging.Debugf("skipping. reason: not a recognized file suffix for yaml/json")
			return nil
		}

		fi, err := fsys.Open(path)
		if err != nil {
			return err
		}
		defer fi.Close()

		cfg, err := config.ParseConfig(fi)
		if err != nil {
			if config.IsErrorUnknownFile(err) {
				logging.Infof("skipping %v, since it is not recognized", d.Name())
			} else {
				logging.Warningf("%v: %v", d.Name(), err)
			}

			return nil
		}

		//do we have a certificate...?
		certContent, ok := cfg.(*config.CertificateContent)
		if ok {
			logging.Debugf("certificate recognized")
			err = fsdb.importCertConfig(*certContent, path)
			if err != nil {
				return err
			}
			return nil
		}

		//...or a profile?
		profileContent, ok := cfg.(*config.CertificateProfile)
		if ok {
			logging.Debugf("profile recognized")
			fsdb.profiles[profileContent.Name] = profileContent
			return nil
		}

		panic(fmt.Errorf("filesystem: file '%s' can neither be casted as a profile nor as a certificate config, even though parsing was successful", path))
	})

	logging.Infof("found %v cert configs (containing %v root configs) and %v cert profiles", len(fsdb.entities), len(fsdb.profiles), len(fsdb.rootAliases))

	return err
}

func (fsdb *FsDb) Open() error {
	err := ImportFiles(fsdb, fsdb.filesystem.FS())
	if err != nil {
		return err
	}

	if !db.IsConsistent(fsdb) {
		return errors.New("database is not consistent")
	}

	return nil
}

func (fsdb *FsDb) Close() error {
	return nil
}
