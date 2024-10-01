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

	"github.com/ghodss/yaml"
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
	DeleteFile(name string) error
}

// this shit belongs into a test class
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

func (m mapfs) DeleteFile(name string) error {
	delete(m.m, name)
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

func (n nativefs) DeleteFile(name string) error {
	if filepath.IsAbs(name) {
		return fmt.Errorf("filesystem: '%s' is an absolute path, rather than a part relative to the provided basename", name)
	}

	return os.Remove(n.basepath + string(os.PathSeparator) + name)
}

// Generates a new [filesystem.Filesystem] based on [os.DirFS], plus some write
// functionality taken from the [os] package.
func NewNativeFs(path string) Filesystem {
	return nativefs{basepath: path, fsObj: os.DirFS(path)}
}

type fsMetadata struct {
	db.Metadata
	configFileName string
}

// It effectively builds a graph of certificate nodes and issuer-relations as edges.
// This allows building certificate hierarchies without imposing an explicit structure
// on the file system, since everything is derived from the configuration files first.
// Generation can then happen, by going through all root nodes and looking up subscriber
// aliases for each one until all certificates have been added.
type FsDb struct {
	//filesystem fs.FS
	filesystem Filesystem
	//greedily store all cert nodes
	configs    map[string]*config.CertificateContent
	artifacts  map[string]*db.BuildArtifact
	fsMetadata map[string]*fsMetadata

	profiles map[string]*config.CertificateProfile

	rootAliases   []string            //aliases of all root certificates
	subscribersOf map[string][]string //gets all subordinate aliases for the key alias
}

// Create a new file system database based on the provided implementation.
// This function pre-allocates about 2K+ KB of arrays to minimize re-allocation,
// so it should be used consciously.
// TODO: Stream from disk instead of caching EVERYTHING
func NewFilesystemDatabase(filesystem Filesystem) db.Database {
	return &FsDb{
		filesystem: filesystem,
		//certNodes must store pointers, because we want to change the content
		configs:       make(map[string]*config.CertificateContent, 1024),
		artifacts:     make(map[string]*db.BuildArtifact, 1024),
		fsMetadata:    make(map[string]*fsMetadata, 1024),
		profiles:      make(map[string]*config.CertificateProfile, 32),
		rootAliases:   make([]string, 0, 128),
		subscribersOf: make(map[string][]string, 1024),
	}
}

func (f fsMetadata) artifactFileName() string {
	return f.configFileName[:strings.LastIndex(f.configFileName, ".")] + ".pem"
}

func (fsdb *FsDb) PutConfig(alias string, cfg config.CertificateContent) error {
	if len(alias) == 0 {
		return errors.New("filesystem.go: alias must not be empty")
	}

	_, existed := fsdb.configs[alias]
	fsdb.configs[alias] = &cfg

	var meta *fsMetadata
	if existed {
		meta = fsdb.fsMetadata[alias]
		meta.LastConfigUpdate = time.Now()

		return nil
	}
	meta = &fsMetadata{
		configFileName: alias + ".yaml",
		Metadata: db.Metadata{
			LastConfigUpdate: time.Now(),
		},
	}
	fsdb.fsMetadata[alias] = meta

	if _, ok := fsdb.artifacts[alias]; !ok {
		fsdb.artifacts[alias] = &db.BuildArtifact{}
	}

	b, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("filesystem.go: can't marshal config for alias %v to yaml: %v",
			alias, err)
	}

	err = fsdb.filesystem.WriteFile(meta.configFileName, b)
	if err != nil {
		return fmt.Errorf("filesystem.go: can't write config for alias %v to file %v: %v",
			alias, meta.configFileName, err)
	}

	return err
}

func (fsdb *FsDb) GetConfig(alias string) (*config.CertificateContent, error) {
	fsentity, ok := fsdb.configs[alias]
	if !ok {
		return nil, nil
	}

	return fsentity, nil
}

func (fsdb *FsDb) PutBuildArtifact(alias string, artifact db.BuildArtifact) error {
	_, ok := fsdb.configs[alias]
	if !ok {
		return fmt.Errorf("filesystem.go: can't find alias %v in database", alias)
	}

	fsdb.artifacts[alias] = &artifact
	err := fsdb.exportPemFile(alias)

	if artifact.Certificate != nil {
		fsdb.fsMetadata[alias].LastBuild = time.Now()
	}

	return err
}

func (fsdb *FsDb) GetBuildArtifact(alias string) (*db.BuildArtifact, error) {
	out, ok := fsdb.artifacts[alias]
	if !ok {
		return nil, nil
	}

	return out, nil
}

func (fsdb *FsDb) GetMetadata(alias string) (*db.Metadata, error) {
	fsentity, ok := fsdb.fsMetadata[alias]
	if !ok {
		return nil, nil
	}

	//copy just in case
	var out db.Metadata = fsentity.Metadata

	return &out, nil
}

func (fsdb *FsDb) Delete(alias string) error {
	meta, ok := fsdb.fsMetadata[alias] //means it does not exist
	if !ok {
		return nil
	}

	err := fsdb.Delete(meta.configFileName)
	if err != nil {
		return err
	}

	err = fsdb.Delete(meta.artifactFileName())
	return err
}

func (fsdb *FsDb) NumEntities() int {
	return len(fsdb.configs)
}

func (fsdb *FsDb) RootEntities() []string {
	return fsdb.rootAliases
}

func (fsdb *FsDb) GetSubscribers(alias string) []string {
	return fsdb.subscribersOf[alias]
}

func (fsdb *FsDb) GetProfile(name string) (*config.CertificateProfile, error) {
	return fsdb.profiles[name], nil
}

func (fsdb *FsDb) AddProfile(profile config.CertificateProfile) error {
	fsdb.profiles[profile.Name] = &profile
	return nil
}

const hashPrefix string = "#HASH:"

func (fsdb *FsDb) exportPemFile(alias string) error {
	bb := bytes.Buffer{}

	cfg, ok := fsdb.configs[alias]
	if !ok {
		return fmt.Errorf("filesystem: alias %v does not exist", alias)
	}

	_, err := bb.Write([]byte(hashPrefix + base64.StdEncoding.EncodeToString(cfg.HashSum()) + "\n"))
	if err != nil {
		logging.Errorf("error writing pem for %v: %v", alias, err)
	}

	artifact := fsdb.artifacts[alias]

	if artifact.Certificate != nil {
		err = artifact.Certificate.WritePem(&bb)
		if err != nil {
			return err
		}
	}
	if artifact.PrivateKey != nil {
		err = cert.WritePrivateKeyToPem(artifact.PrivateKey, &bb)
		if err != nil {
			return err
		}
	}
	if artifact.Request != nil {
		err = artifact.Request.WritePem(&bb)
		if err != nil {
			return err
		}
	}

	meta := fsdb.fsMetadata[alias]

	if bb.Len() > 0 {
		err = fsdb.filesystem.WriteFile(
			meta.artifactFileName(),
			bb.Bytes(),
		)
		if err != nil {
			return err
		}
	}

	meta.LastBuild = time.Now()

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

func (fsdb *FsDb) importCertConfigFile(certContent config.CertificateContent, configPath string) error {
	logging.Debugf("certificate recognized")

	//default alias is the filename
	if len(certContent.Alias) == 0 {
		newAlias := configPath[strings.LastIndex(configPath, "/")+1 : strings.LastIndex(configPath, ".")]
		certContent.Alias = newAlias
		logging.Debugf("alias is not set. setting it to '%v'", newAlias)
	}

	meta, alreadyExists := fsdb.fsMetadata[certContent.Alias]
	if alreadyExists && meta.configFileName != configPath {
		logging.Errorf("alias %s already exists in database", certContent.Alias)
		logging.Errorf("either rename one of these config files to something unique or set a unique alias in the config")

		return fmt.Errorf("alias exists multiple times: %s. ", certContent.Alias)
	}

	if !alreadyExists {
		fsdb.configs[certContent.Alias] = &certContent
		meta = &fsMetadata{
			configFileName: configPath,
		}
		fsdb.fsMetadata[certContent.Alias] = meta
		fsdb.artifacts[certContent.Alias] = &db.BuildArtifact{}
	}

	//get modtime for config file
	statfs, ok := fsdb.filesystem.FS().(fs.StatFS)
	if ok {
		stat, err := statfs.Stat(configPath)
		if err != nil {
			logging.Warningf("could not get modtime for %v: %v", configPath, err)
		} else {
			meta.LastConfigUpdate = stat.ModTime()
		}
	} else {
		logging.Warningf("filesystem does not support statfs. cannot get modtime for %v. updates based on modtimes will be unreliable", configPath)
	}

	//get modtime for cert file
	var readableArtifactFound bool
	var certfiContent []byte
	certFile := meta.artifactFileName()
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
			meta.LastBuild = fi.ModTime()
		}

		//attempt to import certificate and key
		logging.Debugf("attempting to import cert/key for '%v' that we can reuse", certFile)
		importedArtifact := fsdb.importPem(certfiContent)
		fsdb.artifacts[certContent.Alias] = &importedArtifact

		hashIx := bytes.Index(certfiContent, []byte(hashPrefix))

		if hashIx != -1 {
			hashEnd := bytes.IndexRune(certfiContent[hashIx:], '\n')
			hashIx += len(hashPrefix)
			if hashEnd != -1 {
				hashs := string(certfiContent[hashIx:hashEnd])
				hashBytes, err := base64.StdEncoding.DecodeString(hashs)
				if err != nil {
					logging.Warningf("error decoding config hash for %v: %v", certFile, err)
				} else {
					meta.LastConfigHash = hashBytes
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
// TODO: Scales poorly atm since the all data is held in RAM
func importFiles(backend db.Database, fsys fs.FS) error {
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
			err = fsdb.importCertConfigFile(*certContent, path)
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

	logging.Infof("found %v cert configs (containing %v root configs) and %v cert profiles", len(fsdb.configs), len(fsdb.profiles), len(fsdb.rootAliases))

	return err
}

func (fsdb *FsDb) Open() error {
	err := importFiles(fsdb, fsdb.filesystem.FS())
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
