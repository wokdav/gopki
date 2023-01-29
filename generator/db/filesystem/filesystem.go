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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing/fstest"
	"time"

	"github.com/wokdav/gopki/generator"
	"github.com/wokdav/gopki/generator/cert"
	"github.com/wokdav/gopki/generator/config"
	"github.com/wokdav/gopki/generator/db"
	"github.com/wokdav/gopki/logging"

	_ "github.com/wokdav/gopki/generator/config/v1"
)

const writePermissions fs.FileMode = 0644

// Is always initialized with a config, will later be provisioned with a cert context.
type certNode struct {
	configFileName string
	config.CertificateContent
	*cert.CertificateContext
}

// Wrappers for fs.FS with some write functionality.
// If go adds this feature to fs.Fs, we can remove this code.
type Filesystem interface {
	Fs() fs.FS
	WriteFile(name string, content []byte) error
}

type mapfs struct {
	m map[string]*fstest.MapFile
}

func (m mapfs) Fs() fs.FS {
	return fstest.MapFS(m.m)
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
		return mapfs{m: fstest.MapFS{".": &fstest.MapFile{Mode: 0777 | fs.ModeDir}}}
	default:
		return mapfs{m}
	}
}

type nativefs struct {
	basepath string
	fsObj    fs.FS
}

func (n nativefs) Fs() fs.FS {
	return n.fsObj
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

// It effectively builds a graph of certificate nodes and issuer-relations as edges.
// This allows building certificate hierarchies without imposing an explicit structure
// on the file system, since everything is derived from the configuration files first.
// Generation can then happen, by going through all root nodes and looking up subscriber
// aliases for each one until all certificates have been added.
type FsDb struct {
	//filesystem fs.FS
	filesystem Filesystem
	certNodes  map[string]*certNode //greedily stores all cert nodes
	profiles   map[string]config.CertificateProfile

	rootAliases   []string            //aliases of all root certificates
	subscribersOf map[string][]string //gets all subordinate aliases for the key alias
}

// Create a new file system database based on the provided implementation.
// This function pre-allocates about 2K+ KB of arrays to minimize re-allocation,
// so it should be used consciously.
func NewFilesystemDatabase(filesystem Filesystem) FsDb {
	return FsDb{
		filesystem: filesystem,
		//certNodes must store pointers, because we want to change the content
		certNodes:     make(map[string]*certNode, 1024),
		profiles:      make(map[string]config.CertificateProfile, 32),
		rootAliases:   make([]string, 0, 128),
		subscribersOf: make(map[string][]string, 1024),
	}
}

func (fsdb *FsDb) checkConsistency() error {
	sb := strings.Builder{}
	sb.WriteString("filesystem: inconsistent database:\n")
	inconsistent := false
	for alias, node := range fsdb.certNodes {
		if node.CertificateContext == nil {
			sb.WriteString(fmt.Sprintf("  missing certificate context: %v\n", alias))
			inconsistent = true
			continue
		}
		if node.CertificateContext.Issuer == nil {
			sb.WriteString(fmt.Sprintf("  missing issuer context: %v\n", alias))
			inconsistent = true
			continue
		}
	}

	if inconsistent {
		return errors.New(sb.String())
	}

	logging.Debug("db check finished: no missing certificates in database")

	return nil
}

// TODO: add functionality to reuse existing key
// TODO: make sure that subordinates are re-generated, if the certificate above changes
func (fsdb *FsDb) needsUpdate(strat db.UpdateStrategy, n certNode) (bool, error) {
	if strat&db.GenerateAlways > 0 {
		logging.Debugf("%v needs update. reson: GenerateAlways is set", n.CertificateContent.Alias)
		return true, nil
	}

	statFs, ok := fsdb.filesystem.Fs().(fs.StatFS)
	if !ok {
		return false, errors.New("filesystem: file system does not support stat methods")
	}

	certfilename := n.configFileName[:strings.LastIndex(n.configFileName, ".")] + ".pem"
	if strat&db.GenerateNewerConfig > 0 {
		infoPem, err := statFs.Stat(certfilename)
		if err != nil {
			return false, err
		}

		infoCfg, err := statFs.Stat(n.configFileName)
		if err != nil {
			return false, err
		}

		if infoCfg.ModTime().After(infoPem.ModTime()) {
			logging.Debugf("%v needs update. reson: GenerateNewerConfig is set and config modTime [%v] > cert modTime [%v]",
				n.CertificateContent.Alias, infoCfg.ModTime(), infoPem.ModTime())
			return true, nil
		}
	}

	if strat&db.GenerateExpired > 0 {
		//TODO
		return false, errors.New("not implemented")
	}

	if strat&db.GenerateMissing > 0 {
		_, err := statFs.Stat(certfilename)
		if err != nil && errors.Is(err, fs.ErrNotExist) {
			logging.Debugf("%v needs update. reson: GenerateMissing is set and Stat returned ErrNotExist", n.CertificateContent.Alias)
			return true, nil
		}
	}

	return false, nil
}

func (fsdb *FsDb) importContext(certFile string) (*cert.CertificateContext, error) {
	logging.Debugf("attempting to import certificate in '%v'", certFile)
	certfi, err := fsdb.filesystem.Fs().Open(certFile)
	if err != nil {
		logging.Errorf("import failed: %v", err)
		return nil, fmt.Errorf("filesystem: unable to open '%v.pem for reading'", certFile)
	}
	defer certfi.Close()

	cer, key, err := cert.ImportPem(certfi)
	if err != nil {
		logging.Errorf("import failed: %v", err)
		return nil, err
	}

	ctx := &cert.CertificateContext{
		TbsCertificate: &cer.TBSCertificate,
		PrivateKey:     key,
	}
	issuerCtx := cert.AsIssuer(*ctx)
	ctx.Issuer = &issuerCtx

	return ctx, nil
}

func validateAndMerge(fsdb *FsDb, node *certNode) error {
	logging.Debugf("validating and merging %v with profile %v", node.configFileName, node.CertificateContent.Profile)
	if len(node.CertificateContent.Profile) > 0 {
		profile, ok := fsdb.profiles[node.CertificateContent.Profile]
		if !ok {
			return fmt.Errorf("filesystem: '%s' references unknown profile '%s'",
				node.configFileName, node.CertificateContent.Profile)
		}

		logging.Debugf("profile %v was found", node.CertificateContent.Profile)

		if !config.Validate(profile, node.CertificateContent) {
			return fmt.Errorf("filesystem: '%s' does not validate against profile '%s'",
				node.configFileName, node.CertificateContent.Profile)
		}

		logging.Debug("validation was successful")

		newContent, err := config.Merge(profile, node.CertificateContent)
		if err != nil {
			return fmt.Errorf("filesystem: can't merge '%s' with profile'%s' due to '%v'",
				node.configFileName, node.CertificateContent.Profile,
				err)
		}

		logging.Debug("profile data merge was successful")

		node.CertificateContent = *newContent
	}

	return nil
}

func (fsdb *FsDb) updateChains(aliases []string, strat db.UpdateStrategy) (int, error) {
	todo := make([]string, 0, 1024)
	todo = append(todo, aliases...)
	certsGenerated := 0

	i := 0
	for i < len(todo) {
		alias := todo[i]
		i++
		logging.Debugf("currently working on %v (item %v/%v of our to-do list)", alias, i, len(todo))

		//add subscribers to todo list
		subs, exists := fsdb.subscribersOf[alias]
		if exists {
			logging.Debugf("%v signs %v more certificates. adding them to our to-do list", alias, len(subs))
			todo = append(todo, subs...)
		}

		//check if we need to upgrade
		node := fsdb.certNodes[alias]
		baseName := node.configFileName[:strings.LastIndex(node.configFileName, ".")]
		update, err := fsdb.needsUpdate(strat, *node)
		if err != nil {
			return certsGenerated, err
		}

		if !update {
			logging.Debugf("%v does not need an update, so we import so we have it in our db", alias)
			node.CertificateContext, err = fsdb.importContext(baseName + ".pem")
			if err != nil {
				return certsGenerated, err
			}
			continue
		}

		//validate and merge profile if applicable
		if err = validateAndMerge(fsdb, node); err != nil {
			return certsGenerated, err
		}

		logging.Debugf("generating new certificate body for %v", alias)
		ctx, err := generator.BuildCertBody(node.CertificateContent)
		if err != nil {
			return certsGenerated, err
		}

		node.CertificateContext = ctx

		if len(node.CertificateContent.Issuer) > 0 {
			logging.Debugf("issuer property for %v is set", alias)
			issuer := fsdb.certNodes[node.CertificateContent.Issuer]
			issuerCtx := cert.AsIssuer(*issuer.CertificateContext)

			ctx, err := generator.BuildCertBody(node.CertificateContent)
			if err != nil {
				return certsGenerated, err
			}
			node.CertificateContext = ctx
			node.CertificateContext.Issuer = &issuerCtx
		}

		//sign
		logging.Debugf("signing certificate for %v", alias)
		crt, err := node.CertificateContext.Sign(node.CertificateContent.SignatureAlgorithm)
		if err != nil {
			return certsGenerated, err
		}

		//write cert and key files
		bb := bytes.Buffer{}
		err = crt.WritePem(&bb)
		if err != nil {
			return certsGenerated, err
		}

		err = cert.WritePrivateKeyToPem(ctx.PrivateKey, &bb)
		if err != nil {
			return certsGenerated, err
		}

		fname := node.configFileName[:strings.LastIndex(node.configFileName, ".")] + ".pem"
		logging.Debugf("writing %v", fname)
		err = fsdb.filesystem.WriteFile(fname, bb.Bytes())
		if err != nil {
			return certsGenerated, err
		}

		if len(node.CertificateContent.Issuer) == 0 {
			logging.Infof("%v[%v]: %v", node.CertificateContent.Alias, fname, node.CertificateContext.Subject.String())
		} else {
			logging.Infof("%v->%v[%v]: %v", node.CertificateContent.Issuer, node.CertificateContent.Alias, fname, node.CertificateContext.Subject.String())
		}

		certsGenerated++
	}

	logging.Infof("generation finished. %d certs generated", certsGenerated)
	return certsGenerated, nil
}

// Update all certificates in this database according to the provided strategy.
// This involves generating certificates and keys if the strategy demands it
// and writing them out to the filesystem.
func (fsdb *FsDb) Update(strat db.UpdateStrategy) error {
	fsdb.rootAliases = fsdb.rootAliases[:]

	certsGenerated := 0

	var err error
	//sign root certificates
	if len(fsdb.rootAliases) == 0 {
		return errors.New("filesystem: no root certificates to sign with")
	}

	logging.Debugf("found %v root certificate aliases in database", len(fsdb.rootAliases))

	n, err := fsdb.updateChains(fsdb.rootAliases, strat)
	if err != nil {
		return err
	}

	certsGenerated += n

	//if len(fsdb.certNodes) != certsGenerated {
	//	return errors.New("some certificates have missing issuers")
	//}

	err = fsdb.checkConsistency()
	if err != nil {
		return err
	}

	return nil
}

// Open will walk through the filesystem and collect all config files, building
// the certificate hierarchy. It does not just open a file descriptor, as the name might
// suggest.
func (fsdb *FsDb) Open() error {
	logging.Debug("scanning folder for config files")
	err := fs.WalkDir(fsdb.filesystem.Fs(), ".", func(path string, d fs.DirEntry, err error) error {
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

		fi, err := fsdb.filesystem.Fs().Open(path)
		if err != nil {
			return err
		}
		defer fi.Close()

		cfg, err := config.ParseConfig(fi)
		if err != nil {
			logging.Infof("skipping %v due to parsing error", d.Name())
			return nil
		}

		//do we have a certificate...?
		certContent, ok := cfg.(*config.CertificateContent)
		if ok {
			logging.Debugf("certificate recognized")

			//default alias is the filename
			if len(certContent.Alias) == 0 {
				newAlias := path[strings.LastIndex(path, "/")+1 : strings.LastIndex(path, ".")]
				certContent.Alias = newAlias
				logging.Debugf("alias is not set. setting it to '%v'", newAlias)
			}

			_, exists := fsdb.certNodes[certContent.Alias]
			if exists && fsdb.certNodes[certContent.Alias].configFileName != path {
				logging.Errorf("alias %s already exists in database", certContent.Alias)
				logging.Errorf("either rename one of these config files to something unique or set a unique alias in the config")

				return fmt.Errorf("alias exists multiple times: %s. ", certContent.Alias)
			}

			fsdb.certNodes[certContent.Alias] = &certNode{
				configFileName:     path,
				CertificateContent: *certContent,
				CertificateContext: nil,
			}

			if len(certContent.Issuer) == 0 {
				//is root? -> note
				logging.Debugf("we have a root certificate. adding it to root list")
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
			return nil
		}

		//...or a profile?
		profileContent, ok := cfg.(*config.CertificateProfile)
		if ok {
			logging.Debugf("profile recognized")
			fsdb.profiles[profileContent.Name] = *profileContent
			return nil
		}

		panic(fmt.Errorf("filesystem: file '%s' can neither be casted as a profile nor as a certificate config, even though parsing was successful", path))
	})

	logging.Infof("found %v cert configs (containing %v root configs) and %v cert profiles", len(fsdb.certNodes), len(fsdb.profiles), len(fsdb.rootAliases))

	return err
}

// Get all certificates and keys in the filesystem database.
func (fsdb *FsDb) GetAll() ([]cert.CertificateContext, error) {
	out := make([]cert.CertificateContext, len(fsdb.certNodes))
	i := 0
	for _, v := range fsdb.certNodes {
		if v.CertificateContext != nil {
			out[i] = *v.CertificateContext
		}
		i++
	}

	return out[:], nil
}

func (fsdb *FsDb) Close() error {
	return nil
}
