package filesystem

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/wokdav/gopki/generator/cert"
	"github.com/wokdav/gopki/generator/db"
	"github.com/wokdav/gopki/logging"
)

var testrootcert string = `-----BEGIN CERTIFICATE-----
MIIBFDCBvKADAgECAgJOVTAKBggqhkjOPQQDAjAUMRIwEAYDVQQDEwlUZXN0IFJv
b3QwHhcNMjIxMjEzMTg1MDU0WhcNMjcxMjEzMTg1MDU0WjAUMRIwEAYDVQQDEwlU
ZXN0IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNtscTl0w3Yrz1eLFB
AWX9v0oXv5Z1S7ye0vWoPHeDhH3vXSXg89kn9aCEvetSDi//NyxMQ/jRRUeXLio/
LsmgMAoGCCqGSM49BAMCA0cAMEQCIE3U8Bz6zfmVoRUcGa/58jErqDc9GrzDe3DN
EVViQ+boAiBJ30DGDE9O2FfsLxk7pzeucfXoUV1NLDURlCP0bxaPFA==
-----END CERTIFICATE-----
`

var testrootkey string = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxBZoTr/R7fEf9hRL
s+lkvFGbsJmVv8VNRL5YZOvUzbmhRANCAASNtscTl0w3Yrz1eLFBAWX9v0oXv5Z1
S7ye0vWoPHeDhH3vXSXg89kn9aCEvetSDi//NyxMQ/jRRUeXLio/Lsmg
-----END PRIVATE KEY-----
`

func copyFilesIntoMapFs(path string) (*fstest.MapFS, error) {
	abspath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	out := fstest.MapFS{}
	err = fs.WalkDir(os.DirFS(abspath), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		f, err := os.Open(abspath + string(os.PathSeparator) + path)
		if err != nil {
			return err
		}
		defer f.Close()

		buf := bytes.NewBuffer(nil)
		_, err = buf.ReadFrom(f)
		if err != nil {
			return err
		}

		//get modTime for file
		fi, err := f.Stat()
		if err != nil {
			return err
		}

		out[path] = &fstest.MapFile{
			Data:    buf.Bytes(),
			Mode:    0644,
			ModTime: fi.ModTime(),
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &out, nil
}

func TestMain(m *testing.M) {
	logging.Initialize(logging.LevelDebug, nil, nil)
	code := m.Run()
	os.Exit(code)
}

func getTestFs(m map[string]string) Filesystem {
	out := fstest.MapFS{
		".": &fstest.MapFile{
			Mode: 0777 | fs.ModeDir,
		},
	}

	for k, v := range m {
		out[k] = &fstest.MapFile{
			Data: []byte(v),
			Mode: 0644,
		}
	}

	return NewMapFs(out)
}

func quickUpdate(testdb db.CertificateDatabase, strat db.UpdateStrategy) ([]cert.CertificateContext, error) {
	err := testdb.Open()
	if err != nil {
		return nil, err
	}
	defer testdb.Close()

	err = testdb.Update(strat)
	if err != nil {
		return nil, err
	}

	ctx, err := testdb.GetAll()
	if err != nil {
		return nil, err
	}

	return ctx, nil
}

func TestSmoke(t *testing.T) {
	fs := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=Test Root",
			"sub.yaml":  "version: 1\nissuer: root\nsubject: CN=Test Sub",
			"ee.yaml":   "version: 1\nissuer: sub\nsubject: CN=Test EE",
		},
	)

	testdb := NewFilesystemDatabase(fs)
	ctx, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if len(ctx) != 3 {
		t.Fatalf("expected 3 certificates, got %d", len(ctx))
	}
}

func TestNoRoot(t *testing.T) {
	fs := getTestFs(
		map[string]string{
			"sub1.yaml": "version: 1\nissuer: sub2\nsubject: CN=Test Sub1",
			"sub2.yaml": "version: 1\nissuer: sub1\nsubject: CN=Test Sub2",
		},
	)

	testdb := NewFilesystemDatabase(fs)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err == nil {
		t.Fatal("certification paths with no roots should fail")
	}
}

func TestPartial(t *testing.T) {
	fs := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=Test Root",
			"sub.yaml":  "version: 1\nissuer: root\nsubject: CN=Test Sub",
			"sub2.yaml": "version: 1\nissuer: root2\nsubject: CN=Test EE",
		},
	)

	testdb := NewFilesystemDatabase(fs)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err == nil {
		t.Fatal("certification that can't be fully built should yield an error")
	}
}

func TestCeckIssuer(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=Test Root",
			"sub.yaml":  "version: 1\nissuer: root\nsubject: CN=Test Sub",
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatal(err.Error())
	}
	b, err := fs.ReadFile(fsdb.Fs(), "sub.pem")
	if err != nil {
		t.Fatalf(err.Error())
	}

	//check that sub is signed by root
	subCert := cert.Certificate{}
	var p *pem.Block
	for {
		p, b = pem.Decode(b)
		if p == nil {
			break
		}
		if p.Type != "CERTIFICATE" {
			continue
		}
		_, err = asn1.Unmarshal(p.Bytes, &subCert)
		if err != nil {
			t.Fatal(err.Error())
		}
		break
	}

	subx509, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	b, err = fs.ReadFile(fsdb.Fs(), "root.pem")
	if err != nil {
		t.Fatalf(err.Error())
	}

	rootCert := cert.Certificate{}
	p, _ = pem.Decode(b)
	_, err = asn1.Unmarshal(p.Bytes, &rootCert)
	if err != nil {
		t.Fatal(err.Error())
	}

	rootx509, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	if len(subCert.TBSCertificate.Issuer.String()) == 0 {
		t.Fatalf("issuer of sub is empty")
	}

	if subCert.TBSCertificate.Issuer.String() != rootCert.TBSCertificate.Subject.String() {
		t.Fatalf("expected issuer of sub to be subject of root, but sub.issuer='%v' and root.subject='%v'",
			subCert.TBSCertificate.Issuer.String(),
			rootCert.TBSCertificate.Subject.String(),
		)
	}

	err = rootx509.CheckSignature(
		subx509.SignatureAlgorithm,
		subx509.RawTBSCertificate,
		subx509.Signature,
	)

	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestSingle(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=Test Root",
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	ctx, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatal(err.Error())
	}

	if len(ctx) != 1 {
		t.Fatalf("expected 1 certificate in return, but got %d", len(ctx))
	}

	//check self-signed signature
	b, err := fs.ReadFile(fsdb.Fs(), "root.pem")
	if err != nil {
		t.Fatal(err.Error())
	}

	p, _ := pem.Decode(b)
	rootx509, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = rootx509.CheckSignature(
		rootx509.SignatureAlgorithm,
		rootx509.RawTBSCertificate,
		rootx509.Signature,
	)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestDirectories(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			"a/b/c/root.yaml": "version: 1\nsubject: CN=Test Root",
			"x/y/sub.yaml":    "version: 1\nissuer: root\nsubject: CN=Test Sub",
			"ee.yaml":         "version: 1\nissuer: sub\nsubject: CN=Test EE",
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	ctx, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatal(err.Error())
	}

	if len(ctx) != 3 {
		t.Fatalf("expected 3 certificates, got %d", len(ctx))
	}

	//check that certificates are stored in the expected directories
	_, err = fs.ReadFile(fsdb.Fs(), "a/b/c/root.pem")
	if err != nil {
		t.Fatal(err.Error())
	}
	_, err = fs.ReadFile(fsdb.Fs(), "x/y/sub.pem")
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestDirectoriesAmbiguousAlias(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			"a/b/c/root.yaml": "version: 1\nsubject: CN=Test Root",
			"a/b/root.yaml":   "version: 1\nsubject: CN=Test Root2",
			"x/y/sub.yaml":    "version: 1\nissuer: root\nsubject: CN=Test Sub",
			"ee.yaml":         "version: 1\nissuer: sub\nsubject: CN=Test EE",
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err == nil {
		t.Fatal("this should fail")
	}
}

func TestReuseKey(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=Test Root",
			"root.pem":  testrootkey,
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatal(err.Error())
	}

	f, err := fs.ReadFile(fsdb.Fs(), "root.pem")
	if err != nil {
		t.Fatal(err.Error())
	}
	if !strings.Contains(string(f), strings.TrimSpace(testrootkey)) {
		t.Fatal("key has changed")
	}
}

func TestDirectoriesNonAmbiguousAlias(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			"a/b/c/root.yaml": "version: 1\nsubject: CN=Test Root",
			"a/b/root.yaml":   "version: 1\nsubject: CN=Test Root2\nalias: root2",
			"x/y/sub.yaml":    "version: 1\nissuer: root\nsubject: CN=Test Sub",
			"ee.yaml":         "version: 1\nissuer: sub\nsubject: CN=Test EE",
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestIgnoreBad(t *testing.T) {
	fs := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=Test Root",
			"foo.txt":   `¯\_(ツ)_/¯`,
		},
	)

	testdb := NewFilesystemDatabase(fs)
	ctx, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatal(err.Error())
	}

	if len(ctx) != 1 {
		t.Fatalf("expected 1 certificate in return, but got %d", len(ctx))
	}
}

func TestEmptyDir(t *testing.T) {
	fs := getTestFs(
		map[string]string{},
	)

	testdb := NewFilesystemDatabase(fs)
	ctx, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatal(err.Error())
	}

	if len(ctx) != 0 {
		t.Fatalf("expected 0 certificates to be returned, but got %v", len(ctx))
	}
}

func TestWriteCertificates(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=Test Root",
			"sub.yaml":  "version: 1\nissuer: root\nsubject: CN=Test Sub",
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatal(err.Error())
	}

	_, err = fs.ReadFile(fsdb.Fs(), "root.pem")
	if err != nil {
		t.Fatalf(err.Error())
	}

	_, err = fs.ReadFile(fsdb.Fs(), "sub.pem")
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestGenerateMissing(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			"a/root1.yaml": "version: 1\nsubject: CN=Test Root 1",
			//technically this is a root cert, not a sub, but the content doesn't matter for this test
			"a/root1.pem": testrootcert + testrootkey,
			"root2.yaml":  "version: 1\nsubject: CN=Test Root 2",
		},
	)

	bBefore, err := fs.ReadFile(fsdb.Fs(), "a/root1.pem")
	if err != nil {
		t.Fatalf(err.Error())
	}

	testdb := NewFilesystemDatabase(fsdb)
	_, err = quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatal(err.Error())
	}

	//check that root1.pem is unchanged
	bAfter, err := fs.ReadFile(fsdb.Fs(), "a/root1.pem")
	if err != nil {
		t.Fatalf(err.Error())
	}

	if !bytes.Equal(bBefore, bAfter) {
		t.Fatalf("expected root1.pem to remain unchanged")
	}

	//check that root2.pem is generated
	_, err = fs.ReadFile(fsdb.Fs(), "root2.pem")
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestGenerateWithImport(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=Test Root",
			"root.pem":  testrootcert + testrootkey,
			"sub.yaml":  "version: 1\nissuer: root\nsubject: CN=Test Sub",
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatal(err.Error())
	}

	//check that sub is generated properly
	b, err := fs.ReadFile(fsdb.Fs(), "sub.pem")
	if err != nil {
		t.Fatalf(err.Error())
	}

	subCert, err := cert.ImportCertPem(b)
	if err != nil {
		t.Fatal(err.Error())
	}

	subCertBytes, err := asn1.Marshal(*subCert)
	if err != nil {
		t.Fatal(err.Error())
	}

	// prepare x509 import as well for signature check later
	subx509, err := x509.ParseCertificate(subCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	p, _ := pem.Decode([]byte(testrootcert))

	rootCert := cert.Certificate{}
	_, err = asn1.Unmarshal(p.Bytes, &rootCert)
	if err != nil {
		t.Fatal(err.Error())
	}

	rootx509, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	if len(subCert.TBSCertificate.Issuer.String()) == 0 {
		t.Fatalf("issuer of sub is empty")
	}

	if subCert.TBSCertificate.Issuer.String() != rootCert.TBSCertificate.Subject.String() {
		t.Fatalf("expected issuer of sub to be subject of root, but sub.issuer='%v' and root.subject='%v'",
			subCert.TBSCertificate.Issuer.String(),
			rootCert.TBSCertificate.Subject.String(),
		)
	}

	//check signatures
	err = rootx509.CheckSignature(
		subx509.SignatureAlgorithm,
		subx509.RawTBSCertificate,
		subx509.Signature,
	)

	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestCircle(t *testing.T) {
	fs := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=Test Root",
			"sub1.yaml": "version: 1\nissuer: sub2\nsubject: CN=Test Sub1",
			"sub2.yaml": "version: 1\nissuer: sub1\nsubject: CN=Test Sub2",
		},
	)

	testdb := NewFilesystemDatabase(fs)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err == nil {
		t.Fatalf("circular dependencies should fail")
	}
}

func TestBuildExamples(t *testing.T) {
	mpfs, err := copyFilesIntoMapFs("../../../examples")
	if err != nil {
		t.Fatal(err.Error())
	}

	testdb := NewFilesystemDatabase(NewMapFs(*mpfs))
	_, err = quickUpdate(testdb, db.UpdateAll)
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestBugWrongKeyAlg(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=Test Root\nkeyAlgorithm: P-521",
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatal(err.Error())
	}

	b, err := fs.ReadFile(fsdb.Fs(), "root.pem")
	if err != nil {
		t.Fatalf(err.Error())
	}

	//check that sub is signed by root
	p, _ := pem.Decode(b)
	rootx509, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	eckey, ok := rootx509.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("not ecdsa compatible")
	}

	targetCurve := elliptic.P521()
	if !targetCurve.IsOnCurve(eckey.X, eckey.Y) {
		t.Fatalf("key is not on the expected curve")
	}
}

func TestBugWrongKeyAlgRsa(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=Test Root\nkeyAlgorithm: RSA-2048",
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatal(err.Error())
	}

	b, err := fs.ReadFile(fsdb.Fs(), "root.pem")
	if err != nil {
		t.Fatalf(err.Error())
	}

	//check that sub is signed by root
	p, _ := pem.Decode(b)
	rootx509, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	rsakey, ok := rootx509.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("not ecdsa compatible")
	}

	if rsakey.Size() != 2048/8 {
		t.Fatalf("expected rsa key to be 2048 bit long instead of %v", rsakey.Size()*8)
	}
}

func TestBugWrongDate(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=Test Root\nvalidity:\n  from: '2020-01-01'\n  until: '2050-01-01'\n",
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatal(err.Error())
	}

	b, err := fs.ReadFile(fsdb.Fs(), "root.pem")
	if err != nil {
		t.Fatalf(err.Error())
	}

	//check that sub is signed by root
	p, _ := pem.Decode(b)
	rootx509, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	expectedFrom := time.Date(2020, 1, 1, 0, 0, 0, 0, time.Local)
	gotFrom := rootx509.NotBefore

	if !gotFrom.Equal(expectedFrom) {
		t.Fatalf("expected validNotBefore to be %v instead of %v", expectedFrom.String(), gotFrom.String())
	}

	expectedUntil := time.Date(2050, 1, 1, 0, 0, 0, 0, time.Local)
	gotUntil := rootx509.NotAfter

	if !gotUntil.Equal(expectedUntil) {
		t.Fatalf("expected validNotBefore to be %v instead of %v", expectedUntil.String(), gotUntil.String())
	}
}

func TestBugWrongAuthKeyId(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=Test Root",
			"sub.yaml":  "version: 1\nsubject: CN=Test Sub\nissuer: root\nextensions:\n  - subjectKeyIdentifier:\n      content: hash\n  - authorityKeyIdentifier:\n      content:\n        id: hash",
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatal(err.Error())
	}

	b, err := fs.ReadFile(fsdb.Fs(), "sub.pem")
	if err != nil {
		t.Fatalf(err.Error())
	}

	//check that sub is signed by root
	p, _ := pem.Decode(b)
	subx509, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	subkeyid := make([]byte, 0, 20)
	_, err = asn1.Unmarshal(subx509.Extensions[0].Value, &subkeyid)
	if err != nil {
		t.Fatal(err.Error())
	}

	authkeyid := cert.AuthorityKeyIdentifier{}
	_, err = asn1.Unmarshal(subx509.Extensions[1].Value, &authkeyid)
	if err != nil {
		t.Fatal(err.Error())
	}

	if bytes.Equal(subkeyid, authkeyid.KeyIdentifier) {
		t.Fatal("authority key identifier unexpectedly identical to subject key identifier")
	}
}

func TestProfileSmoke(t *testing.T) {
	fs := getTestFs(
		map[string]string{
			"root.yaml":         "version: 1\nsubject: CN=Test Root\nprofile: rootProfile",
			"root-profile.yaml": "version: 1\nname: rootProfile\nextensions:\n  - subjectKeyIdentifier:\n      content: hash",
		},
	)

	testdb := NewFilesystemDatabase(fs)
	ctx, err := quickUpdate(testdb, db.UpdateMissing)
	if err != nil {
		t.Fatalf(err.Error())
	}

	oid, ok := cert.GetOid(cert.OidExtensionSubjectKeyId)
	if !ok {
		panic("oid not found")
	}

	profileExtension, err := ctx[0].Extensions[0].Compile(&ctx[0])
	if err != nil {
		t.Fatal(err.Error())
	}
	if !profileExtension.Id.Equal(oid) {
		t.Fatalf("expected oid %v, but got %v", oid.String(), profileExtension.Id.String())
	}
}

func TestValidateFail(t *testing.T) {
	fs := getTestFs(
		map[string]string{
			"root.yaml":         "version: 1\nsubject: CN=Test Root\nprofile: rootProfile",
			"root-profile.yaml": "version: 1\nname: rootProfile\nsubjectAttributes:\n  allowOther: false\n  attributes:\n    - attribute: C",
		},
	)

	testdb := NewFilesystemDatabase(fs)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err == nil {
		t.Fatal("this should fail")
	}

	if !strings.Contains(err.Error(), "does not validate") {
		t.Fatalf("expected error due to failed validation, but instead got '%s'", err.Error())
	}
}

func TestUnknownProfile(t *testing.T) {
	fs := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=Test Root\nprofile: rootProfile",
		},
	)

	testdb := NewFilesystemDatabase(fs)
	_, err := quickUpdate(testdb, db.UpdateMissing)
	if err == nil {
		t.Fatal("this should fail")
	}

	if !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("expected error due to unknown profile, but instead got '%s'", err.Error())
	}
}

func TestWriteToFileMapFs(t *testing.T) {
	fsdb := getTestFs(map[string]string{})
	filename := "testfile.txt"
	content := "test"

	err := fsdb.WriteFile(filename, []byte(content))
	if err != nil {
		t.Fatal(err.Error())
	}

	b, err := fs.ReadFile(fsdb.Fs(), filename)
	if err != nil {
		t.Fatal(err.Error())
	}

	if string(b) != content {
		t.Fatalf("expected '%s' to containt '%s' instead of '%s'",
			filename, content, string(b))
	}
}

func TestWriteToFileNativeFs(t *testing.T) {
	tmpDir, err := os.MkdirTemp(".", "")
	if err != nil {
		t.Fatal(err.Error())
	}

	defer os.RemoveAll(tmpDir)

	filename := "testfile.txt"
	content := "test"

	filesys := NewNativeFs(tmpDir)

	err = filesys.WriteFile(filename, []byte(content))
	if err != nil {
		t.Fatal(err.Error())
	}

	b, err := fs.ReadFile(filesys.Fs(), filename)
	if err != nil {
		t.Fatal(err.Error())
	}

	if string(b) != content {
		t.Fatalf("expected '%s' to containt '%s' instead of '%s'",
			filename, content, string(b))
	}
}

func TestNilMapfs(t *testing.T) {
	mfs := NewMapFs(nil)
	_, err := mfs.Fs().Open(".")
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestGenerateNewer(t *testing.T) {
	today := time.Now()
	yesterday := today.AddDate(0, 0, -1)
	tomorrow := today.AddDate(0, 0, 1)

	testpem := testrootcert + testrootkey

	var mpfs fstest.MapFS = map[string]*fstest.MapFile{
		".": {
			Mode:    0777 | fs.ModeDir,
			ModTime: today,
		},
		"root.yaml": {
			Data:    []byte("version: 1\nsubject: CN=Test Root"),
			Mode:    0644,
			ModTime: today,
		},
		"root.pem": {
			Data:    []byte(testpem),
			Mode:    0644,
			ModTime: yesterday,
		},
		"sub.yaml": {
			Data:    []byte("version: 1\nsubject: CN=Test Sub\nissuer: root"),
			Mode:    0644,
			ModTime: tomorrow,
		},
		"sub.pem": {
			Data:    []byte(testpem),
			Mode:    0644,
			ModTime: tomorrow,
		},
	}

	testdb := NewFilesystemDatabase(NewMapFs(mpfs))
	_, err := quickUpdate(testdb, db.UpdateNewerConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}

	//check that regeneration happens
	b, err := mpfs.ReadFile("root.pem")
	if err != nil {
		t.Fatal(err.Error())
	}

	if strings.Contains(string(b), testrootcert) {
		t.Fatal("expect root certificate to change")
	}

	//check that sub is regenerated, since root has changed
	sub, err := mpfs.ReadFile("sub.pem")
	if err != nil {
		t.Fatal(err.Error())
	}

	if string(sub) == testpem {
		t.Fatal("expect sub certificate to change")
	}

	//try another update
	_, err = quickUpdate(testdb, db.UpdateNewerConfig)
	if err != nil {
		t.Fatalf(err.Error())
	}

	//check that regeneration does NOT happen
	b2, err := mpfs.ReadFile("root.pem")
	if err != nil {
		t.Fatal(err.Error())
	}

	if !bytes.Equal(b, b2) {
		t.Fatal("expect root certificate not to change")
	}
}

var expiredCert string = `
-----BEGIN CERTIFICATE-----
MIIBIzCByaADAgECAgMAmTAwCgYIKoZIzj0EAwIwGjEYMBYGA1UEAxMPVGVzdFJv
b3RFeHBpcmVkMB4XDTIzMDIwMjIzMDAwMFoXDTIyMTIzMTIzMDAwMFowGjEYMBYG
A1UEAxMPVGVzdFJvb3RFeHBpcmVkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
3x3WIsdrhVPVAEfZ4gc7hQcSt7sQhvfljlW0FkbfRFiZ+8rJF1u9TzT+qVb/kClg
G+pvzO3qGFELnpLPaGZcojAKBggqhkjOPQQDAgNJADBGAiEAztS0dL4f/cV1QEFv
NQ6z07fnEHc6UHA9iI1KT5Nk2tQCIQDbtvrEtvR1JDjU30ySf4ivBEbffdA0TQKY
TXDjnyMA5A==
-----END CERTIFICATE-----`

var expiredKey string = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgllR3y5IVNNOvF4Ey
PFtAq0C/FEMaP50IxaL3swaDkh2hRANCAATfHdYix2uFU9UAR9niBzuFBxK3uxCG
9+WOVbQWRt9EWJn7yskXW71PNP6pVv+QKWAb6m/M7eoYUQueks9oZlyi
-----END PRIVATE KEY-----`

func TestGenerateExpired(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			"root.yaml": "version: 1\nsubject: CN=TestRootExpired",
			"root.pem":  expiredCert + "\n" + expiredKey,
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	_, err := quickUpdate(testdb, db.UpdateExpired)
	if err != nil {
		t.Fatal(err.Error())
	}

	newPem, _ := fs.ReadFile(fsdb.Fs(), "root.pem")
	if strings.Contains(string(newPem), expiredCert) {
		t.Fatal("expected certificate to change")
	}
}

func TestGenerateExpiredExplicit(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			//validity is set in past, so Generate Expired should not update this one
			"root.yaml": "version: 1\nsubject: CN=TestRootExpired\nvalidity:\n  until: 2000-01-01",
			"root.pem":  expiredCert + "\n" + expiredKey,
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	_, err := quickUpdate(testdb, db.UpdateExpired)
	if err != nil {
		t.Fatal(err.Error())
	}

	newPem, _ := fs.ReadFile(fsdb.Fs(), "root.pem")
	if !strings.Contains(string(newPem), expiredCert) {
		t.Fatal("expected certificate not to change")
	}
}

func TestGenerateExpiredExplicitFuture(t *testing.T) {
	fsdb := getTestFs(
		map[string]string{
			//new generation would not result in an expried certificate, so its ok
			"root.yaml": "version: 1\nsubject: CN=TestRootExpired\nvalidity:\n  until: 2150-01-01",
			"root.pem":  expiredCert + "\n" + expiredKey,
		},
	)

	testdb := NewFilesystemDatabase(fsdb)
	_, err := quickUpdate(testdb, db.UpdateExpired)
	if err != nil {
		t.Fatal(err.Error())
	}

	newPem, _ := fs.ReadFile(fsdb.Fs(), "root.pem")
	if strings.Contains(string(newPem), expiredCert) {
		t.Fatal("expected certificate to change")
	}
}
