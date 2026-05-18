package root

import (
	"testing"
	"time"

	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

func setupSignableRoot(t *testing.T, dir string) (rootPath, keyPath string) {
	t.Helper()
	rootPath = initRoot(t, dir)
	keyPath = generateECKeyFile(t, dir, "sign-key.pem")

	for _, role := range []string{tufmeta.ROOT, tufmeta.TARGETS, tufmeta.SNAPSHOT, tufmeta.TIMESTAMP} {
		SetThreshold(SetThresholdOptions{Path: rootPath, Role: role, Threshold: 1})
	}
	AddKey(AddKeyOptions{
		Path:     rootPath,
		KeyPaths: []string{keyPath},
		Roles:    []string{tufmeta.ROOT, tufmeta.TARGETS, tufmeta.SNAPSHOT, tufmeta.TIMESTAMP},
	})
	Expire(ExpireOptions{Path: rootPath, Expires: time.Now().Add(365 * 24 * time.Hour)})

	return rootPath, keyPath
}

func TestSign(t *testing.T) {
	dir := t.TempDir()
	rootPath, keyPath := setupSignableRoot(t, dir)

	err := Sign(SignOptions{
		Path:     rootPath,
		KeyPaths: []string{keyPath},
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	md := readRoot(t, rootPath)
	if len(md.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(md.Signatures))
	}
	if len(md.Signatures[0].Signature) == 0 {
		t.Fatal("expected non-empty signature value")
	}
}

func TestSign_IncrementalReplace(t *testing.T) {
	dir := t.TempDir()
	rootPath, keyPath := setupSignableRoot(t, dir)

	Sign(SignOptions{Path: rootPath, KeyPaths: []string{keyPath}})
	Sign(SignOptions{Path: rootPath, KeyPaths: []string{keyPath}})

	md := readRoot(t, rootPath)
	if len(md.Signatures) != 1 {
		t.Fatalf("expected 1 signature (replaced), got %d", len(md.Signatures))
	}
}

func TestSign_CrossSign(t *testing.T) {
	dir := t.TempDir()
	rootPath, keyPath := setupSignableRoot(t, dir)
	Sign(SignOptions{Path: rootPath, KeyPaths: []string{keyPath}})

	newRootPath := initRoot(t, dir+"2")
	key2Path := generateECKeyFile(t, dir+"2", "key2.pem")
	for _, role := range []string{tufmeta.ROOT, tufmeta.TARGETS, tufmeta.SNAPSHOT, tufmeta.TIMESTAMP} {
		SetThreshold(SetThresholdOptions{Path: newRootPath, Role: role, Threshold: 1})
	}
	AddKey(AddKeyOptions{
		Path:     newRootPath,
		KeyPaths: []string{keyPath, key2Path},
		Roles:    []string{tufmeta.ROOT, tufmeta.TARGETS, tufmeta.SNAPSHOT, tufmeta.TIMESTAMP},
	})
	BumpVersion(BumpVersionOptions{Path: newRootPath})
	Expire(ExpireOptions{Path: newRootPath, Expires: time.Now().Add(365 * 24 * time.Hour)})

	err := Sign(SignOptions{
		Path:          newRootPath,
		KeyPaths:      []string{keyPath},
		CrossSignPath: rootPath,
	})
	if err != nil {
		t.Fatalf("Cross-sign failed: %v", err)
	}

	md := readRoot(t, newRootPath)
	if len(md.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(md.Signatures))
	}
}

func TestSign_InvalidRootPath(t *testing.T) {
	err := Sign(SignOptions{Path: "/nonexistent", KeyPaths: []string{"key.pem"}})
	if err == nil {
		t.Fatal("expected error for nonexistent root.json")
	}
}

func TestSign_InvalidCrossSignPath(t *testing.T) {
	dir := t.TempDir()
	rootPath, keyPath := setupSignableRoot(t, dir)

	err := Sign(SignOptions{
		Path:          rootPath,
		KeyPaths:      []string{keyPath},
		CrossSignPath: "/nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent cross-sign path")
	}
}

func TestSign_InvalidKeyPath(t *testing.T) {
	dir := t.TempDir()
	rootPath, _ := setupSignableRoot(t, dir)

	err := Sign(SignOptions{
		Path:     rootPath,
		KeyPaths: []string{"/nonexistent/key.pem"},
	})
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestSign_KeyNotInRoot(t *testing.T) {
	dir := t.TempDir()
	rootPath, _ := setupSignableRoot(t, dir)
	unknownKey := generateECKeyFile(t, dir, "unknown.pem")

	err := Sign(SignOptions{
		Path:     rootPath,
		KeyPaths: []string{unknownKey},
	})
	if err == nil {
		t.Fatal("expected error for key not in root.json")
	}
}

func TestSign_ThresholdNotMet(t *testing.T) {
	dir := t.TempDir()
	rootPath := initRoot(t, dir)
	key1Path := generateECKeyFile(t, dir, "key1.pem")
	key2Path := generateECKeyFile(t, dir, "key2.pem")

	SetThreshold(SetThresholdOptions{Path: rootPath, Role: tufmeta.ROOT, Threshold: 2})
	for _, role := range []string{tufmeta.TARGETS, tufmeta.SNAPSHOT, tufmeta.TIMESTAMP} {
		SetThreshold(SetThresholdOptions{Path: rootPath, Role: role, Threshold: 1})
	}
	AddKey(AddKeyOptions{
		Path:     rootPath,
		KeyPaths: []string{key1Path, key2Path},
		Roles:    []string{tufmeta.ROOT, tufmeta.TARGETS, tufmeta.SNAPSHOT, tufmeta.TIMESTAMP},
	})
	Expire(ExpireOptions{Path: rootPath, Expires: time.Now().Add(365 * 24 * time.Hour)})

	err := Sign(SignOptions{
		Path:     rootPath,
		KeyPaths: []string{key1Path},
	})
	if err == nil {
		t.Fatal("expected error: root threshold=2 but only 1 signature")
	}
}

func TestSign_IgnoreThreshold(t *testing.T) {
	dir := t.TempDir()
	rootPath := initRoot(t, dir)
	key1Path := generateECKeyFile(t, dir, "key1.pem")
	key2Path := generateECKeyFile(t, dir, "key2.pem")

	SetThreshold(SetThresholdOptions{Path: rootPath, Role: tufmeta.ROOT, Threshold: 2})
	for _, role := range []string{tufmeta.TARGETS, tufmeta.SNAPSHOT, tufmeta.TIMESTAMP} {
		SetThreshold(SetThresholdOptions{Path: rootPath, Role: role, Threshold: 1})
	}
	AddKey(AddKeyOptions{
		Path:     rootPath,
		KeyPaths: []string{key1Path, key2Path},
		Roles:    []string{tufmeta.ROOT, tufmeta.TARGETS, tufmeta.SNAPSHOT, tufmeta.TIMESTAMP},
	})
	Expire(ExpireOptions{Path: rootPath, Expires: time.Now().Add(365 * 24 * time.Hour)})

	err := Sign(SignOptions{
		Path:            rootPath,
		KeyPaths:        []string{key1Path},
		IgnoreThreshold: true,
	})
	if err != nil {
		t.Fatalf("Sign with IgnoreThreshold should succeed: %v", err)
	}
}

func TestSign_MultipleKeys(t *testing.T) {
	dir := t.TempDir()
	rootPath := initRoot(t, dir)
	key1Path := generateECKeyFile(t, dir, "key1.pem")
	key2Path := generateECKeyFile(t, dir, "key2.pem")

	SetThreshold(SetThresholdOptions{Path: rootPath, Role: tufmeta.ROOT, Threshold: 2})
	for _, role := range []string{tufmeta.TARGETS, tufmeta.SNAPSHOT, tufmeta.TIMESTAMP} {
		SetThreshold(SetThresholdOptions{Path: rootPath, Role: role, Threshold: 1})
	}
	AddKey(AddKeyOptions{
		Path:     rootPath,
		KeyPaths: []string{key1Path, key2Path},
		Roles:    []string{tufmeta.ROOT, tufmeta.TARGETS, tufmeta.SNAPSHOT, tufmeta.TIMESTAMP},
	})
	Expire(ExpireOptions{Path: rootPath, Expires: time.Now().Add(365 * 24 * time.Hour)})

	err := Sign(SignOptions{
		Path:     rootPath,
		KeyPaths: []string{key1Path, key2Path},
	})
	if err != nil {
		t.Fatalf("Sign with multiple keys failed: %v", err)
	}

	md := readRoot(t, rootPath)
	if len(md.Signatures) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(md.Signatures))
	}
}

func TestValidateThreshold_InsufficientKeys(t *testing.T) {
	md := &tufmeta.Metadata[tufmeta.RootType]{
		Signed: tufmeta.RootType{
			Roles: map[string]*tufmeta.Role{
				tufmeta.ROOT: {Threshold: 2, KeyIDs: []string{"key1"}},
			},
		},
	}

	err := validateThreshold(md)
	if err == nil {
		t.Fatal("expected error for insufficient keys")
	}
}

func TestValidateThreshold_InsufficientSignatures(t *testing.T) {
	md := &tufmeta.Metadata[tufmeta.RootType]{
		Signed: tufmeta.RootType{
			Roles: map[string]*tufmeta.Role{
				tufmeta.ROOT: {Threshold: 2, KeyIDs: []string{"key1", "key2"}},
			},
		},
		Signatures: []tufmeta.Signature{
			{KeyID: "key1", Signature: tufmeta.HexBytes("sig1")},
		},
	}

	err := validateThreshold(md)
	if err == nil {
		t.Fatal("expected error for insufficient signatures")
	}
}

func TestValidateThreshold_Pass(t *testing.T) {
	md := &tufmeta.Metadata[tufmeta.RootType]{
		Signed: tufmeta.RootType{
			Roles: map[string]*tufmeta.Role{
				tufmeta.ROOT:      {Threshold: 1, KeyIDs: []string{"key1"}},
				tufmeta.TARGETS:   {Threshold: 1, KeyIDs: []string{"key1"}},
				tufmeta.SNAPSHOT:  {Threshold: 1, KeyIDs: []string{"key1"}},
				tufmeta.TIMESTAMP: {Threshold: 1, KeyIDs: []string{"key1"}},
			},
		},
		Signatures: []tufmeta.Signature{
			{KeyID: "key1", Signature: tufmeta.HexBytes("sig1")},
		},
	}

	err := validateThreshold(md)
	if err != nil {
		t.Fatalf("validateThreshold should pass: %v", err)
	}
}
