package keys

import (
	"os"
	"strings"
	"testing"
)

// withPipeStdin replaces os.Stdin with a pipe (non-TTY) for the duration of the
// test, ensuring passphrase prompts don't block when tests run from a terminal.
func withPipeStdin(t *testing.T) {
	t.Helper()
	origStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = origStdin
		r.Close()
		w.Close()
	})
}

func TestNewPassphraseFunc_IndexedEnvVar(t *testing.T) {
	t.Setenv("TUF_KEY_PASSPHRASE_0", "pass-for-first")
	t.Setenv("TUF_KEY_PASSPHRASE_1", "pass-for-second")

	fn := NewPassphraseFunc([]string{"keys/a.pem", "keys/b.pem"})

	pass, err := fn("keys/a.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pass) != "pass-for-first" {
		t.Fatalf("expected pass-for-first, got %q", pass)
	}

	pass, err = fn("keys/b.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pass) != "pass-for-second" {
		t.Fatalf("expected pass-for-second, got %q", pass)
	}
}

func TestNewPassphraseFunc_GlobalFallback(t *testing.T) {
	t.Setenv("TUF_KEY_PASSPHRASE", "global-pass")

	fn := NewPassphraseFunc([]string{"keys/a.pem"})

	pass, err := fn("keys/a.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pass) != "global-pass" {
		t.Fatalf("expected global-pass, got %q", pass)
	}
}

func TestNewPassphraseFunc_IndexedOverridesGlobal(t *testing.T) {
	t.Setenv("TUF_KEY_PASSPHRASE", "global")
	t.Setenv("TUF_KEY_PASSPHRASE_0", "indexed")

	fn := NewPassphraseFunc([]string{"keys/a.pem"})

	pass, err := fn("keys/a.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pass) != "indexed" {
		t.Fatalf("expected indexed env var to take priority, got %q", pass)
	}
}

func TestNewPassphraseFunc_GlobalFallbackForUnknownPath(t *testing.T) {
	t.Setenv("TUF_KEY_PASSPHRASE", "global-pass")

	fn := NewPassphraseFunc([]string{"keys/a.pem"})

	pass, err := fn("keys/unknown.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pass) != "global-pass" {
		t.Fatalf("expected global-pass for unknown path, got %q", pass)
	}
}

func TestNewPassphraseFunc_NoEnvNoTerminal(t *testing.T) {
	withPipeStdin(t)
	fn := NewPassphraseFunc([]string{"keys/a.pem"})

	_, err := fn("keys/a.pem")
	if err == nil {
		t.Fatal("expected error when no env var and stdin is not a terminal")
	}
	if !strings.Contains(err.Error(), "TUF_KEY_PASSPHRASE") {
		t.Fatalf("error should mention TUF_KEY_PASSPHRASE, got: %v", err)
	}
	if !strings.Contains(err.Error(), "TUF_KEY_PASSPHRASE_0") {
		t.Fatalf("error should mention indexed env var, got: %v", err)
	}
}

func TestNewPassphraseFunc_NoEnvNoTerminalUnknownPath(t *testing.T) {
	withPipeStdin(t)
	fn := NewPassphraseFunc([]string{"keys/a.pem"})

	_, err := fn("keys/unknown.pem")
	if err == nil {
		t.Fatal("expected error when no env var and stdin is not a terminal")
	}
	if !strings.Contains(err.Error(), "TUF_KEY_PASSPHRASE") {
		t.Fatalf("error should mention TUF_KEY_PASSPHRASE, got: %v", err)
	}
	if strings.Contains(err.Error(), "TUF_KEY_PASSPHRASE_") {
		t.Fatalf("error should NOT mention indexed env var for unknown path, got: %v", err)
	}
}

func TestNewPassphraseFunc_EmptyKeyPaths(t *testing.T) {
	t.Setenv("TUF_KEY_PASSPHRASE", "global")

	fn := NewPassphraseFunc(nil)

	pass, err := fn("any-key.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pass) != "global" {
		t.Fatalf("expected global, got %q", pass)
	}
}

func TestNewPassphraseFunc_SkipsUnencryptedKeyIndex(t *testing.T) {
	t.Setenv("TUF_KEY_PASSPHRASE_0", "pass-for-first")
	t.Setenv("TUF_KEY_PASSPHRASE_2", "pass-for-third")

	fn := NewPassphraseFunc([]string{"keys/enc1.pem", "keys/plain.pem", "keys/enc2.pem"})

	pass, err := fn("keys/enc1.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pass) != "pass-for-first" {
		t.Fatalf("expected pass-for-first, got %q", pass)
	}

	pass, err = fn("keys/enc2.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pass) != "pass-for-third" {
		t.Fatalf("expected pass-for-third, got %q", pass)
	}
}

func TestNewPassphraseFunc_DuplicateKeyPathUsesFirstIndex(t *testing.T) {
	t.Setenv("TUF_KEY_PASSPHRASE_0", "first-occurrence")
	t.Setenv("TUF_KEY_PASSPHRASE_2", "second-occurrence")

	fn := NewPassphraseFunc([]string{"keys/a.pem", "keys/b.pem", "keys/a.pem"})

	pass, err := fn("keys/a.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pass) != "first-occurrence" {
		t.Fatalf("expected first-occurrence (index 0), got %q", pass)
	}
}

func TestPromptNewPassphrase_EnvVar(t *testing.T) {
	t.Setenv("TUF_KEYGEN_PASSPHRASE", "keygen-pass")

	pass, err := PromptNewPassphrase()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pass) != "keygen-pass" {
		t.Fatalf("expected keygen-pass, got %q", pass)
	}
}

func TestPromptNewPassphrase_NoEnvNoTerminal(t *testing.T) {
	withPipeStdin(t)
	_, err := PromptNewPassphrase()
	if err == nil {
		t.Fatal("expected error when no env var and stdin is not a terminal")
	}
	if !strings.Contains(err.Error(), "TUF_KEYGEN_PASSPHRASE") {
		t.Fatalf("error should mention TUF_KEYGEN_PASSPHRASE, got: %v", err)
	}
}
