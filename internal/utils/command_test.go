package utils

import (
	"runtime"
	"strings"
	"testing"
)

func TestRunCommand_Echo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("echo test not applicable on Windows")
	}

	output, err := RunCommand("echo hello")
	if err != nil {
		t.Fatalf("RunCommand failed: %v", err)
	}

	if strings.TrimSpace(string(output)) != "hello" {
		t.Fatalf("expected 'hello', got %q", output)
	}
}

func TestRunCommand_EmptyCommand(t *testing.T) {
	_, err := RunCommand("")
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}

func TestRunCommand_NonexistentBinary(t *testing.T) {
	_, err := RunCommand("nonexistent_binary_xyz123")
	if err == nil {
		t.Fatal("expected error for nonexistent binary")
	}
}

func TestRunCommand_MultipleArgs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("not applicable on Windows")
	}

	output, err := RunCommand("printf %s test")
	if err != nil {
		t.Fatalf("RunCommand failed: %v", err)
	}
	if string(output) != "test" {
		t.Fatalf("expected 'test', got %q", output)
	}
}
