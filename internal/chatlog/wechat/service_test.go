package wechat

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestIsTemporaryFileLockError(t *testing.T) {
	if runtime.GOOS == "windows" && !isTemporaryFileLockError(fmt.Errorf("copy failed: %w", syscall.Errno(32))) {
		t.Fatal("wrapped Windows sharing violation should be temporary")
	}
	if runtime.GOOS != "windows" && isTemporaryFileLockError(fmt.Errorf("write failed: %w", syscall.Errno(32))) {
		t.Fatal("non-Windows errno 32 must not be treated as a file lock")
	}
	if !isTemporaryFileLockError(errors.New("sharing violation")) {
		t.Fatal("sharing-violation message should be temporary")
	}
	if !isTemporaryFileLockError(errors.New("device or resource busy")) {
		t.Fatal("busy-file message should be temporary")
	}
	if isTemporaryFileLockError(errors.New("incorrect database key")) {
		t.Fatal("key errors must remain fatal")
	}
}

func TestReplaceDecryptedFileReplacesPreviousOutput(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "message.db")
	temp := filepath.Join(dir, "message.db.tmp")
	if err := os.WriteFile(output, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(temp, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceDecryptedFile(temp, output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("output = %q, want new", data)
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatalf("temporary output still exists: %v", err)
	}
}
