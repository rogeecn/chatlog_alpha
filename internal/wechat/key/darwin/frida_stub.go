//go:build !darwin

package darwin

import (
	"context"
	"fmt"
)

// FridaAvailable is only meaningful on macOS.
func FridaAvailable() bool { return false }

// ExtractKeyViaFrida is only supported on macOS.
func ExtractKeyViaFrida(ctx context.Context, dataDir string, status func(string)) (string, error) {
	_ = ctx
	_ = dataDir
	_ = status
	return "", fmt.Errorf("Frida 提 key 仅支持 macOS")
}

// ApplyCapturedKeyToDataDir is only supported on macOS.
func ApplyCapturedKeyToDataDir(dataDir, keyHex string, status func(string)) (string, int, error) {
	_ = dataDir
	_ = keyHex
	_ = status
	return "", 0, fmt.Errorf("Frida 提 key 仅支持 macOS")
}
