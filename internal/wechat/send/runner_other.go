//go:build !darwin

package send

import (
	"context"
	"fmt"
	"runtime"
)

type platformRunner struct{}

func newPlatformRunner() Runner { return &platformRunner{} }

func (r *platformRunner) Environment(context.Context) Environment {
	return Environment{
		Platform:       runtime.GOOS,
		Architecture:   runtime.GOARCH,
		ProfileVersion: SupportedWeChatVersion,
		Reason:         "原生 Frida 发信调试当前仅支持 macOS arm64；Windows 构建不会加载 macOS hook 资产",
	}
}

func (r *platformRunner) Run(context.Context, Request, Reporter) (Result, error) {
	return Result{}, fmt.Errorf("%w: %s/%s", ErrUnsupported, runtime.GOOS, runtime.GOARCH)
}
