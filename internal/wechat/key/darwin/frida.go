//go:build darwin

package darwin

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/decrypt/common"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

const (
	defaultFridaTimeout = 180 * time.Second
	defaultWeChatExe    = "/Applications/WeChat.app/Contents/MacOS/WeChat"
	fridaScriptFileName = "wechat_key_frida.py"
)

// FridaAvailable reports whether python3 + frida can be used for key capture.
func FridaAvailable() bool {
	py, err := findPython3()
	if err != nil {
		return false
	}
	cmd := exec.Command(py, "-c", "import frida; print(frida.__version__)")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

// ExtractKeyViaFrida launches WeChat via LaunchServices (`open -a`), attaches
// Frida ASAP, hooks CCKeyDerivationPBKDF, captures the 32-byte DB password,
// validates against db_storage, and writes all_keys.json.
//
// Why not frida.spawn(raw binary)? Spawning the executable bypasses macOS
// LaunchServices / sandbox container setup, so WeChat often starts with an
// empty profile instead of ~/Library/Containers/com.tencent.xinWeChat/...
//
// status may be nil. dataDir may be empty at start (filled after login); when
// empty, the key is still returned if captured, but all_keys.json is only
// written when a dataDir can be resolved and at least one DB validates.
func ExtractKeyViaFrida(ctx context.Context, dataDir string, status func(string)) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if status != nil {
		status("检查 Frida 环境...")
	}
	if !FridaAvailable() {
		return "", fmt.Errorf("Frida 不可用：请先执行 pip3 install frida-tools")
	}

	scriptPath, cleanup, err := resolveFridaScript()
	if err != nil {
		return "", err
	}
	if cleanup != nil {
		defer cleanup()
	}

	exe := strings.TrimSpace(os.Getenv("WECHAT_EXE"))
	if exe == "" {
		exe = defaultWeChatExe
	}
	if st, err := os.Stat(exe); err != nil || st.IsDir() {
		return "", fmt.Errorf("未找到微信可执行文件: %s", exe)
	}

	timeout := defaultFridaTimeout
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 5*time.Second {
			timeout = rem
		}
	}

	py, err := findPython3()
	if err != nil {
		return "", err
	}

	// Default --mode open: open -a WeChat (sandbox container / user data intact)
	// then attach. Override with CHATLOG_FRIDA_MODE=spawn only if you accept empty profile.
	mode := strings.TrimSpace(os.Getenv("CHATLOG_FRIDA_MODE"))
	if mode == "" {
		mode = "open"
	}
	args := []string{
		scriptPath,
		"--mode", mode,
		"--json",
		"--timeout", fmt.Sprintf("%d", int(timeout.Seconds())),
		"--exe", exe,
	}
	cmd := exec.CommandContext(ctx, py, args...)
	// Ensure child is not left in a broken root-only environment when possible.
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("创建 Frida 输出管道失败: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("创建 Frida 错误管道失败: %w", err)
	}

	if status != nil {
		if mode == "open" {
			status("正在通过 open -a 启动微信（保留用户数据）并用 Frida Hook 密钥...")
		} else {
			status(fmt.Sprintf("正在通过 Frida mode=%s 提取密钥...", mode))
		}
	}
	log.Info().Str("script", scriptPath).Str("exe", exe).Str("mode", mode).Msg("starting frida key capture")

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("启动 Frida 脚本失败: %w", err)
	}

	// Drain stderr so the process cannot block on a full pipe.
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			log.Debug().Str("frida_stderr", line).Msg("frida")
			if status != nil && (strings.Contains(line, "ERROR") || strings.Contains(line, "error")) {
				status("Frida: " + line)
			}
		}
	}()

	var (
		capturedKey string
		lastErr     string
	)
	sc := bufio.NewScanner(stdout)
	// keys are short JSON lines; allow larger just in case
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var msg fridaMsg
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			log.Debug().Str("line", line).Msg("frida non-json line")
			continue
		}
		switch msg.Type {
		case "log", "status":
			if status != nil && msg.Message != "" {
				status(msg.Message)
			}
		case "error":
			if msg.Message != "" {
				lastErr = msg.Message
				if status != nil {
					status("Frida: " + msg.Message)
				}
			}
		case "key", "done":
			key := strings.ToLower(strings.TrimSpace(msg.Key))
			if len(key) == 64 {
				if _, err := hex.DecodeString(key); err == nil {
					capturedKey = key
					if status != nil {
						status("已捕获数据库密钥，正在验证...")
					}
					// Stop child immediately — session.detach can hang under WeChat.
					if cmd.Process != nil {
						_ = cmd.Process.Kill()
					}
					// Drain remaining scan in background is unnecessary; break out.
					goto fridaDone
				}
			}
		}
	}
fridaDone:
	_ = sc.Err()

	// Wait may return "signal: killed" after we force-kill on success — ignore if key ok.
	waitErr := cmd.Wait()
	if capturedKey == "" {
		if lastErr != "" {
			return "", fmt.Errorf("Frida 未捕获到密钥: %s", lastErr)
		}
		if waitErr != nil {
			return "", fmt.Errorf("Frida 提 key 失败: %w", waitErr)
		}
		return "", fmt.Errorf("Frida 未捕获到密钥（请登录微信并打开聊天窗口后重试）")
	}
	_ = waitErr

	// Optional: persist all_keys.json when dataDir is known.
	if dataDir != "" {
		if n, err := writeAllKeysFromCapturedKey(dataDir, capturedKey, status); err != nil {
			log.Warn().Err(err).Msg("write all_keys.json from frida key failed")
			if status != nil {
				status(fmt.Sprintf("密钥已捕获但写入 all_keys.json 失败: %v（仍返回密钥）", err))
			}
		} else if status != nil {
			status(fmt.Sprintf("已写入 all_keys.json（%d 条）", n))
		}
	}

	return capturedKey, nil
}

// ApplyCapturedKeyToDataDir validates a key against DBs under dataDir and writes all_keys.json.
func ApplyCapturedKeyToDataDir(dataDir, keyHex string, status func(string)) (string, int, error) {
	keyHex = strings.ToLower(strings.TrimSpace(keyHex))
	if len(keyHex) != 64 {
		return "", 0, fmt.Errorf("invalid key length")
	}
	if _, err := hex.DecodeString(keyHex); err != nil {
		return "", 0, fmt.Errorf("invalid key hex: %w", err)
	}
	n, err := writeAllKeysFromCapturedKey(dataDir, keyHex, status)
	if err != nil {
		return "", 0, err
	}
	key, err := loadAndValidateMessageKey(dataDir, status)
	if err != nil {
		// Still return the captured key if message preference failed but file was written.
		if n > 0 {
			return keyHex, n, nil
		}
		return "", n, err
	}
	return key, n, nil
}

type fridaMsg struct {
	Type       string `json:"type"`
	Message    string `json:"message"`
	Key        string `json:"key"`
	DerivedKey string `json:"derived_key"`
	Salt       string `json:"salt"`
	Rounds     int    `json:"rounds"`
	Len        int    `json:"len"`
	Count      int    `json:"count"`
}

func writeAllKeysFromCapturedKey(dataDir, keyHex string, status func(string)) (int, error) {
	accountDir, dbStorageDir := resolveDBDirs(dataDir)
	dbSalts, err := collectDBSalts(dbStorageDir)
	if err != nil {
		return 0, err
	}
	if len(dbSalts) == 0 {
		return 0, fmt.Errorf("未找到可用加密数据库（db_storage）")
	}

	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return 0, err
	}
	d, err := decrypt.NewDecryptor(model.PlatformDarwin, 4)
	if err != nil {
		return 0, err
	}

	// Account DBs share one passphrase. Validate against any DB that has a full page;
	// then write the same key for every encrypted db entry.
	validated := 0
	for _, ds := range dbSalts {
		dbPath := resolveDBPath(dataDir, ds.DBRel)
		dbInfo, err := common.OpenDBFile(dbPath, 4096)
		if err != nil {
			continue
		}
		if d.Validate(dbInfo.FirstPage, keyBytes) {
			validated++
		}
	}
	if validated == 0 {
		if status != nil {
			status("密钥尚未通过 DB 页校验，仍写入候选 all_keys.json 供后续使用")
		}
	} else if status != nil {
		status(fmt.Sprintf("密钥校验通过：%d 个数据库", validated))
	}

	out := map[string]keyFileEntry{}
	for _, ds := range dbSalts {
		out[ds.DBRel] = keyFileEntry{EncKey: keyHex}
	}

	keysPath := filepath.Join(accountDir, "all_keys.json")
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("序列化 all_keys.json 失败: %w", err)
	}
	if err := os.WriteFile(keysPath, raw, 0600); err != nil {
		return 0, fmt.Errorf("写入 %s 失败: %w", keysPath, err)
	}
	if err := normalizeAllKeysOwnership(keysPath); err != nil && status != nil {
		status(fmt.Sprintf("警告：all_keys.json 权限归一化失败：%v", err))
	}
	return len(out), nil
}

func findPython3() (string, error) {
	candidates := []string{"python3", "python"}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			// Prefer a python that can import nothing at least runs.
			return p, nil
		}
	}
	return "", fmt.Errorf("未找到 python3")
}

func resolveFridaScript() (path string, cleanup func(), err error) {
	// 1) Explicit env
	if p := strings.TrimSpace(os.Getenv("CHATLOG_FRIDA_SCRIPT")); p != "" {
		if st, e := os.Stat(p); e == nil && !st.IsDir() {
			return p, nil, nil
		}
	}

	// 2) Next to executable / cwd / repo scripts/
	search := []string{}
	if exe, e := os.Executable(); e == nil {
		dir := filepath.Dir(exe)
		search = append(search,
			filepath.Join(dir, "scripts", fridaScriptFileName),
			filepath.Join(dir, fridaScriptFileName),
		)
	}
	if wd, e := os.Getwd(); e == nil {
		search = append(search,
			filepath.Join(wd, "scripts", fridaScriptFileName),
			filepath.Join(wd, fridaScriptFileName),
		)
	}
	// walk up a few levels from cwd (dev: repo root)
	if wd, e := os.Getwd(); e == nil {
		cur := wd
		for i := 0; i < 5; i++ {
			search = append(search, filepath.Join(cur, "scripts", fridaScriptFileName))
			parent := filepath.Dir(cur)
			if parent == cur {
				break
			}
			cur = parent
		}
	}
	for _, p := range search {
		if st, e := os.Stat(p); e == nil && !st.IsDir() {
			return p, nil, nil
		}
	}

	// 3) Materialize embedded script to temp file
	tmp, e := os.CreateTemp("", "chatlog_wechat_key_frida_*.py")
	if e != nil {
		return "", nil, fmt.Errorf("创建临时 Frida 脚本失败: %w", e)
	}
	if _, e := io.WriteString(tmp, embeddedFridaScript); e != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("写入临时 Frida 脚本失败: %w", e)
	}
	if e := tmp.Close(); e != nil {
		os.Remove(tmp.Name())
		return "", nil, e
	}
	if e := os.Chmod(tmp.Name(), 0700); e != nil {
		os.Remove(tmp.Name())
		return "", nil, e
	}
	return tmp.Name(), func() { _ = os.Remove(tmp.Name()) }, nil
}
