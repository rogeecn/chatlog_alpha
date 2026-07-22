//go:build darwin

package send

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"howett.net/plist"
)

const (
	weChatAppPath   = "/Applications/WeChat.app"
	weChatInfoPlist = weChatAppPath + "/Contents/Info.plist"
	weChatDylibPath = weChatAppPath + "/Contents/Resources/wechat.dylib"
	maxNativeOutput = 1024 * 1024
)

//go:embed assets
var senderAssets embed.FS

var stepLinePattern = regexp.MustCompile(`^\[(\d+)/(\d+)\]\s*(.*)$`)
var commandLinePattern = regexp.MustCompile(`^\[命令:([^]]+)\]\s*(.*)$`)

type platformRunner struct{}

func newPlatformRunner() Runner { return &platformRunner{} }

func (r *platformRunner) Environment(ctx context.Context) Environment {
	env := Environment{
		Platform:         runtime.GOOS,
		Architecture:     runtime.GOARCH,
		ProfileVersion:   SupportedWeChatVersion,
		ElevationCapable: fileExists("/usr/bin/osascript"),
	}
	env.WeChatInstalled = fileExists(weChatInfoPlist) && fileExists(weChatDylibPath)
	if env.WeChatInstalled {
		env.WeChatVersion, env.WeChatBuild = readWeChatVersion()
		env.ProfileMatched = env.WeChatVersion == SupportedWeChatVersion
		env.DylibSHA256 = fileSHA256(weChatDylibPath)
	}
	env.WeChatPID = findWeChatPID()
	env.WeChatRunning = env.WeChatPID > 0

	if py, err := findPython(); err == nil {
		env.PythonPath = py
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(probeCtx, py, "-c", "import frida; print(frida.__version__)").CombinedOutput()
		if err == nil {
			env.FridaVersion = strings.TrimSpace(string(out))
		}
	}

	switch {
	case runtime.GOARCH != "arm64":
		env.Reason = "当前内置 hook profile 仅支持 darwin-arm64"
	case !env.WeChatInstalled:
		env.Reason = "未找到 /Applications/WeChat.app"
	case !env.ProfileMatched:
		env.Reason = fmt.Sprintf("微信版本 %s 与 hook profile %s 不匹配", fallback(env.WeChatVersion, "未知"), SupportedWeChatVersion)
	case env.PythonPath == "":
		env.Reason = "未找到 python3"
	case env.FridaVersion == "":
		env.Reason = "Python Frida 不可用，请先安装 frida-tools"
	case !env.WeChatRunning:
		env.Reason = "微信主进程未运行或尚未登录"
	default:
		env.Supported = true
	}
	return env
}

func (r *platformRunner) Run(ctx context.Context, request Request, report Reporter) (Result, error) {
	request, err := request.Normalized()
	if err != nil {
		return Result{}, err
	}
	if request.ManualRelease && request.Release == nil {
		return Result{}, fmt.Errorf("manual release requires a release signal")
	}
	emit(report, "info", "environment", 0, 0, "检查 macOS、微信版本、Python 和 Frida")
	env := r.Environment(ctx)
	if !env.Supported {
		return Result{}, fmt.Errorf("发送环境不可用: %s", env.Reason)
	}
	root, cleanup, err := materializeAssets()
	if err != nil {
		return Result{}, err
	}
	defer cleanup()
	if request.ManualRelease {
		request.releaseFile = filepath.Join(root, "manual-release")
		request.commandDir = filepath.Join(root, "commands")
		if err := os.MkdirAll(request.commandDir, 0o700); err != nil {
			return Result{}, fmt.Errorf("create persistent command directory: %w", err)
		}
		stopReleaseWatcher := make(chan struct{})
		releaseWatcherDone := make(chan struct{})
		go func() {
			defer close(releaseWatcherDone)
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			commands := request.Commands
			readySeen := false
			for {
				select {
				case <-request.Release:
					if err := os.WriteFile(request.releaseFile, []byte("release\n"), 0o600); err != nil {
						emit(report, "error", "manual_release", 0, 0, "写入手动释放指令失败: "+err.Error())
					}
					return
				case command, ok := <-commands:
					if !ok {
						commands = nil
						continue
					}
					if err := writePersistentCommand(root, request.commandDir, command); err != nil {
						emitCommand(report, "error", command.ID, "连续发送入队失败: "+err.Error())
					}
				case <-ticker.C:
					emitPersistentCommandResults(request.commandDir, report)
					ready := fileExists(request.releaseFile + ".ready")
					if ready && !readySeen {
						emit(report, "info", "manual_release", 0, 0, "当前 Frida session 可继续发送；等待下一次发送或手动释放")
					}
					readySeen = ready
				case <-ctx.Done():
					// Cancellation is not a successful manual release, but creating the
					// same file lets an elevated Python process that is already waiting
					// leave its hold and execute its normal finally cleanup path.
					_ = os.WriteFile(request.releaseFile, []byte("cancel\n"), 0o600)
					return
				case <-stopReleaseWatcher:
					return
				}
			}
		}()
		defer func() {
			close(stopReleaseWatcher)
			<-releaseWatcherDone
		}()
	}

	if request.MessageType == MessageImage {
		if request.Operation == OperationSend {
			imagePath, imageCleanup, err := resolveImage(root, request)
			if err != nil {
				return Result{}, err
			}
			defer imageCleanup()
			request.ImagePath = imagePath
			request.ImageData = ""
		} else {
			imagePath, err := writeProbeImage(root)
			if err != nil {
				return Result{}, err
			}
			request.ImagePath = imagePath
		}
	}

	args := buildArgs(root, env, request)
	elevationPython := env.PythonPath
	elevationArgs := args
	elevationRequest := request
	result := Result{Receiver: request.Receiver(), ExitCode: -1}
	emit(report, "info", "launch", 0, 0, fmt.Sprintf("启动可复用 Frida session，初始目标 %s", request.Receiver()))
	exitCode, output, err := runStreaming(ctx, env.PythonPath, args, report, commandTimeout(request), request.ManualRelease)
	result.ExitCode = exitCode
	if err == nil {
		return result, nil
	}
	if shouldRetryImageAfterControlledRestart(request, output) {
		emit(report, "warning", "recovery", 0, 0, "检测到微信图片上传服务未就绪(-20001)或上传参数校验失败(-20003)；受控重启已完成，正在自动重试一次")
		retryEnv := r.Environment(ctx)
		if retryEnv.Supported && retryEnv.WeChatPID > 0 && retryEnv.WeChatPID != env.WeChatPID {
			retryRequest := request
			retryRequest.PID = retryEnv.WeChatPID
			retryArgs := buildArgs(root, retryEnv, retryRequest)
			elevationPython = retryEnv.PythonPath
			elevationArgs = retryArgs
			elevationRequest = retryRequest
			emit(report, "info", "launch", 0, 0, fmt.Sprintf("使用新 WeChat PID %d 重新建立可复用 Frida session", retryEnv.WeChatPID))
			exitCode, output, err = runStreaming(ctx, retryEnv.PythonPath, retryArgs, report, commandTimeout(retryRequest), retryRequest.ManualRelease)
			result.ExitCode = exitCode
			if err == nil {
				return result, nil
			}
		} else {
			emit(report, "error", "recovery", 0, 0, "微信已尝试重启，但新进程环境检查未通过；停止自动重试")
		}
	}

	if !request.AllowElevation || !isAttachPermissionError(output) || nativeTriggerStarted(output) {
		return result, describeNativeRunError(err, output)
	}

	emit(report, "warning", "elevation", 0, 0, "普通权限无法 attach；正在弹出 macOS 管理员授权窗口")
	exitCode, output, elevatedErr := runElevated(
		ctx,
		elevationPython,
		elevationArgs,
		report,
		commandTimeout(elevationRequest),
		elevationRequest.releaseFile,
	)
	result.Elevated = true
	result.ExitCode = exitCode
	if elevatedErr != nil {
		return result, fmt.Errorf("elevated native send task failed: %w; %s", elevatedErr, lastUsefulLine(output))
	}
	return result, nil
}

func buildArgs(root string, env Environment, request Request) []string {
	var args []string
	useMixedSendHost := request.Operation == OperationSend && request.ManualRelease
	if request.MessageType == MessageImage || useMixedSendHost {
		args = []string{
			filepath.Join(root, "native_send_image_once.py"),
			"--message-type", string(request.MessageType),
			"--receiver", request.Receiver(),
			"--health-check-seconds", "30",
			"--output", filepath.Join(root, "image-events.jsonl"),
		}
		if request.Operation == OperationProbe {
			args = append(args, "--attach-smoke", "--context-timeout", "45", "--attach-timeout", "20", "--controlled-restart-on-attach-timeout", "--image", request.ImagePath)
		} else {
			if request.MessageType == MessageImage {
				args = append(args, "--image", request.ImagePath)
			} else {
				args = append(args, "--message", request.Content)
				if request.AtUser != "" {
					args = append(args, "--at-user", request.AtUser)
				}
			}
			args = append(args,
				"--execute",
				"--i-accept-freeze-risk",
				"--i-accept-image-known-freeze-risk",
				"--use-static-image-callback-profile",
				"--proactive-upload-wrapper",
				"--context-timeout", "45",
				"--attach-timeout", "20",
				"--controlled-restart-on-attach-timeout",
				"--upload-timeout", "90",
				"--upload-readiness-seconds", "180",
				"--timeout", "60",
				"--post-finish-hold", "5",
				"--cleanup-timeout", "45",
				"--controlled-restart-on-release",
			)
			if request.Sender != "" {
				args = append(args, "--sender", request.Sender)
			}
		}
	} else {
		content := request.Content
		if content == "" {
			content = "CHATLOG-HOOK-PROBE"
		}
		args = []string{
			filepath.Join(root, "native_send_once.py"),
			"--receiver", request.Receiver(),
			"--message", content,
			"--health-check-seconds", "12",
			"--output", filepath.Join(root, "text-events.jsonl"),
		}
		if request.AtUser != "" {
			args = append(args, "--at-user", request.AtUser)
		}
		if request.Operation == OperationProbe {
			args = append(args, "--attach-smoke", "--context-timeout", "20", "--attach-timeout", "20", "--controlled-restart-on-attach-timeout")
		} else {
			args = append(args,
				"--execute",
				"--i-accept-freeze-risk",
				"--context-timeout", "20",
				"--attach-timeout", "20",
				"--controlled-restart-on-attach-timeout",
				"--timeout", "35",
				"--inter-send-delay", "0.5",
				"--post-finish-hold", "5",
			)
		}
	}
	if request.PID > 0 {
		args = append(args, "--pid", strconv.Itoa(request.PID))
	} else if env.WeChatPID > 0 {
		args = append(args, "--pid", strconv.Itoa(env.WeChatPID))
	}
	if request.ManualRelease {
		args = append(args,
			"--manual-release-file", request.releaseFile,
			"--command-dir", request.commandDir,
		)
	}
	return args
}

func commandTimeout(request Request) time.Duration {
	if request.Operation == OperationProbe {
		return time.Minute
	}
	if request.MessageType == MessageImage {
		return 8 * time.Minute
	}
	return 2 * time.Minute
}

func runStreaming(
	ctx context.Context,
	executable string,
	args []string,
	report Reporter,
	timeout time.Duration,
	manualRelease bool,
) (int, string, error) {
	cmd := exec.Command(executable, args...)
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return -1, "", err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return -1, "", err
	}
	if err := cmd.Start(); err != nil {
		return -1, "", err
	}

	var output strings.Builder
	var outputMu sync.Mutex
	var wg sync.WaitGroup
	manualReleaseReached := make(chan struct{})
	var manualReleaseOnce sync.Once
	drain := func(reader io.Reader, level string) {
		defer wg.Done()
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 16*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			outputMu.Lock()
			appendBoundedOutput(&output, line+"\n")
			outputMu.Unlock()
			emitLine(report, level, line)
			if manualRelease && isManualReleaseWaitLine(line) {
				manualReleaseOnce.Do(func() { close(manualReleaseReached) })
			}
		}
	}
	wg.Add(2)
	go drain(stdout, "info")
	go drain(stderr, "error")
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	var timeoutTimer *time.Timer
	var timeoutCh <-chan time.Time
	if timeout > 0 {
		timeoutTimer = time.NewTimer(timeout)
		timeoutCh = timeoutTimer.C
		defer timeoutTimer.Stop()
	}
	manualReleaseCh := (<-chan struct{})(nil)
	if manualRelease {
		manualReleaseCh = manualReleaseReached
	}
	var waitErr error
	for {
		select {
		case waitErr = <-waitCh:
			goto finished
		case <-manualReleaseCh:
			// The native operation has succeeded and is intentionally holding
			// its session. Stop the execution watchdog; only an explicit release,
			// cancel, or service shutdown may end the hold now.
			manualReleaseCh = nil
			timeoutCh = nil
			if timeoutTimer != nil {
				timeoutTimer.Stop()
			}
		case <-ctx.Done():
			waitErr = stopNativeCommand(cmd, waitCh, report, "收到停止请求")
			if ctx.Err() != nil {
				waitErr = ctx.Err()
			}
			goto finished
		case <-timeoutCh:
			waitErr = stopNativeCommand(cmd, waitCh, report, "执行阶段超时")
			waitErr = context.DeadlineExceeded
			goto finished
		}
	}

finished:
	wg.Wait()
	exitCode := 0
	if waitErr != nil {
		exitCode = -1
		if ee, ok := waitErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		}
	}
	return exitCode, output.String(), waitErr
}

func stopNativeCommand(cmd *exec.Cmd, waitCh <-chan error, report Reporter, reason string) error {
	emit(report, "warning", "cleanup", 0, 0, reason+"，先向 Python 发送 SIGINT，等待 finally 释放 Frida")
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case err := <-waitCh:
		return err
	case <-time.After(120 * time.Second):
		emit(report, "error", "cleanup", 0, 0, "优雅清理超过 120 秒，终止注入宿主；图片受控重启和健康检查已获得完整收尾窗口")
		_ = cmd.Process.Kill()
		return <-waitCh
	}
}

func runElevated(
	ctx context.Context,
	python string,
	args []string,
	report Reporter,
	timeout time.Duration,
	manualReleaseFile string,
) (int, string, error) {
	home, _ := os.UserHomeDir()
	userSite := pythonUserSite(python)
	commandParts := []string{"/usr/bin/env", "PYTHONUNBUFFERED=1"}
	if home != "" {
		commandParts = append(commandParts, "HOME="+home)
	}
	if userSite != "" {
		commandParts = append(commandParts, "PYTHONPATH="+userSite)
	}
	commandParts = append(commandParts, python)
	commandParts = append(commandParts, args...)
	shellCommand := make([]string, 0, len(commandParts))
	for _, part := range commandParts {
		shellCommand = append(shellCommand, shellQuote(part))
	}
	baseCommand := strings.Join(shellCommand, " ")
	elevatedLogFile := ""
	if manualReleaseFile != "" {
		// `do shell script` buffers stdout until the privileged command exits.
		// A reusable session can live for hours, so redirect Python output to a
		// file and tail it from Go instead of accumulating an unbounded AppleEvent.
		elevatedLogFile = manualReleaseFile + ".elevated.log"
		quotedLog := shellQuote(elevatedLogFile)
		baseCommand = ": >" + quotedLog + "; /bin/chmod 0644 " + quotedLog + "; " +
			baseCommand + " >>" + quotedLog + " 2>&1"
	}
	// The Python host owns frida-helper as a direct child and cleans only helpers
	// whose PPID equals its own PID. Do not use a global pgrep/pkill trap here:
	// another Frida session may legitimately start while this job is running.
	wrappedCommand := baseCommand
	applescript := `do shell script "` + appleScriptEscape(wrappedCommand) + `" with administrator privileges`
	cmd := exec.Command("/usr/bin/osascript", "-e", applescript)
	var osascriptOutput strings.Builder
	var nativeOutput strings.Builder
	cmd.Stdout = &osascriptOutput
	cmd.Stderr = &osascriptOutput
	if err := cmd.Start(); err != nil {
		return -1, "", err
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	var timeoutTimer *time.Timer
	var timeoutCh <-chan time.Time
	if timeout > 0 {
		timeoutTimer = time.NewTimer(timeout)
		timeoutCh = timeoutTimer.C
		defer timeoutTimer.Stop()
	}
	var readyTicker *time.Ticker
	var readyCh <-chan time.Time
	readyFile := ""
	readyObserved := false
	var elevatedLogOffset int64
	if manualReleaseFile != "" {
		readyFile = manualReleaseFile + ".ready"
		readyTicker = time.NewTicker(200 * time.Millisecond)
		readyCh = readyTicker.C
		defer readyTicker.Stop()
	}
	var err error
	for {
		if elevatedLogFile != "" {
			emitElevatedLog(elevatedLogFile, &elevatedLogOffset, false, report, &nativeOutput)
		}
		if readyFile != "" && fileExists(readyFile) && !readyObserved {
			emit(report, "info", "manual_release", 0, 0, "操作已完成，Frida 保持连接；可以继续发送或手动释放")
			readyObserved = true
			timeoutCh = nil
			if timeoutTimer != nil {
				timeoutTimer.Stop()
			}
		}
		select {
		case err = <-waitCh:
			goto elevatedFinished
		case <-readyCh:
			continue
		case <-ctx.Done():
			err = stopNativeCommand(cmd, waitCh, report, "收到停止请求")
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			goto elevatedFinished
		case <-timeoutCh:
			_ = stopNativeCommand(cmd, waitCh, report, "执行阶段超时")
			err = context.DeadlineExceeded
			goto elevatedFinished
		}
	}

elevatedFinished:
	if elevatedLogFile != "" {
		emitElevatedLog(elevatedLogFile, &elevatedLogOffset, true, report, &nativeOutput)
	}
	if elevatedLogFile == "" {
		for _, line := range strings.Split(strings.TrimSpace(osascriptOutput.String()), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				emitLine(report, "info", line)
			}
		}
	}
	text := strings.TrimSpace(nativeOutput.String() + osascriptOutput.String())
	exitCode := 0
	if err != nil {
		exitCode = -1
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		}
	}
	return exitCode, text, err
}

func emitElevatedLog(path string, offset *int64, final bool, report Reporter, output *strings.Builder) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	if _, err := file.Seek(*offset, io.SeekStart); err != nil {
		return
	}
	data, err := io.ReadAll(file)
	if err != nil || len(data) == 0 {
		return
	}
	consume := len(data)
	if !final {
		if lastNewline := strings.LastIndexByte(string(data), '\n'); lastNewline >= 0 {
			consume = lastNewline + 1
		} else {
			return
		}
	}
	chunk := string(data[:consume])
	*offset += int64(consume)
	appendBoundedOutput(output, chunk)
	for _, line := range strings.Split(strings.TrimSpace(chunk), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			emitLine(report, "info", line)
		}
	}
}

func appendBoundedOutput(output *strings.Builder, value string) {
	if len(value) >= maxNativeOutput {
		output.Reset()
		output.WriteString(value[len(value)-maxNativeOutput:])
		return
	}
	if output.Len()+len(value) > maxNativeOutput {
		current := output.String()
		keep := maxNativeOutput - len(value)
		if keep > len(current) {
			keep = len(current)
		}
		output.Reset()
		if keep > 0 {
			output.WriteString(current[len(current)-keep:])
		}
	}
	output.WriteString(value)
}

func emitLine(report Reporter, level, line string) {
	if match := commandLinePattern.FindStringSubmatch(line); len(match) == 3 {
		emitCommand(report, level, strings.TrimSpace(match[1]), strings.TrimSpace(match[2]))
		return
	}
	if match := stepLinePattern.FindStringSubmatch(line); len(match) == 4 {
		step, _ := strconv.Atoi(match[1])
		total, _ := strconv.Atoi(match[2])
		emit(report, level, "native", step, total, match[3])
		return
	}
	stage := "native"
	if strings.HasPrefix(line, "[手动释放]") {
		stage = "manual_release"
	} else if strings.HasPrefix(line, "[事件]") {
		stage = "event"
	} else if strings.HasPrefix(line, "[清理]") || strings.Contains(line, "Frida helper") || strings.Contains(line, "session 已分离") {
		stage = "cleanup"
	} else if strings.HasPrefix(line, "[健康]") {
		stage = "health"
	} else if strings.HasPrefix(line, "[就绪]") {
		stage = "readiness"
	} else if strings.HasPrefix(line, "[保活]") || strings.HasPrefix(line, "[最终排空]") {
		stage = "drain"
	}
	emit(report, level, stage, 0, 0, line)
}

func isManualReleaseWaitLine(line string) bool {
	return strings.HasPrefix(line, "[手动释放]") && strings.Contains(line, "等待用户")
}

func emit(report Reporter, level, stage string, step, total int, message string) {
	if report == nil {
		return
	}
	report(Progress{Time: time.Now(), Level: level, Stage: stage, Step: step, Total: total, Message: message})
}

func emitCommand(report Reporter, level, commandID, message string) {
	if report == nil {
		return
	}
	report(Progress{
		Time:      time.Now(),
		Level:     level,
		Stage:     "command",
		CommandID: commandID,
		Message:   message,
	})
}

type persistentCommandPayload struct {
	CommandID   string      `json:"command_id"`
	Sequence    uint64      `json:"sequence"`
	MessageType MessageType `json:"message_type"`
	Receiver    string      `json:"receiver"`
	Content     string      `json:"content,omitempty"`
	AtUser      string      `json:"at_user,omitempty"`
	Sender      string      `json:"sender,omitempty"`
	ImagePath   string      `json:"image_path,omitempty"`
}

func writePersistentCommand(root string, commandDir string, command Command) error {
	request, err := command.Request.Normalized()
	if err != nil {
		return err
	}
	if request.Operation != OperationSend {
		return fmt.Errorf("persistent command must be a send operation")
	}
	payload := persistentCommandPayload{
		CommandID:   command.ID,
		Sequence:    command.Sequence,
		MessageType: request.MessageType,
		Receiver:    request.Receiver(),
		Content:     request.Content,
		AtUser:      request.AtUser,
		Sender:      request.Sender,
	}
	imageRoot := ""
	commandPublished := false
	defer func() {
		if imageRoot != "" && !commandPublished {
			_ = os.RemoveAll(imageRoot)
		}
	}()
	if request.MessageType == MessageImage {
		imageRoot = filepath.Join(root, "command-images", command.ID)
		if err := os.MkdirAll(imageRoot, 0o700); err != nil {
			return err
		}
		imagePath, _, err := resolveImage(imageRoot, request)
		if err != nil {
			return err
		}
		payload.ImagePath = imagePath
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	base := fmt.Sprintf("%020d-%s", command.Sequence, command.ID)
	temporary := filepath.Join(commandDir, base+".tmp")
	final := filepath.Join(commandDir, base+".json")
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, final); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	commandPublished = true
	return nil
}

func emitPersistentCommandResults(commandDir string, report Reporter) {
	for _, suffix := range []string{".done", ".failed"} {
		paths, _ := filepath.Glob(filepath.Join(commandDir, "*"+suffix))
		sort.Strings(paths)
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			commandID := strings.TrimSuffix(filepath.Base(path), suffix)
			level := "info"
			message := "连续发送完成"
			if suffix == ".failed" {
				level = "error"
				message = "连续发送失败: " + strings.TrimSpace(string(data))
			}
			emitCommand(report, level, commandID, message)
			_ = os.Remove(path)
			_ = os.RemoveAll(filepath.Join(filepath.Dir(commandDir), "command-images", commandID))
		}
	}
}

func materializeAssets() (string, func(), error) {
	root, err := os.MkdirTemp("", "chatlog-wechat-send-*")
	if err != nil {
		return "", nil, fmt.Errorf("create sender runtime: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	err = fs.WalkDir(senderAssets, "assets", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel("assets", path)
		if err != nil || rel == "." {
			return err
		}
		target := filepath.Join(root, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		data, err := senderAssets.ReadFile(path)
		if err != nil {
			return err
		}
		mode := os.FileMode(0600)
		if strings.HasSuffix(target, ".py") {
			mode = 0700
		}
		return os.WriteFile(target, data, mode)
	})
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("materialize sender assets: %w", err)
	}
	return root, cleanup, nil
}

func resolveImage(root string, request Request) (string, func(), error) {
	if request.ImagePath != "" {
		path, err := filepath.Abs(request.ImagePath)
		if err != nil {
			return "", func() {}, err
		}
		st, err := os.Stat(path)
		if err != nil || st.IsDir() {
			return "", func() {}, fmt.Errorf("image path is not readable: %s", path)
		}
		if st.Size() <= 0 || st.Size() > MaxImageBytes {
			return "", func() {}, fmt.Errorf("image size must be between 1 and %d bytes", MaxImageBytes)
		}
		if _, err := validateImageFile(path); err != nil {
			return "", func() {}, err
		}
		return path, func() {}, nil
	}

	raw := request.ImageData
	mimeHint := ""
	if strings.HasPrefix(raw, "data:") {
		header, payload, ok := strings.Cut(raw, ",")
		if !ok || !strings.Contains(header, ";base64") {
			return "", func() {}, fmt.Errorf("image_data must be a base64 data URL")
		}
		mimeHint = strings.TrimPrefix(strings.Split(header, ";")[0], "data:")
		raw = payload
	}
	if len(raw) > (MaxImageBytes*4/3)+4096 {
		return "", func() {}, fmt.Errorf("image_data exceeds %d bytes", MaxImageBytes)
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", func() {}, fmt.Errorf("decode image_data: %w", err)
	}
	if len(data) == 0 || len(data) > MaxImageBytes {
		return "", func() {}, fmt.Errorf("image size must be between 1 and %d bytes", MaxImageBytes)
	}
	detected, err := validateImageBytes(data)
	if err != nil {
		return "", func() {}, err
	}
	if mimeHint != "" && !strings.HasPrefix(strings.ToLower(mimeHint), "image/") {
		return "", func() {}, fmt.Errorf("image_data MIME hint is not an image")
	}
	ext := imageExtension(detected)
	path := filepath.Join(root, "upload"+ext)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", func() {}, err
	}
	return path, func() { _ = os.Remove(path) }, nil
}

func validateImageFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open image: %w", err)
	}
	defer f.Close()
	header := make([]byte, 512)
	n, err := io.ReadFull(f, header)
	if err != nil && err != io.ErrUnexpectedEOF {
		return "", fmt.Errorf("read image header: %w", err)
	}
	detected, err := validateImageType(header[:n])
	if err != nil {
		return "", err
	}
	if detected == "image/png" || detected == "image/jpeg" || detected == "image/gif" {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return "", err
		}
		if _, _, err := image.DecodeConfig(f); err != nil {
			return "", fmt.Errorf("invalid image data: %w", err)
		}
	}
	return detected, nil
}

func validateImageBytes(data []byte) (string, error) {
	detected, err := validateImageType(data)
	if err != nil {
		return "", err
	}
	if detected == "image/png" || detected == "image/jpeg" || detected == "image/gif" {
		if _, _, err := image.DecodeConfig(bytes.NewReader(data)); err != nil {
			return "", fmt.Errorf("invalid image data: %w", err)
		}
	}
	return detected, nil
}

func validateImageType(data []byte) (string, error) {
	detected := strings.ToLower(strings.TrimSpace(strings.Split(http.DetectContentType(data), ";")[0]))
	switch detected {
	case "image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp":
		return detected, nil
	default:
		return "", fmt.Errorf("uploaded data is not a supported image (detected %s)", detected)
	}
}

func writeProbeImage(root string) (string, error) {
	const probePNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
	data, err := base64.StdEncoding.DecodeString(probePNG)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "hook-probe.png")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", err
	}
	return path, nil
}

func imageExtension(mimeType string) string {
	switch strings.ToLower(strings.TrimSpace(strings.Split(mimeType, ";")[0])) {
	case "image/jpeg":
		return ".jpg"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	case "image/bmp":
		return ".bmp"
	default:
		return ".png"
	}
}

func findPython() (string, error) {
	for _, name := range []string{"python3", "python"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("python3 not found")
}

func pythonUserSite(python string) string {
	out, err := exec.Command(python, "-c", "import site; print(site.getusersitepackages())").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func readWeChatVersion() (string, string) {
	data, err := os.ReadFile(weChatInfoPlist)
	if err != nil {
		return "", ""
	}
	var info struct {
		ShortVersion  string `plist:"CFBundleShortVersionString"`
		BundleVersion string `plist:"WeChatBundleVersion"`
		Build         string `plist:"CFBundleVersion"`
	}
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return "", ""
	}
	version := strings.TrimSpace(info.BundleVersion)
	if version == "" {
		version = strings.TrimSpace(info.ShortVersion)
	}
	return version, strings.TrimSpace(info.Build)
}

func findWeChatPID() int {
	out, err := exec.Command("/bin/ps", "-axo", "pid=,command=").Output()
	if err != nil {
		return 0
	}
	const executable = "/Applications/WeChat.app/Contents/MacOS/WeChat"
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && strings.Join(fields[1:], " ") == executable {
			pid, _ := strconv.Atoi(fields[0])
			return pid
		}
	}
	return 0
}

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func isAttachPermissionError(output string) bool {
	lower := strings.ToLower(output)
	for _, marker := range []string{
		"permission denied", "not permitted", "unable to access process", "failed to attach",
		"attach 失败", "process cannot be attached", "task_for_pid",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func nativeTriggerStarted(output string) bool {
	return strings.Contains(output, "[事件] 已调用 MMStartTask") ||
		strings.Contains(output, "[事件] 开始上传图片") ||
		strings.Contains(output, "[4/6] 触发") ||
		strings.Contains(output, "[5/8] 触发")
}

func shouldRetryImageAfterControlledRestart(request Request, output string) bool {
	if request.Operation != OperationSend || request.MessageType != MessageImage {
		return false
	}
	uploadRejected := strings.Contains(output, "-20001") || strings.Contains(output, "-20003")
	return uploadRejected &&
		strings.Contains(output, "WeChat 已受控重启") &&
		!strings.Contains(output, "图片上传完成") &&
		!strings.Contains(output, "开始发送图片")
}

func describeNativeRunError(err error, output string) error {
	lower := strings.ToLower(output)
	if strings.Contains(lower, "timeout was reached") && !nativeTriggerStarted(output) {
		return fmt.Errorf("Frida attach 超时；本任务创建的 helper 已清理。当前微信进程可能残留旧注入状态，请保存草稿并重启微信后再执行 Hook 检查: %w", err)
	}
	return fmt.Errorf("native send task failed: %w", err)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func appleScriptEscape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func lastUsefulLine(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return line
		}
	}
	return "no output"
}

func fallback(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}
