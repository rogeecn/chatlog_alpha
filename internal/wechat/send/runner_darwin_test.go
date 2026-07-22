//go:build darwin

package send

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveImageDataURL(t *testing.T) {
	root := t.TempDir()
	path, cleanup, err := resolveImage(root, Request{
		ImageData: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if filepath.Ext(path) != ".png" {
		t.Fatalf("unexpected image path %q", path)
	}
	if st, err := os.Stat(path); err != nil || st.Size() == 0 {
		t.Fatalf("image was not materialized: stat=%v err=%v", st, err)
	}
}

func TestResolveImageDataURLRejectsFakeImageMIME(t *testing.T) {
	_, _, err := resolveImage(t.TempDir(), Request{
		ImageData: "data:image/png;base64,bm90LWFuLWltYWdl",
	})
	if err == nil || !strings.Contains(err.Error(), "not a supported image") {
		t.Fatalf("fake image data must be rejected, got %v", err)
	}
}

func TestValidateImageFileRejectsTruncatedPNG(t *testing.T) {
	path := filepath.Join(t.TempDir(), "truncated.png")
	if err := os.WriteFile(path, []byte("\x89PNG\r\n\x1a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateImageFile(path); err == nil || !strings.Contains(err.Error(), "invalid image data") {
		t.Fatalf("truncated PNG must be rejected, got %v", err)
	}
}

func TestBuildImageProbeArgsUsesTemporaryImage(t *testing.T) {
	root := t.TempDir()
	path, err := writeProbeImage(root)
	if err != nil {
		t.Fatal(err)
	}
	args := buildArgs(root, Environment{WeChatPID: 123}, Request{
		Operation:   OperationProbe,
		TargetType:  TargetGroup,
		MessageType: MessageImage,
		GroupID:     "123@chatroom",
		ImagePath:   path,
	})
	joined := strings.Join(args, " ")
	for _, expected := range []string{"--attach-smoke", "--image " + path, "--receiver 123@chatroom", "--pid 123"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("args %q missing %q", joined, expected)
		}
	}
	if strings.Contains(joined, "--controlled-restart-on-release") {
		t.Fatalf("probe args must not restart WeChat: %q", joined)
	}
}

func TestBuildImageSendArgsUseControlledRestart(t *testing.T) {
	root := t.TempDir()
	path, err := writeProbeImage(root)
	if err != nil {
		t.Fatal(err)
	}
	args := buildArgs(root, Environment{WeChatPID: 123}, Request{
		Operation:   OperationSend,
		TargetType:  TargetPrivate,
		MessageType: MessageImage,
		UserID:      "filehelper",
		ImagePath:   path,
		AcceptRisk:  true,
	})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--controlled-restart-on-release") {
		t.Fatalf("image send args must use controlled WeChat restart: %q", joined)
	}
	if !strings.Contains(joined, "--upload-readiness-seconds 180") {
		t.Fatalf("image send args must wait for WeChat upload readiness: %q", joined)
	}
	if !strings.Contains(joined, "--post-finish-hold 5") {
		t.Fatalf("image send args must use the five-second final safety window: %q", joined)
	}
}

func TestBuildTextSendArgsUseFiveSecondSafetyWindow(t *testing.T) {
	args := buildArgs(t.TempDir(), Environment{WeChatPID: 123}, Request{
		Operation:   OperationSend,
		TargetType:  TargetPrivate,
		MessageType: MessageText,
		UserID:      "filehelper",
		Content:     "five-second-window",
		AcceptRisk:  true,
	})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--post-finish-hold 5") {
		t.Fatalf("text send args must use the five-second final safety window: %q", joined)
	}
}

func TestBuildPersistentTextSendUsesMixedHost(t *testing.T) {
	args := buildArgs(t.TempDir(), Environment{WeChatPID: 123}, Request{
		Operation:     OperationSend,
		TargetType:    TargetPrivate,
		MessageType:   MessageText,
		UserID:        "filehelper",
		Content:       "mixed-host-text",
		Sender:        "wxid_sender",
		AcceptRisk:    true,
		ManualRelease: true,
		releaseFile:   "/tmp/release",
		commandDir:    "/tmp/commands",
	})
	joined := strings.Join(args, " ")
	for _, expected := range []string{
		"native_send_image_once.py",
		"--message-type text",
		"--message mixed-host-text",
		"--controlled-restart-on-release",
		"--post-finish-hold 5",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("mixed text args %q missing %q", joined, expected)
		}
	}
}

func TestImageAgentHasIdleStartTaskFallback(t *testing.T) {
	source, err := senderAssets.ReadFile("assets/native/image_send_agent.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, expected := range []string{"defaultStartTaskFuncAddr: 0x51173d0", "default_manager_wrapper"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("image agent missing idle StartTask fallback %q", expected)
		}
	}
}

func TestImageHostStagesBoundedUploadPath(t *testing.T) {
	source, err := senderAssets.ReadFile("assets/native_send_image_once.py")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, expected := range []string{
		"MAX_WECHAT_UPLOAD_PATH_BYTES = 176",
		"cl-{time.time_ns():x}",
		"#chatlog_md5_salt_",
		"signed32 != -20001",
		"shutdown_frida_runtime",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("image host missing bounded-path/readiness guard %q", expected)
		}
	}
	if strings.Contains(text, "signed32 not in {-20001, -20003}") {
		t.Fatal("image host must not retry parameter/path rejection -20003 in the same process")
	}
}

func TestSenderHostsCloseFridaDeviceManager(t *testing.T) {
	textHost, err := senderAssets.ReadFile("assets/native_send_once.py")
	if err != nil {
		t.Fatal(err)
	}
	imageHost, err := senderAssets.ReadFile("assets/native_send_image_once.py")
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{"text": string(textHost), "mixed": string(imageHost)} {
		if !strings.Contains(source, "shutdown_frida_runtime") {
			t.Fatalf("%s host does not close frida-python DeviceManager", name)
		}
	}
	if !strings.Contains(string(textHost), "frida_module.shutdown()") {
		t.Fatal("shared runtime cleanup must call the official frida.shutdown API")
	}
	if strings.Contains(string(textHost), `subprocess.run(["pkill"`) {
		t.Fatal("sender cleanup must not globally pkill unrelated Frida helpers")
	}
}

func TestImageAgentKeepsValidatedSyntheticUploadLayout(t *testing.T) {
	source, err := senderAssets.ReadFile("assets/native/image_send_agent.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, expected := range []string{
		"StartC2CUpload to reject the object with -20003",
		"const fileId = receiver + '_' + String(Math.floor(Date.now() / 1000))",
		"uploadImageX1.add(0x48).writePointer(imageIdAddr)",
		"uploadImageX1.add(0x68).writeUtf8String(receiver)",
		"uploadImageX1.add(0xe8).writePointer(imagePathAddr)",
		"uploadImageX1.add(0x118).writePointer(imagePathAddr)",
		"uploadImageX1.add(0x148).writePointer(imagePathAddr)",
		"receiver_string_mode: 'inline_static_profile'",
		"upload_image_incomplete",
		"aes_key_matches_request: aesKey === generation.uploadAesKey",
		"function triggerSendText(taskId, protoHex, payloadHex)",
		"sendMsgType === 'text' ? sendTextMessageAddr : sendImgMessageAddr",
		"trigger_send_text",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("image agent missing validated synthetic upload layout %q", expected)
		}
	}
	for _, forbidden := range []string{
		"receiver.slice(0, maxReceiverPrefix)",
		"file_id_receiver_truncated",
		"patchUploadReceiver(uploadImageX1.add(0x68)",
		"uploadImageX1.add(0x50).writeU64(utf8ByteLength(fileId))",
		"uploadImageX1.add(0xf0).writeU64(imagePathLength)",
		"uploadImageX1.add(0x120).writeU64(imagePathLength)",
		"uploadImageX1.add(0x150).writeU64(imagePathLength)",
		"callbackAesKey || generation.uploadAesKey",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("image agent reintroduced rejected upload layout fragment %q", forbidden)
		}
	}
}

func TestEmitLineClassifiesUploadReadiness(t *testing.T) {
	var got Progress
	emitLine(func(progress Progress) { got = progress }, "info", "[就绪] 微信进程运行 12 秒，15 秒后重试")
	if got.Stage != "readiness" || !strings.Contains(got.Message, "15 秒后重试") {
		t.Fatalf("unexpected readiness progress: %#v", got)
	}
}

func TestBuildArgsIncludesManualReleaseFile(t *testing.T) {
	root := t.TempDir()
	releaseFile := filepath.Join(root, "release")
	commandDir := filepath.Join(root, "commands")
	args := buildArgs(root, Environment{WeChatPID: 123}, Request{
		Operation:     OperationProbe,
		TargetType:    TargetPrivate,
		MessageType:   MessageText,
		UserID:        "filehelper",
		ManualRelease: true,
		releaseFile:   releaseFile,
		commandDir:    commandDir,
	})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--manual-release-file "+releaseFile) {
		t.Fatalf("args %q missing manual release file", joined)
	}
	if !strings.Contains(joined, "--command-dir "+commandDir) {
		t.Fatalf("args %q missing persistent command directory", joined)
	}
}

func TestWritePersistentTextCommand(t *testing.T) {
	root := t.TempDir()
	commandDir := filepath.Join(root, "commands")
	if err := os.MkdirAll(commandDir, 0o700); err != nil {
		t.Fatal(err)
	}
	err := writePersistentCommand(root, commandDir, Command{
		ID:       "command-id",
		Sequence: 7,
		Request: Request{
			Operation:   OperationSend,
			TargetType:  TargetPrivate,
			MessageType: MessageText,
			UserID:      "filehelper",
			Content:     "second message",
			AcceptRisk:  true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(commandDir, "*.json"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("unexpected command files %#v err=%v", paths, err)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{`"command_id":"command-id"`, `"sequence":7`, `"receiver":"filehelper"`, `"content":"second message"`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("command payload %q missing %q", text, expected)
		}
	}
}

func TestWritePersistentImageCommandsUseIndependentFiles(t *testing.T) {
	root := t.TempDir()
	commandDir := filepath.Join(root, "commands")
	if err := os.MkdirAll(commandDir, 0o700); err != nil {
		t.Fatal(err)
	}
	imageData := "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
	for sequence, id := range []string{"first-image", "second-image"} {
		err := writePersistentCommand(root, commandDir, Command{
			ID:       id,
			Sequence: uint64(sequence + 1),
			Request: Request{
				Operation:   OperationSend,
				TargetType:  TargetPrivate,
				MessageType: MessageImage,
				UserID:      "filehelper",
				ImageData:   imageData,
				AcceptRisk:  true,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	paths, err := filepath.Glob(filepath.Join(commandDir, "*.json"))
	if err != nil || len(paths) != 2 {
		t.Fatalf("unexpected command files %#v err=%v", paths, err)
	}
	imagePaths := make(map[string]struct{}, 2)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var payload persistentCommandPayload
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.ImagePath == "" || !fileExists(payload.ImagePath) {
			t.Fatalf("command image was not materialized: %#v", payload)
		}
		if !strings.HasPrefix(payload.ImagePath, filepath.Join(root, "command-images", payload.CommandID)+string(os.PathSeparator)) {
			t.Fatalf("command image escaped its private directory: %#v", payload)
		}
		imagePaths[payload.ImagePath] = struct{}{}
	}
	if len(imagePaths) != 2 {
		t.Fatalf("queued image commands reused a file: %#v", imagePaths)
	}
}

func TestRunStreamingStopsWatchdogAtManualRelease(t *testing.T) {
	started := time.Now()
	exitCode, output, err := runStreaming(
		context.Background(),
		"/bin/sh",
		[]string{"-c", "printf '[手动释放] 操作已完成，等待用户手动释放\\n'; sleep 0.35"},
		nil,
		100*time.Millisecond,
		true,
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("manual hold should outlive execution watchdog: code=%d err=%v output=%q", exitCode, err, output)
	}
	if time.Since(started) < 300*time.Millisecond {
		t.Fatalf("test command returned before its manual hold completed")
	}
}

func TestAppendBoundedOutput(t *testing.T) {
	var output strings.Builder
	appendBoundedOutput(&output, strings.Repeat("a", maxNativeOutput))
	appendBoundedOutput(&output, "tail")
	if output.Len() != maxNativeOutput {
		t.Fatalf("bounded output length=%d want=%d", output.Len(), maxNativeOutput)
	}
	if !strings.HasSuffix(output.String(), "tail") {
		t.Fatal("bounded output did not retain the newest text")
	}
}

func TestDescribeAttachTimeout(t *testing.T) {
	err := describeNativeRunError(context.DeadlineExceeded, "图片发送测试失败：timeout was reached")
	if !strings.Contains(err.Error(), "helper 已清理") || !strings.Contains(err.Error(), "重启微信") {
		t.Fatalf("unexpected error %q", err)
	}
}

func TestRetryImageAfterControlledRestart(t *testing.T) {
	request := Request{Operation: OperationSend, MessageType: MessageImage}
	for _, code := range []string{"-20001", "-20003"} {
		output := "微信上传入口拒绝请求 signed32=" + code + "\n[清理] WeChat 已受控重启：old_pid=1 new_pid=2。"
		if !shouldRetryImageAfterControlledRestart(request, output) {
			t.Fatalf("expected rejected image upload %s to retry after controlled restart", code)
		}
		if shouldRetryImageAfterControlledRestart(request, output+"\n[事件] 图片上传完成") {
			t.Fatalf("must not retry upload %s after upload completion", code)
		}
		if shouldRetryImageAfterControlledRestart(request, output+"\n[事件] 开始发送图片") {
			t.Fatalf("must not retry upload %s after send trigger", code)
		}
	}
	output := "微信上传入口拒绝请求 signed32=-20003\n[清理] WeChat 已受控重启：old_pid=1 new_pid=2。"
	request.MessageType = MessageText
	if shouldRetryImageAfterControlledRestart(request, output) {
		t.Fatal("text send must not use image recovery")
	}
}
