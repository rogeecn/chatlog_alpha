package http

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	wechatsend "github.com/sjzar/chatlog/internal/wechat/send"
)

type fakeSendRunner struct {
	block chan struct{}
	err   error
}

func (f *fakeSendRunner) Environment(context.Context) wechatsend.Environment {
	return wechatsend.Environment{Supported: true, Platform: "darwin", Architecture: "arm64"}
}

func (f *fakeSendRunner) Run(ctx context.Context, req wechatsend.Request, report wechatsend.Reporter) (wechatsend.Result, error) {
	report(wechatsend.Progress{Time: time.Now(), Stage: "native", Step: 1, Total: 2, Message: "started"})
	if f.block != nil {
		select {
		case <-ctx.Done():
			return wechatsend.Result{}, ctx.Err()
		case <-f.block:
		}
	}
	if f.err != nil {
		return wechatsend.Result{}, f.err
	}
	if req.ManualRelease {
		if req.Release == nil {
			return wechatsend.Result{}, errors.New("missing release channel")
		}
		report(wechatsend.Progress{Time: time.Now(), Stage: "manual_release", Message: "操作已完成，等待用户继续发送或手动释放"})
		for {
			select {
			case <-ctx.Done():
				return wechatsend.Result{}, ctx.Err()
			case <-req.Release:
				report(wechatsend.Progress{Time: time.Now(), Stage: "manual_release", Message: "已收到释放指令"})
				return wechatsend.Result{Receiver: req.Receiver(), ExitCode: 0}, nil
			case command := <-req.Commands:
				report(wechatsend.Progress{Time: time.Now(), Stage: "command", CommandID: command.ID, Message: "开始连续发送"})
				report(wechatsend.Progress{Time: time.Now(), Stage: "command", CommandID: command.ID, Message: "连续发送完成"})
				report(wechatsend.Progress{Time: time.Now(), Stage: "manual_release", Message: "操作已完成，等待用户继续发送或手动释放"})
			}
		}
	}
	return wechatsend.Result{Receiver: req.Receiver(), ExitCode: 0}, nil
}

func validProbeRequest() wechatsend.Request {
	return wechatsend.Request{
		Operation:   wechatsend.OperationProbe,
		TargetType:  wechatsend.TargetPrivate,
		MessageType: wechatsend.MessageText,
		UserID:      "filehelper",
	}
}

func waitSendDebugJob(t *testing.T, manager *sendDebugManager, id string) sendDebugJobView {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		view, ok := manager.get(id)
		if ok && !isActiveSendDebugState(view.State) {
			return view
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s did not finish", id)
	return sendDebugJobView{}
}

func waitSendDebugState(t *testing.T, manager *sendDebugManager, id, state string) sendDebugJobView {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		view, ok := manager.get(id)
		if ok && view.State == state {
			return view
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s did not reach state %s", id, state)
	return sendDebugJobView{}
}

func TestSendDebugManagerSuccessfulJob(t *testing.T) {
	manager := &sendDebugManager{runner: &fakeSendRunner{}, jobs: map[string]*sendDebugJob{}}
	created, err := manager.create(validProbeRequest())
	if err != nil {
		t.Fatal(err)
	}
	view := waitSendDebugJob(t, manager, created.ID)
	if view.State != "succeeded" {
		t.Fatalf("unexpected state %q error=%q", view.State, view.Error)
	}
	if view.Result == nil || view.Result.Receiver != "filehelper" {
		t.Fatalf("unexpected result %#v", view.Result)
	}
	if len(view.Progress) != 1 || view.Progress[0].Message != "started" {
		t.Fatalf("unexpected progress %#v", view.Progress)
	}
}

func TestSendDebugManagerKeepsFailureState(t *testing.T) {
	manager := &sendDebugManager{runner: &fakeSendRunner{err: errors.New("boom")}, jobs: map[string]*sendDebugJob{}}
	created, err := manager.create(validProbeRequest())
	if err != nil {
		t.Fatal(err)
	}
	view := waitSendDebugJob(t, manager, created.ID)
	if view.State != "failed" || view.Error != "boom" {
		t.Fatalf("unexpected failed job %#v", view)
	}
}

func TestSendDebugManagerWaitsForManualRelease(t *testing.T) {
	manager := &sendDebugManager{runner: &fakeSendRunner{}, jobs: map[string]*sendDebugJob{}}
	req := validProbeRequest()
	req.ManualRelease = true
	created, err := manager.create(req)
	if err != nil {
		t.Fatal(err)
	}
	waiting := waitSendDebugState(t, manager, created.ID, "waiting_release")
	if !waiting.ReleaseRequired || waiting.ReleaseRequested {
		t.Fatalf("unexpected manual release flags %#v", waiting)
	}
	active, ok := manager.active()
	if !ok || active.ID != created.ID || active.State != "waiting_release" {
		t.Fatalf("manual hold was not recoverable as active job: %#v", active)
	}
	if _, err := manager.create(validProbeRequest()); err == nil {
		t.Fatal("expected waiting manual-release job to block a concurrent task")
	}
	if !manager.release(created.ID) {
		t.Fatal("expected release request to be accepted")
	}
	view := waitSendDebugJob(t, manager, created.ID)
	if view.State != "succeeded" || !view.ReleaseRequested || view.ReleaseRequired {
		t.Fatalf("unexpected released job %#v", view)
	}
	if _, ok := manager.active(); ok {
		t.Fatal("completed job must not remain active")
	}
}

func TestImageManualReleaseReportsControlledRestart(t *testing.T) {
	release := make(chan struct{})
	job := &sendDebugJob{
		ID:      "image-job",
		State:   "waiting_release",
		release: release,
		raw: wechatsend.Request{
			Operation:   wechatsend.OperationSend,
			MessageType: wechatsend.MessageImage,
		},
	}
	manager := &sendDebugManager{jobs: map[string]*sendDebugJob{job.ID: job}}
	if !manager.release(job.ID) {
		t.Fatal("expected image release request to be accepted")
	}
	if len(job.Progress) != 1 || !strings.Contains(job.Progress[0].Message, "受控重启微信") {
		t.Fatalf("image release must explain controlled restart, progress=%#v", job.Progress)
	}
	select {
	case <-release:
	default:
		t.Fatal("image release channel was not closed")
	}
}

func TestSendDebugManagerQueuesContinuousSends(t *testing.T) {
	manager := &sendDebugManager{runner: &fakeSendRunner{}, jobs: map[string]*sendDebugJob{}}
	req := validProbeRequest()
	req.Operation = wechatsend.OperationSend
	req.Content = "首次发送"
	req.AcceptRisk = true
	req.ManualRelease = true
	created, err := manager.create(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = waitSendDebugState(t, manager, created.ID, "waiting_release")
	sendReq := wechatsend.Request{
		TargetType:  wechatsend.TargetPrivate,
		MessageType: wechatsend.MessageText,
		UserID:      "filehelper",
		Content:     "连续发送",
		AcceptRisk:  true,
	}
	firstID, err := manager.enqueue(created.ID, sendReq)
	if err != nil {
		t.Fatal(err)
	}
	imageReq := wechatsend.Request{
		TargetType:  wechatsend.TargetPrivate,
		MessageType: wechatsend.MessageImage,
		UserID:      "filehelper",
		ImagePath:   "/tmp/mixed-session-test.png",
		AcceptRisk:  true,
	}
	secondID, err := manager.enqueue(created.ID, imageReq)
	if err != nil {
		t.Fatal(err)
	}
	if firstID == secondID {
		t.Fatal("continuous commands must have distinct ids")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		view, ok := manager.get(created.ID)
		if ok && view.State == "waiting_release" && view.PendingCommands == 0 && view.CompletedSends == 3 {
			if !view.ImageUsed {
				t.Fatal("mixed session must remember that an image command ran")
			}
			firstStatus, ok := manager.command(created.ID, firstID)
			if !ok || firstStatus.State != "succeeded" {
				t.Fatalf("unexpected first command status %#v", firstStatus)
			}
			secondStatus, ok := manager.command(created.ID, secondID)
			if !ok || secondStatus.State != "succeeded" {
				t.Fatalf("unexpected second command status %#v", secondStatus)
			}
			if !manager.release(created.ID) {
				t.Fatal("release after continuous sends was rejected")
			}
			final := waitSendDebugJob(t, manager, created.ID)
			if final.State != "succeeded" {
				t.Fatalf("unexpected final state %#v", final)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("continuous sends did not drain")
}

func TestSendDebugManagerRejectsSendOnProbeSession(t *testing.T) {
	manager := &sendDebugManager{runner: &fakeSendRunner{}, jobs: map[string]*sendDebugJob{}}
	req := validProbeRequest()
	req.ManualRelease = true
	created, err := manager.create(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = waitSendDebugState(t, manager, created.ID, "waiting_release")
	_, err = manager.enqueue(created.ID, wechatsend.Request{
		TargetType:  wechatsend.TargetPrivate,
		MessageType: wechatsend.MessageText,
		UserID:      "filehelper",
		Content:     "不能从 probe 直接发",
		AcceptRisk:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "Hook 检查 session") {
		t.Fatalf("probe enqueue must require a new send session: %v", err)
	}
	if !manager.release(created.ID) {
		t.Fatal("probe release rejected")
	}
	_ = waitSendDebugJob(t, manager, created.ID)
}

func TestSendDebugManagerCloseCancelsManualHold(t *testing.T) {
	manager := &sendDebugManager{runner: &fakeSendRunner{}, jobs: map[string]*sendDebugJob{}}
	req := validProbeRequest()
	req.ManualRelease = true
	created, err := manager.create(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = waitSendDebugState(t, manager, created.ID, "waiting_release")
	manager.close()
	view, ok := manager.get(created.ID)
	if !ok || view.State != "canceled" {
		t.Fatalf("manual hold was not canceled during shutdown: %#v", view)
	}
}

func TestFinishedCommandDedupeIsBounded(t *testing.T) {
	job := &sendDebugJob{
		finishedCommands: make(map[string]struct{}),
		finishedOrder:    make([]string, 0, maxFinishedCommandID),
	}
	for i := 0; i < maxFinishedCommandID+10; i++ {
		if !markSendDebugCommandFinished(job, string(rune(i+1))) {
			t.Fatalf("command %d unexpectedly treated as duplicate", i)
		}
	}
	if len(job.finishedCommands) != maxFinishedCommandID || len(job.finishedOrder) != maxFinishedCommandID {
		t.Fatalf("dedupe cache was not bounded: map=%d order=%d", len(job.finishedCommands), len(job.finishedOrder))
	}
}

func TestReleaseSendDebugPayloadsClearsBufferedImages(t *testing.T) {
	commands := make(chan wechatsend.Command, 2)
	commands <- wechatsend.Command{Request: wechatsend.Request{ImageData: "large-base64-image"}}
	job := &sendDebugJob{
		raw:      wechatsend.Request{ImageData: "initial-large-base64-image"},
		release:  make(chan struct{}),
		commands: commands,
	}
	releaseSendDebugPayloads(job)
	if job.raw.ImageData != "" || job.release != nil || job.commands != nil {
		t.Fatalf("payload references were retained: raw=%q release=%v commands=%v", job.raw.ImageData, job.release, job.commands)
	}
}

func TestSenderFromAccountDataDir(t *testing.T) {
	for _, tc := range []struct {
		path string
		want string
	}{
		{"/tmp/xwechat_files/wxid_rpb68e2rx68i22_e364", "wxid_rpb68e2rx68i22"},
		{"/tmp/xwechat_files/not-a-wechat-account", ""},
		{"", ""},
	} {
		if got := senderFromAccountDataDir(tc.path); got != tc.want {
			t.Fatalf("senderFromAccountDataDir(%q)=%q want %q", tc.path, got, tc.want)
		}
	}
}

func TestContinuousSendQueueBackpressure(t *testing.T) {
	commands := make(chan wechatsend.Command, maxTextSendQueue)
	manager := &sendDebugManager{
		jobs: map[string]*sendDebugJob{
			"active": {
				ID:              "active",
				State:           "running",
				SessionReady:    true,
				PendingCommands: maxTextSendQueue,
				commands:        commands,
				raw: wechatsend.Request{
					Operation:   wechatsend.OperationSend,
					MessageType: wechatsend.MessageText,
				},
			},
		},
		activeID: "active",
	}
	_, err := manager.enqueue("active", wechatsend.Request{
		TargetType:  wechatsend.TargetPrivate,
		MessageType: wechatsend.MessageText,
		UserID:      "filehelper",
		Content:     "overflow",
		AcceptRisk:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "队列已满") {
		t.Fatalf("expected queue backpressure, got %v", err)
	}
}

func TestMixedSessionLimitsPendingImagesIndependently(t *testing.T) {
	commands := make(chan wechatsend.Command, maxTextSendQueue)
	manager := &sendDebugManager{
		jobs: map[string]*sendDebugJob{
			"mixed": {
				ID:              "mixed",
				State:           "running",
				SessionReady:    true,
				PendingImages:   maxImageSendQueue,
				commands:        commands,
				commandStatuses: make(map[string]*sendDebugCommandStatus),
				raw: wechatsend.Request{
					Operation:   wechatsend.OperationSend,
					MessageType: wechatsend.MessageText,
				},
			},
		},
		activeID: "mixed",
	}
	_, err := manager.enqueue("mixed", wechatsend.Request{
		TargetType:  wechatsend.TargetPrivate,
		MessageType: wechatsend.MessageImage,
		UserID:      "filehelper",
		ImagePath:   "/tmp/queued-image.png",
		AcceptRisk:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "队列已满") {
		t.Fatalf("expected independent image backpressure, got %v", err)
	}
}

func TestSendDebugManagerRejectsConcurrentFridaJob(t *testing.T) {
	block := make(chan struct{})
	manager := &sendDebugManager{runner: &fakeSendRunner{block: block}, jobs: map[string]*sendDebugJob{}}
	first, err := manager.create(validProbeRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.create(validProbeRequest()); err == nil {
		t.Fatal("expected concurrent job rejection")
	}
	close(block)
	_ = waitSendDebugJob(t, manager, first.ID)
}

func TestLoopbackRemoteValidation(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:5030", "[::1]:5030", "127.0.0.1"} {
		if !isLoopbackRemote(addr) {
			t.Fatalf("expected loopback for %q", addr)
		}
	}
	for _, addr := range []string{"192.168.1.4:5030", "8.8.8.8:53", ""} {
		if isLoopbackRemote(addr) {
			t.Fatalf("expected non-loopback for %q", addr)
		}
	}
}
