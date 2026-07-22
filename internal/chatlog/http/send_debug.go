package http

import (
	"context"
	"errors"
	"net"
	stdhttp "net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	wechatsend "github.com/sjzar/chatlog/internal/wechat/send"
)

const (
	maxSendDebugBody     = wechatsend.MaxImageBytes*4/3 + 1024*1024
	maxSendDebugProgress = 600
	maxSendDebugJobs     = 20
	maxTextSendQueue     = 256
	maxImageSendQueue    = 8
	maxFinishedCommandID = 2048
	maxSendCommandStatus = 2048
)

type sendDebugManager struct {
	mu       sync.RWMutex
	runner   wechatsend.Runner
	jobs     map[string]*sendDebugJob
	activeID string
	closed   bool
}

type sendDebugJob struct {
	ID               string
	State            string
	Request          wechatsend.Request
	CreatedAt        time.Time
	StartedAt        time.Time
	EndedAt          time.Time
	Progress         []wechatsend.Progress
	Result           *wechatsend.Result
	Error            string
	ReleaseRequested bool
	SessionReady     bool
	PendingCommands  int
	PendingImages    int
	CompletedSends   int
	ImageUsed        bool
	NextSequence     uint64
	cancel           context.CancelFunc
	release          chan struct{}
	commands         chan wechatsend.Command
	done             chan struct{}
	raw              wechatsend.Request
	finishedCommands map[string]struct{}
	finishedOrder    []string
	commandStatuses  map[string]*sendDebugCommandStatus
	commandOrder     []string
}

type sendDebugCommandStatus struct {
	ID          string                 `json:"id"`
	State       string                 `json:"state"`
	Receiver    string                 `json:"receiver"`
	MessageType wechatsend.MessageType `json:"message_type"`
	CreatedAt   time.Time              `json:"created_at"`
	StartedAt   time.Time              `json:"started_at,omitempty"`
	EndedAt     time.Time              `json:"ended_at,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

type sendDebugJobView struct {
	ID               string                `json:"id"`
	State            string                `json:"state"`
	Request          wechatsend.Request    `json:"request"`
	CreatedAt        time.Time             `json:"created_at"`
	StartedAt        time.Time             `json:"started_at,omitempty"`
	EndedAt          time.Time             `json:"ended_at,omitempty"`
	Progress         []wechatsend.Progress `json:"progress"`
	Result           *wechatsend.Result    `json:"result,omitempty"`
	Error            string                `json:"error,omitempty"`
	ReleaseRequired  bool                  `json:"release_required"`
	ReleaseRequested bool                  `json:"release_requested"`
	SessionReady     bool                  `json:"session_ready"`
	PendingCommands  int                   `json:"pending_commands"`
	CompletedSends   int                   `json:"completed_sends"`
	ImageUsed        bool                  `json:"image_used"`
}

func newSendDebugManager() *sendDebugManager {
	return &sendDebugManager{
		runner: wechatsend.NewRunner(),
		jobs:   make(map[string]*sendDebugJob),
	}
}

func (m *sendDebugManager) close() {
	m.mu.Lock()
	m.closed = true
	var activeDone <-chan struct{}
	for _, job := range m.jobs {
		if !isActiveSendDebugState(job.State) {
			continue
		}
		if job.cancel != nil {
			job.cancel()
			activeDone = job.done
			continue
		}
		if job.State == "queued" {
			job.State = "canceled"
			job.EndedAt = time.Now()
			job.Error = "服务退出，任务在启动前取消"
			close(job.done)
			releaseSendDebugPayloads(job)
		}
	}
	m.activeID = ""
	m.mu.Unlock()
	if activeDone != nil {
		select {
		case <-activeDone:
		case <-time.After(130 * time.Second):
			// The platform runner gives image cleanup up to 120 seconds so a
			// controlled WeChat restart and health check can finish. Keep the HTTP
			// shutdown window slightly larger, but never block forever if Frida or
			// the OS-level attach process itself is wedged.
		}
	}
}

func (m *sendDebugManager) create(req wechatsend.Request) (*sendDebugJobView, error) {
	normalized, err := req.Normalized()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errors.New("send debug manager is closed")
	}
	if active := m.jobs[m.activeID]; active != nil && isActiveSendDebugState(active.State) {
		return nil, errors.New("另一个 Frida 发信调试任务仍在运行")
	}
	m.pruneLocked()
	var release chan struct{}
	var commands chan wechatsend.Command
	if normalized.ManualRelease {
		release = make(chan struct{})
		// A send job is a mixed text/image session. Keep the broad text queue
		// capacity here and enforce the stricter image count separately.
		commands = make(chan wechatsend.Command, maxTextSendQueue)
		normalized.Release = release
		normalized.Commands = commands
	}
	job := &sendDebugJob{
		ID:               uuid.NewString(),
		State:            "queued",
		Request:          normalized.PublicCopy(),
		CreatedAt:        time.Now(),
		Progress:         make([]wechatsend.Progress, 0, 64),
		release:          release,
		commands:         commands,
		done:             make(chan struct{}),
		raw:              normalized,
		finishedCommands: make(map[string]struct{}),
		finishedOrder:    make([]string, 0, 64),
		commandStatuses:  make(map[string]*sendDebugCommandStatus),
		commandOrder:     make([]string, 0, 64),
		ImageUsed:        normalized.Operation == wechatsend.OperationSend && normalized.MessageType == wechatsend.MessageImage,
	}
	m.jobs[job.ID] = job
	m.activeID = job.ID
	view := jobView(job)
	go m.run(job.ID)
	return &view, nil
}

func (m *sendDebugManager) run(id string) {
	m.mu.Lock()
	job := m.jobs[id]
	if job == nil || m.closed || job.State != "queued" {
		m.mu.Unlock()
		return
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if job.raw.ManualRelease {
		// The native runner owns an execution watchdog. Once it reports the
		// successful manual-release hold, this context intentionally has no
		// deadline and ends only on release completion, cancel, or shutdown.
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		timeout := 2 * time.Minute
		if job.raw.Operation == wechatsend.OperationProbe {
			timeout = time.Minute
		} else if job.raw.MessageType == wechatsend.MessageImage {
			timeout = 6 * time.Minute
		}
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
	}
	job.cancel = cancel
	job.State = "running"
	job.StartedAt = time.Now()
	runRequest := job.raw
	// The runner now owns its request copy. Drop the potentially 27 MiB base64
	// body from retained job state immediately; public views never expose it.
	job.raw.ImageData = ""
	m.mu.Unlock()

	report := func(progress wechatsend.Progress) {
		m.mu.Lock()
		defer m.mu.Unlock()
		current := m.jobs[id]
		if current == nil {
			return
		}
		current.Progress = append(current.Progress, progress)
		if len(current.Progress) > maxSendDebugProgress {
			current.Progress = append([]wechatsend.Progress(nil), current.Progress[len(current.Progress)-maxSendDebugProgress:]...)
		}
		if progress.Stage == "manual_release" {
			switch {
			case strings.Contains(progress.Message, "等待用户"), strings.Contains(progress.Message, "可继续发送"):
				if !current.SessionReady {
					current.SessionReady = true
					if current.raw.Operation == wechatsend.OperationSend {
						current.CompletedSends++
					}
				}
				if !current.ReleaseRequested && current.PendingCommands == 0 {
					current.State = "waiting_release"
				}
			case strings.Contains(progress.Message, "已收到释放指令"):
				current.State = "running"
				current.ReleaseRequested = true
			}
		}
		if progress.Stage == "command" && progress.CommandID != "" {
			failed := progress.Level == "error" || strings.Contains(progress.Message, "发送失败") || strings.Contains(progress.Message, "入队失败")
			completed := strings.Contains(progress.Message, "发送完成")
			enqueueFailed := strings.Contains(progress.Message, "入队失败")
			status := current.commandStatuses[progress.CommandID]
			if status != nil {
				switch {
				case strings.Contains(progress.Message, "开始连续发送"):
					status.State = "running"
					if status.StartedAt.IsZero() {
						status.StartedAt = progress.Time
					}
				case completed && !failed:
					status.State = "succeeded"
					status.EndedAt = progress.Time
				case failed:
					status.State = "failed"
					status.EndedAt = progress.Time
					status.Error = progress.Message
				}
			}
			if failed || completed {
				if markSendDebugCommandFinished(current, progress.CommandID) {
					if current.PendingCommands > 0 {
						current.PendingCommands--
					}
					if completed && !failed {
						current.CompletedSends++
					}
					if status != nil && status.MessageType == wechatsend.MessageImage && current.PendingImages > 0 {
						current.PendingImages--
					}
				}
				if failed && !enqueueFailed {
					current.SessionReady = false
				}
				if completed && !failed && current.SessionReady && current.PendingCommands == 0 {
					current.State = "waiting_release"
				}
				if enqueueFailed && current.SessionReady && current.PendingCommands == 0 {
					current.State = "waiting_release"
				}
			}
		}
	}
	result, runErr := m.runner.Run(ctx, runRequest, report)
	ctxErr := ctx.Err()
	cancel()

	m.mu.Lock()
	defer m.mu.Unlock()
	job = m.jobs[id]
	if job == nil {
		return
	}
	job.EndedAt = time.Now()
	job.cancel = nil
	job.SessionReady = false
	job.PendingCommands = 0
	job.PendingImages = 0
	close(job.done)
	if runErr == nil {
		job.State = "succeeded"
		job.Result = &result
	} else if errors.Is(ctxErr, context.Canceled) {
		job.State = "canceled"
		job.Error = "任务已取消，正在完成 Frida 兜底清理"
	} else if errors.Is(ctxErr, context.DeadlineExceeded) || errors.Is(runErr, context.DeadlineExceeded) {
		job.State = "failed"
		job.Error = "任务超时并已触发清理"
	} else {
		job.State = "failed"
		job.Error = runErr.Error()
	}
	if m.activeID == id {
		m.activeID = ""
	}
	for _, status := range job.commandStatuses {
		if status.State == "queued" || status.State == "running" {
			status.State = job.State
			status.EndedAt = job.EndedAt
			status.Error = job.Error
		}
	}
	releaseSendDebugPayloads(job)
}

func releaseSendDebugPayloads(job *sendDebugJob) {
	if job == nil {
		return
	}
	job.raw = wechatsend.Request{}
	job.release = nil
	job.PendingImages = 0
	if job.commands != nil {
		for {
			select {
			case command := <-job.commands:
				command.Request.ImageData = ""
			default:
				job.commands = nil
				return
			}
		}
	}
}

func markSendDebugCommandFinished(job *sendDebugJob, commandID string) bool {
	if _, seen := job.finishedCommands[commandID]; seen {
		return false
	}
	job.finishedCommands[commandID] = struct{}{}
	job.finishedOrder = append(job.finishedOrder, commandID)
	if len(job.finishedOrder) > maxFinishedCommandID {
		oldest := job.finishedOrder[0]
		job.finishedOrder = job.finishedOrder[1:]
		delete(job.finishedCommands, oldest)
	}
	return true
}

func (m *sendDebugManager) get(id string) (sendDebugJobView, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	job := m.jobs[id]
	if job == nil {
		return sendDebugJobView{}, false
	}
	return jobView(job), true
}

func (m *sendDebugManager) active() (sendDebugJobView, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	job := m.jobs[m.activeID]
	if job == nil || !isActiveSendDebugState(job.State) {
		return sendDebugJobView{}, false
	}
	return jobView(job), true
}

func (m *sendDebugManager) command(jobID, commandID string) (sendDebugCommandStatus, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	job := m.jobs[jobID]
	if job == nil || job.commandStatuses == nil {
		return sendDebugCommandStatus{}, false
	}
	status := job.commandStatuses[commandID]
	if status == nil {
		return sendDebugCommandStatus{}, false
	}
	return *status, true
}

func (m *sendDebugManager) cancel(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	job := m.jobs[id]
	if job == nil {
		return false
	}
	if job.State == "queued" && job.cancel == nil {
		job.State = "canceled"
		job.EndedAt = time.Now()
		job.Error = "任务在启动前取消"
		close(job.done)
		if m.activeID == id {
			m.activeID = ""
		}
		releaseSendDebugPayloads(job)
		return true
	}
	if job.cancel != nil && (job.State == "running" || job.State == "waiting_release") {
		job.SessionReady = false
		if job.State == "waiting_release" {
			job.State = "running"
			job.Progress = append(job.Progress, wechatsend.Progress{
				Time:    time.Now(),
				Level:   "warning",
				Stage:   "cleanup",
				Message: "用户已请求强制停止，正在执行自动兜底清理",
			})
		}
		job.cancel()
		return true
	}
	return false
}

func (m *sendDebugManager) release(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	job := m.jobs[id]
	if job == nil || job.State != "waiting_release" || job.PendingCommands != 0 || job.release == nil || job.ReleaseRequested {
		return false
	}
	close(job.release)
	job.ReleaseRequested = true
	job.SessionReady = false
	job.State = "running"
	releaseMessage := "用户已请求释放，正在执行 force_cleanup -> unload -> detach"
	imageUsed := job.ImageUsed || (job.raw.Operation == wechatsend.OperationSend && job.raw.MessageType == wechatsend.MessageImage)
	if imageUsed && job.raw.Operation == wechatsend.OperationSend {
		releaseMessage = "用户已请求释放混合图文 session；本 session 发送过图片，正在补足 5 秒 generation 安全窗口，随后受控重启微信并清理 Frida helper"
	}
	job.Progress = append(job.Progress, wechatsend.Progress{
		Time:    time.Now(),
		Level:   "info",
		Stage:   "manual_release",
		Message: releaseMessage,
	})
	return true
}

func (m *sendDebugManager) enqueue(id string, req wechatsend.Request) (string, error) {
	req.Operation = wechatsend.OperationSend
	req.ManualRelease = false
	req.Release = nil
	req.Commands = nil
	normalized, err := req.Normalized()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	job := m.jobs[id]
	if job == nil || !isActiveSendDebugState(job.State) {
		return "", errors.New("Frida session 不存在或已经结束")
	}
	if job.raw.Operation != wechatsend.OperationSend {
		return "", errors.New("Hook 检查 session 不能直接发送；请先释放并建立发送 session")
	}
	if !job.SessionReady || job.ReleaseRequested || job.commands == nil {
		return "", errors.New("Frida session 尚未就绪或正在释放")
	}
	if job.PendingCommands >= maxTextSendQueue || (normalized.MessageType == wechatsend.MessageImage && job.PendingImages >= maxImageSendQueue) {
		return "", errors.New("连续发送队列已满，请等待当前消息完成")
	}
	job.NextSequence++
	command := wechatsend.Command{
		ID:       uuid.NewString(),
		Sequence: job.NextSequence,
		Request:  normalized,
	}
	select {
	case job.commands <- command:
		job.PendingCommands++
		if normalized.MessageType == wechatsend.MessageImage {
			job.PendingImages++
			job.ImageUsed = true
		}
		job.State = "running"
		job.commandStatuses[command.ID] = &sendDebugCommandStatus{
			ID:          command.ID,
			State:       "queued",
			Receiver:    normalized.Receiver(),
			MessageType: normalized.MessageType,
			CreatedAt:   time.Now(),
		}
		job.commandOrder = append(job.commandOrder, command.ID)
		if len(job.commandOrder) > maxSendCommandStatus {
			oldest := job.commandOrder[0]
			job.commandOrder = job.commandOrder[1:]
			delete(job.commandStatuses, oldest)
		}
		job.Progress = append(job.Progress, wechatsend.Progress{
			Time:      time.Now(),
			Level:     "info",
			Stage:     "command",
			CommandID: command.ID,
			Message:   "连续发送已排队，目标 " + normalized.Receiver(),
		})
		return command.ID, nil
	default:
		job.NextSequence--
		return "", errors.New("连续发送队列已满，请等待当前消息完成")
	}
}

func (m *sendDebugManager) pruneLocked() {
	if len(m.jobs) < maxSendDebugJobs {
		return
	}
	completed := make([]*sendDebugJob, 0, len(m.jobs))
	for _, job := range m.jobs {
		if !isActiveSendDebugState(job.State) {
			completed = append(completed, job)
		}
	}
	sort.Slice(completed, func(i, j int) bool { return completed[i].CreatedAt.Before(completed[j].CreatedAt) })
	for len(m.jobs) >= maxSendDebugJobs && len(completed) > 0 {
		delete(m.jobs, completed[0].ID)
		completed = completed[1:]
	}
}

func jobView(job *sendDebugJob) sendDebugJobView {
	view := sendDebugJobView{
		ID:               job.ID,
		State:            job.State,
		Request:          job.Request,
		CreatedAt:        job.CreatedAt,
		StartedAt:        job.StartedAt,
		EndedAt:          job.EndedAt,
		Progress:         append([]wechatsend.Progress(nil), job.Progress...),
		Error:            job.Error,
		ReleaseRequired:  job.State == "waiting_release",
		ReleaseRequested: job.ReleaseRequested,
		SessionReady:     job.SessionReady,
		PendingCommands:  job.PendingCommands,
		CompletedSends:   job.CompletedSends,
		ImageUsed:        job.ImageUsed,
	}
	if job.Result != nil {
		resultCopy := *job.Result
		view.Result = &resultCopy
	}
	return view
}

func (s *Service) handleSendDebugEnvironment(c *gin.Context) {
	if !requireLocalDebugRequest(c) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	c.JSON(stdhttp.StatusOK, s.sendDebug.runner.Environment(ctx))
}

func (s *Service) handleSendDebugJobCreate(c *gin.Context) {
	if !requireLocalDebugRequest(c) {
		return
	}
	c.Request.Body = stdhttp.MaxBytesReader(c.Writer, c.Request.Body, maxSendDebugBody)
	var req wechatsend.Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "请求格式无效或图片超过 20 MiB: " + err.Error()})
		return
	}
	// Web debug jobs intentionally retain their hooks after success. The user
	// releases them explicitly from the page; failure/cancel/service shutdown
	// still takes the automatic cleanup path.
	req.ManualRelease = true
	if req.Operation == wechatsend.OperationSend && strings.TrimSpace(req.Sender) == "" {
		req.Sender = senderFromAccountDataDir(s.conf.GetDataDir())
	}
	job, err := s.sendDebug.create(req)
	if err != nil {
		status := stdhttp.StatusBadRequest
		if strings.Contains(err.Error(), "仍在运行") {
			status = stdhttp.StatusConflict
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(stdhttp.StatusAccepted, job)
}

func (s *Service) handleSendDebugJobGet(c *gin.Context) {
	if !requireLocalDebugRequest(c) {
		return
	}
	job, ok := s.sendDebug.get(strings.TrimSpace(c.Param("id")))
	if !ok {
		c.JSON(stdhttp.StatusNotFound, gin.H{"error": "调试任务不存在"})
		return
	}
	c.JSON(stdhttp.StatusOK, job)
}

func (s *Service) handleSendDebugActiveJobGet(c *gin.Context) {
	if !requireLocalDebugRequest(c) {
		return
	}
	job, ok := s.sendDebug.active()
	if !ok {
		c.JSON(stdhttp.StatusOK, gin.H{"active": false})
		return
	}
	c.JSON(stdhttp.StatusOK, job)
}

func (s *Service) handleSendDebugJobCancel(c *gin.Context) {
	if !requireLocalDebugRequest(c) {
		return
	}
	if !s.sendDebug.cancel(strings.TrimSpace(c.Param("id"))) {
		c.JSON(stdhttp.StatusConflict, gin.H{"error": "任务不存在或已经结束"})
		return
	}
	c.JSON(stdhttp.StatusAccepted, gin.H{"status": "canceling"})
}

func (s *Service) handleSendDebugJobEnqueue(c *gin.Context) {
	if !requireLocalDebugRequest(c) {
		return
	}
	c.Request.Body = stdhttp.MaxBytesReader(c.Writer, c.Request.Body, maxSendDebugBody)
	var req wechatsend.Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "请求格式无效或图片超过 20 MiB: " + err.Error()})
		return
	}
	if req.MessageType == wechatsend.MessageImage && strings.TrimSpace(req.Sender) == "" {
		req.Sender = senderFromAccountDataDir(s.conf.GetDataDir())
	}
	commandID, err := s.sendDebug.enqueue(strings.TrimSpace(c.Param("id")), req)
	if err != nil {
		status := stdhttp.StatusBadRequest
		if strings.Contains(err.Error(), "尚未就绪") || strings.Contains(err.Error(), "队列已满") {
			status = stdhttp.StatusConflict
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(stdhttp.StatusAccepted, gin.H{"status": "queued", "command_id": commandID})
}

func senderFromAccountDataDir(dataDir string) string {
	name := filepath.Base(filepath.Clean(strings.TrimSpace(dataDir)))
	first := strings.IndexByte(name, '_')
	last := strings.LastIndexByte(name, '_')
	if strings.HasPrefix(name, "wxid_") && first >= 0 && last > first {
		return name[:last]
	}
	return ""
}

func (s *Service) handleSendDebugCommandGet(c *gin.Context) {
	if !requireLocalDebugRequest(c) {
		return
	}
	status, ok := s.sendDebug.command(strings.TrimSpace(c.Param("id")), strings.TrimSpace(c.Param("command_id")))
	if !ok {
		c.JSON(stdhttp.StatusNotFound, gin.H{"error": "发送命令不存在或已超过保留上限"})
		return
	}
	c.JSON(stdhttp.StatusOK, status)
}

func (s *Service) handleSendDebugJobRelease(c *gin.Context) {
	if !requireLocalDebugRequest(c) {
		return
	}
	if !s.sendDebug.release(strings.TrimSpace(c.Param("id"))) {
		c.JSON(stdhttp.StatusConflict, gin.H{"error": "任务尚未进入等待释放状态，或释放已提交"})
		return
	}
	c.JSON(stdhttp.StatusAccepted, gin.H{"status": "releasing"})
}

func isActiveSendDebugState(state string) bool {
	return state == "queued" || state == "running" || state == "waiting_release"
}

func requireLocalDebugRequest(c *gin.Context) bool {
	if isLoopbackRemote(c.Request.RemoteAddr) {
		return true
	}
	c.JSON(stdhttp.StatusForbidden, gin.H{"error": "Frida 发信调试仅允许从本机 Web 控制台调用"})
	c.Abort()
	return false
}

func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.Trim(strings.TrimSpace(remoteAddr), "[]")
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
