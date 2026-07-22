package send

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	SupportedWeChatVersion = "4.1.11.55"
	MaxTextBytes           = 32 * 1024
	MaxImageBytes          = 20 * 1024 * 1024
	MaxReceiverBytes       = 255
)

type TargetType string

const (
	TargetPrivate TargetType = "private"
	TargetGroup   TargetType = "group"
)

type MessageType string

const (
	MessageText  MessageType = "text"
	MessageImage MessageType = "image"
)

type Operation string

const (
	OperationProbe Operation = "probe"
	OperationSend  Operation = "send"
)

// Request is deliberately explicit about private/group targets. It avoids the
// reference project's ambiguous "user_id and group_id may both be present"
// behavior and keeps a single normalized receiver for the native sender.
type Request struct {
	Operation      Operation   `json:"operation"`
	TargetType     TargetType  `json:"target_type"`
	MessageType    MessageType `json:"message_type"`
	UserID         string      `json:"user_id,omitempty"`
	GroupID        string      `json:"group_id,omitempty"`
	Content        string      `json:"content,omitempty"`
	AtUser         string      `json:"at_user,omitempty"`
	AtName         string      `json:"at_name,omitempty"`
	ImageData      string      `json:"image_data,omitempty"`
	ImagePath      string      `json:"image_path,omitempty"`
	Sender         string      `json:"sender,omitempty"`
	PID            int         `json:"pid,omitempty"`
	AcceptRisk     bool        `json:"accept_risk,omitempty"`
	AllowElevation bool        `json:"allow_elevation,omitempty"`
	ManualRelease  bool        `json:"manual_release,omitempty"`
	// Release is supplied by the job manager. A successful native task waits
	// for this signal before final cleanup. Text/probe sessions use force_cleanup
	// -> unload -> detach; an executed image session uses a controlled WeChat
	// restart to avoid hot-unload callback races. It is never accepted from or
	// exposed to the HTTP client.
	Release     <-chan struct{} `json:"-"`
	Commands    <-chan Command  `json:"-"`
	releaseFile string
	commandDir  string
}

// Command is a follow-up send executed by an already attached Frida session.
// Sequence preserves click order even when several HTTP requests arrive close
// together; ID is surfaced in progress events for per-send feedback.
type Command struct {
	ID       string
	Sequence uint64
	Request  Request
}

func (r Request) Normalized() (Request, error) {
	r.Operation = Operation(strings.ToLower(strings.TrimSpace(string(r.Operation))))
	if r.Operation == "" {
		r.Operation = OperationSend
	}
	r.TargetType = TargetType(strings.ToLower(strings.TrimSpace(string(r.TargetType))))
	r.MessageType = MessageType(strings.ToLower(strings.TrimSpace(string(r.MessageType))))
	r.UserID = strings.TrimSpace(r.UserID)
	r.GroupID = strings.TrimSpace(r.GroupID)
	r.Content = strings.TrimSpace(r.Content)
	r.AtUser = canonicalMentionList(r.AtUser)
	r.AtName = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r.AtName), "@"))
	r.ImageData = strings.TrimSpace(r.ImageData)
	r.ImagePath = strings.TrimSpace(r.ImagePath)
	r.Sender = strings.TrimSpace(r.Sender)

	if r.Operation != OperationProbe && r.Operation != OperationSend {
		return r, fmt.Errorf("operation must be probe or send")
	}
	if r.MessageType != MessageText && r.MessageType != MessageImage {
		return r, fmt.Errorf("message_type must be text or image")
	}
	if r.TargetType != TargetPrivate && r.TargetType != TargetGroup {
		return r, fmt.Errorf("target_type must be private or group")
	}
	if r.PID < 0 {
		return r, fmt.Errorf("pid must be non-negative")
	}

	switch r.TargetType {
	case TargetPrivate:
		if r.UserID == "" {
			return r, fmt.Errorf("private target requires user_id")
		}
		if r.GroupID != "" {
			return r, fmt.Errorf("private target must not include group_id")
		}
		if strings.HasSuffix(strings.ToLower(r.UserID), "@chatroom") {
			return r, fmt.Errorf("private user_id must not end with @chatroom")
		}
		if r.AtUser != "" || r.AtName != "" {
			return r, fmt.Errorf("mentions are only supported for group targets")
		}
	case TargetGroup:
		if r.GroupID == "" {
			return r, fmt.Errorf("group target requires group_id")
		}
		if r.UserID != "" {
			return r, fmt.Errorf("group target must not include user_id")
		}
		if !strings.HasSuffix(strings.ToLower(r.GroupID), "@chatroom") {
			return r, fmt.Errorf("group_id must end with @chatroom")
		}
	}
	if err := validateReceiverID(r.Receiver()); err != nil {
		return r, err
	}

	if r.Operation == OperationProbe {
		return r, nil
	}
	if !r.AcceptRisk {
		return r, fmt.Errorf("native send requires explicit risk acknowledgement")
	}
	switch r.MessageType {
	case MessageText:
		if r.Content == "" {
			return r, fmt.Errorf("text message requires content")
		}
		if len([]byte(r.Content)) > MaxTextBytes {
			return r, fmt.Errorf("text content exceeds %d bytes", MaxTextBytes)
		}
		if r.TargetType == TargetGroup && r.AtUser != "" && r.AtName != "" {
			prefix := "@" + r.AtName + "\u2005"
			if !strings.HasPrefix(r.Content, prefix) {
				r.Content = prefix + r.Content
			}
		}
	case MessageImage:
		if r.ImageData == "" && r.ImagePath == "" {
			return r, fmt.Errorf("image message requires image_data or image_path")
		}
		if r.ImageData != "" && r.ImagePath != "" {
			return r, fmt.Errorf("provide only one of image_data or image_path")
		}
	}
	return r, nil
}

func validateReceiverID(receiver string) error {
	if len(receiver) > MaxReceiverBytes {
		return fmt.Errorf("receiver exceeds %d bytes", MaxReceiverBytes)
	}
	for i := 0; i < len(receiver); i++ {
		if receiver[i] <= 0x20 || receiver[i] >= 0x7f {
			return fmt.Errorf("receiver must be a printable ASCII WeChat ID")
		}
	}
	return nil
}

func (r Request) Receiver() string {
	if r.TargetType == TargetGroup {
		return strings.TrimSpace(r.GroupID)
	}
	return strings.TrimSpace(r.UserID)
}

func (r Request) PublicCopy() Request {
	r.ImageData = ""
	r.Release = nil
	r.Commands = nil
	r.releaseFile = ""
	r.commandDir = ""
	return r
}

func canonicalMentionList(raw string) string {
	raw = strings.NewReplacer("，", ",", ";", ",", "；", ",", "\n", ",").Replace(raw)
	seen := map[string]struct{}{}
	parts := make([]string, 0, 4)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		parts = append(parts, part)
	}
	return strings.Join(parts, ",")
}

type Environment struct {
	Platform         string `json:"platform"`
	Architecture     string `json:"architecture"`
	Supported        bool   `json:"supported"`
	Reason           string `json:"reason,omitempty"`
	PythonPath       string `json:"python_path,omitempty"`
	FridaVersion     string `json:"frida_version,omitempty"`
	WeChatInstalled  bool   `json:"wechat_installed"`
	WeChatRunning    bool   `json:"wechat_running"`
	WeChatPID        int    `json:"wechat_pid,omitempty"`
	WeChatVersion    string `json:"wechat_version,omitempty"`
	WeChatBuild      string `json:"wechat_build,omitempty"`
	DylibSHA256      string `json:"dylib_sha256,omitempty"`
	ProfileVersion   string `json:"profile_version"`
	ProfileMatched   bool   `json:"profile_matched"`
	ElevationCapable bool   `json:"elevation_capable"`
}

type Progress struct {
	Time      time.Time `json:"time"`
	Level     string    `json:"level"`
	Stage     string    `json:"stage"`
	Step      int       `json:"step,omitempty"`
	Total     int       `json:"total,omitempty"`
	CommandID string    `json:"command_id,omitempty"`
	Message   string    `json:"message"`
}

type Result struct {
	Receiver string `json:"receiver"`
	Elevated bool   `json:"elevated"`
	ExitCode int    `json:"exit_code"`
}

type Reporter func(Progress)

type Runner interface {
	Environment(context.Context) Environment
	Run(context.Context, Request, Reporter) (Result, error)
}

var ErrUnsupported = errors.New("wechat native send is unsupported on this platform")

func NewRunner() Runner {
	return newPlatformRunner()
}
