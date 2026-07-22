package windows

import (
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/sjzar/chatlog/internal/wechat/model"
	"github.com/sjzar/chatlog/pkg/appver"
)

const (
	V3ProcessName = "WeChat"
	V4ProcessName = "Weixin"
	V3DBFile      = `Msg\Misc.db`
	V4DBFile      = `db_storage\session\session.db`

	noDataDirRecheckInterval = 30 * time.Second
)

type processCacheEntry struct {
	info      *model.Process
	hasData   bool
	checkedAt time.Time
}

// Detector 实现 Windows 平台的进程检测器
type Detector struct {
	mu    sync.Mutex
	cache map[uint32]processCacheEntry
}

// NewDetector 创建一个新的 Windows 检测器
func NewDetector() *Detector {
	return &Detector{cache: make(map[uint32]processCacheEntry)}
}

func isWeixinChildCommandLine(commandLine string) bool {
	return strings.Contains(commandLine, "--type=")
}

// FindProcesses 查找所有微信进程并返回它们的信息
func (d *Detector) FindProcesses() ([]*model.Process, error) {
	processes, err := process.Processes()
	if err != nil {
		log.Err(err).Msg("获取进程列表失败")
		return nil, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	result := make([]*model.Process, 0, 2)
	alivePIDs := make(map[uint32]struct{})
	now := time.Now()
	for _, p := range processes {
		name, err := p.Name()
		name = strings.TrimSuffix(name, ".exe")
		if err != nil || (name != V3ProcessName && name != V4ProcessName) {
			continue
		}

		pid := uint32(p.Pid)

		// V4 的 Chromium 子进程会携带 --type=；主进程也可能有
		// --scene= 等参数，因此只排除明确的子进程参数。
		if name == V4ProcessName {
			commandLine, err := p.Cmdline()
			if err != nil {
				log.Debug().Err(err).Msgf("获取进程 %d 命令行失败", p.Pid)
				continue
			}
			if isWeixinChildCommandLine(commandLine) {
				continue
			}
		}
		alivePIDs[pid] = struct{}{}

		if entry, ok := d.cache[pid]; ok && (entry.hasData || now.Sub(entry.checkedAt) < noDataDirRecheckInterval) {
			cached := *entry.info
			result = append(result, &cached)
			continue
		}

		// 获取进程信息
		procInfo, err := d.getProcessInfo(p)
		if err != nil {
			log.Err(err).Msgf("获取进程 %d 的信息失败", p.Pid)
			continue
		}

		d.cache[pid] = processCacheEntry{
			info:      procInfo,
			hasData:   procInfo.DataDir != "",
			checkedAt: now,
		}
		copyInfo := *procInfo
		result = append(result, &copyInfo)
	}

	for pid := range d.cache {
		if _, ok := alivePIDs[pid]; !ok {
			delete(d.cache, pid)
		}
	}

	return result, nil
}

// getProcessInfo 获取微信进程的详细信息
func (d *Detector) getProcessInfo(p *process.Process) (*model.Process, error) {
	procInfo := &model.Process{
		PID:      uint32(p.Pid),
		Status:   model.StatusOffline,
		Platform: model.PlatformWindows,
	}

	// 获取可执行文件路径
	exePath, err := p.Exe()
	if err != nil {
		log.Err(err).Msg("获取可执行文件路径失败")
		return nil, err
	}
	procInfo.ExePath = exePath

	// 获取版本信息
	versionInfo, err := appver.New(exePath)
	if err != nil {
		log.Debug().Err(err).Msg("获取版本信息失败，回退到微信V4")
		procInfo.Version = 4
		procInfo.FullVersion = "4.0.0.0"
	} else {
		procInfo.Version = versionInfo.Version
		procInfo.FullVersion = versionInfo.FullVersion
	}

	// 初始化附加信息（数据目录、账户名）
	if err := initializeProcessInfo(p, procInfo); err != nil {
		log.Err(err).Msg("初始化进程信息失败")
		// 即使初始化失败也返回部分信息
	}

	return procInfo, nil
}
