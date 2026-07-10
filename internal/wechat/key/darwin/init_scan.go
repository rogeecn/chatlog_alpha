package darwin

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/decrypt/common"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

type keyFileEntry struct {
	EncKey string `json:"enc_key"`
}

type dbSaltEntry struct {
	SaltHex string
	DBRel   string
}

// loadAndValidateMessageKey picks a usable data key from all_keys.json
// (written by Frida extraction). No process memory scan.
func loadAndValidateMessageKey(dataDir string, status func(string)) (string, error) {
	keys, err := loadAllKeys(dataDir)
	if err != nil {
		return "", err
	}
	if status != nil {
		status(fmt.Sprintf("检查 all_keys.json（共 %d 条）...", len(keys)))
	}

	if key, ok := pickPreferredMessageKey(dataDir, keys, status); ok {
		if status != nil {
			status("已从 all_keys.json 选中可用密钥")
		}
		return key, nil
	}
	return "", fmt.Errorf("all_keys.json 中没有有效 enc_key")
}

func pickPreferredMessageKey(dataDir string, keys map[string]string, status func(string)) (string, bool) {
	if len(keys) == 0 {
		return "", false
	}

	// 1) Try exact message_0 first and verify if possible.
	for dbRel, key := range keys {
		p := normalizePath(dbRel)
		if p == "message/message_0.db" || strings.HasSuffix(p, "/message/message_0.db") {
			if validateKeyOnDBPath(dataDir, dbRel, key) {
				return strings.ToLower(key), true
			}
		}
	}

	// 2) Try any message/*.db and verify if possible.
	for dbRel, key := range keys {
		p := normalizePath(dbRel)
		if strings.Contains(p, "/message/") || strings.HasPrefix(p, "message/") {
			if strings.HasSuffix(p, ".db") {
				if validateKeyOnDBPath(dataDir, dbRel, key) {
					return strings.ToLower(key), true
				}
			}
		}
	}

	// 3) Frequency fallback: choose the key appearing in the most DB entries.
	type keyCount struct {
		Key   string
		Count int
	}
	counter := map[string]int{}
	for _, key := range keys {
		k := strings.TrimSpace(strings.ToLower(key))
		if len(k) != 64 {
			continue
		}
		counter[k]++
	}
	if len(counter) == 0 {
		return "", false
	}
	counts := make([]keyCount, 0, len(counter))
	for k, c := range counter {
		counts = append(counts, keyCount{Key: k, Count: c})
	}
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].Count == counts[j].Count {
			return counts[i].Key < counts[j].Key
		}
		return counts[i].Count > counts[j].Count
	})
	if status != nil {
		status(fmt.Sprintf("message库未命中，按频次回退选择候选 key（top=%d）", counts[0].Count))
	}
	return counts[0].Key, true
}

func validateKeyOnDBPath(dataDir, dbRelPath, keyHex string) bool {
	keyHex = strings.TrimSpace(strings.ToLower(keyHex))
	if len(keyHex) != 64 {
		return false
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return false
	}

	dbPath := resolveDBPath(dataDir, dbRelPath)
	dbInfo, err := common.OpenDBFile(dbPath, 4096)
	if err != nil {
		return false
	}
	d, err := decrypt.NewDecryptor(model.PlatformDarwin, 4)
	if err != nil {
		return false
	}
	return d.Validate(dbInfo.FirstPage, keyBytes)
}

func resolveDBPath(dataDir, dbRelPath string) string {
	_, dbStorageDir := resolveDBDirs(dataDir)
	p := normalizePath(dbRelPath)
	if filepath.IsAbs(dbRelPath) {
		return dbRelPath
	}
	if strings.HasPrefix(p, "db_storage/") {
		return filepath.Join(filepath.Dir(dbStorageDir), filepath.FromSlash(p))
	}
	return filepath.Join(dbStorageDir, filepath.FromSlash(p))
}

func collectDBSalts(dbStorageDir string) ([]dbSaltEntry, error) {
	stat, err := os.Stat(dbStorageDir)
	if err != nil || !stat.IsDir() {
		return nil, fmt.Errorf("数据库目录不存在: %s", dbStorageDir)
	}

	out := make([]dbSaltEntry, 0, 64)
	err = filepath.WalkDir(dbStorageDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".db") {
			return nil
		}
		salt, ok := readDBSalt(path)
		if !ok {
			return nil
		}
		rel, err := filepath.Rel(dbStorageDir, path)
		if err != nil {
			return nil
		}
		out = append(out, dbSaltEntry{SaltHex: salt, DBRel: normalizePath(rel)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func readDBSalt(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	buf := make([]byte, 16)
	if _, err := io.ReadFull(f, buf); err != nil {
		return "", false
	}
	if string(buf[:15]) == "SQLite format 3" {
		return "", false
	}
	return strings.ToLower(hex.EncodeToString(buf)), true
}

func resolveDBDirs(dataDir string) (accountDir string, dbStorageDir string) {
	clean := filepath.Clean(dataDir)
	if clean == "." || clean == "" {
		return dataDir, filepath.Join(dataDir, "db_storage")
	}
	base := strings.ToLower(filepath.Base(clean))
	if base == "db_storage" {
		return filepath.Dir(clean), clean
	}
	return clean, filepath.Join(clean, "db_storage")
}

func normalizeAllKeysOwnership(keysPath string) error {
	_ = os.Chmod(keysPath, 0600)

	// sudo 场景：文件会默认 root 属主，这里自动转回调用用户，避免后续 GUI/HTTP 无法读取。
	if os.Geteuid() != 0 {
		return nil
	}
	uidStr := strings.TrimSpace(os.Getenv("SUDO_UID"))
	gidStr := strings.TrimSpace(os.Getenv("SUDO_GID"))
	if uidStr == "" || gidStr == "" {
		return nil
	}
	uid, err := strconv.Atoi(uidStr)
	if err != nil || uid <= 0 {
		return nil
	}
	gid, err := strconv.Atoi(gidStr)
	if err != nil || gid <= 0 {
		return nil
	}
	if err := os.Chown(keysPath, uid, gid); err != nil {
		return err
	}
	return os.Chmod(keysPath, 0600)
}
