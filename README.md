# chatlog_alpha

微信 4.x 聊天记录本地查询工具，支持 `macOS` 与 `Windows`。

> **当前 macOS 实机验证微信版本：`4.1.11.54`（Mac 版）**。其他版本未保证可用。  
>
> **Windows 用户请注意：** 当前 Windows 仍使用**进程内存扫描**提取 data key，**未完成充分实机测试，不保证能正常工作**。请优先在测试环境验证。  
> 若你在 Windows 上使用：无论成功或失败，都欢迎通过 [GitHub Issues](https://github.com/teest114514/chatlog_alpha/issues) **反馈结果**（微信版本、是否提 key 成功、报错信息等），以便评估是否将 Windows 也升级为 **Frida Hook** 方式（与 macOS 对齐）。

## 更新日志（近期）

### 2026-07-10

- macOS 数据库密钥（data key）**仅支持 Frida Hook** `CCKeyDerivationPBKDF`；已移除 data key 内存扫描实现。
- 默认用 LaunchServices `open -a WeChat` 拉起微信后再 attach，保留沙盒用户数据（避免 `frida.spawn` 裸二进制导致空账号）。
- 解密链路改为 SQLCipher4：`PBKDF2-HMAC-SHA512`（256000 轮）派生后 AES-CBC 解页。
- 新增 CLI：`chatlog key`；TUI「重启并获取密钥」走同一 Frida 路径。
- 当前文档标注可运行微信版本为 **Mac 版 4.1.11.54**。

### 2026-04-26

- 实验性语义能力默认切换到本地 Ollama：embedding 默认 `qwen3-embedding:8b`，rerank 默认 `dengcao/Qwen3-Reranker-8B:Q5_K_M`，默认地址 `http://127.0.0.1:11434`。
- GLM/DeepSeek 调整为可选 Chat provider：未配置 Chat API Key 时仍可进行向量索引、语义搜索和 Ollama 精排；会话问答、LLM 摘要和时间知识图谱抽取等 Chat 能力会提示配置后使用。
- 前端“配置与索引管理”新增 Ollama Base URL、DeepSeek API Key/Base URL、Embedding/Rerank/Chat Provider 配置；切换 provider 时会自动同步对应默认模型名。
- Ollama 调用新增串行调度：embedding、rerank、Ollama chat 共享同一执行锁，避免多个本地模型同时加载；同一阶段会复用已加载模型，阶段切换、任务结束或连通性测试结束后释放模型。
- 向量索引和时间知识图谱状态新增处理速度与预计完成时长展示，便于判断本地 Ollama 或远程 LLM 任务是否需要暂停、调低并发或更换模型。
- 修正 Ollama `qwen3-embedding:4b` 维度识别：自动使用 `2560` 维，避免索引已写入但覆盖会话、最近索引消息和检索按错误维度查空。

### 2026-04-25

- 新增“时间知识图谱”实验平台：支持聊天消息、业务数据和外部事件进入本地图谱抽取队列，自动维护实体、关系、事件、事实、证据和时间版本，并提供前端图谱可视化、时间线、事实关系列表和图谱问答。
- 向量索引新增暂停/恢复：暂停会取消当前构建并保留断点，恢复后重建任务按断点续传继续；暂停状态下实时增量索引不会继续触发。
- Chunk 索引增量优化：会话 chunk 不再每次整会话删除重建，会按 `content_hash` 只重算变化片段并清理过期 chunk，降低大群聊和 LLM Chunk 的重复向量化成本。
- Chunk 尾部窗口优化：新增消息通常只从最后一个已索引 session chunk 的起点开始重建尾部片段，避免每次扫描整段超长会话。
- 实体候选优化：联系人/群成员候选会按精确匹配、群内命中、模糊匹配、向量召回分层排序，并合并同一实体来源，减少短昵称误匹配和不必要的歧义提示。
- 前端新增向量化内容可视化：可在“配置与索引管理”中预览消息向量、实体向量和 Chunk 向量的入库文本、类型分布、向量维度、范数、前若干维条形图，并将样本向量投影到可拖拽旋转的模拟 3D 语义空间中观察聚类和离群点。
- 向量化内容可视化增强：支持 `message/entity/chunk` 混合视图，自动按最近邻距离标记疑似离群点；Chunk 视图会按同一会话绘制时间轨迹线，用于观察语义片段是否连续。
- 向量化内容可视化支持按 session 快捷筛选：可搜索最近会话并选择群聊/联系人，只查看该会话的 message、chunk 和关联 entity；Chunk 轨迹会聚焦到选中会话。
- 实验性功能页移除“只检索证据”入口，保留聊天式问答并继续在回答中展示证据。
- 仪表盘热点摘要改为手动触发，点击“生成摘要”后才调用 `summary=1` 和 GLM，避免进入仪表盘或切换时间窗时自动消耗 LLM 请求。

### 2026-04-24

- 移除语义匹配推送：关键词钩子移除基于 GLM Reranker 的语义匹配，仅保留字面 `strings.Contains` 关键词命中。
- 仪表盘扩展：新增全局概览卡片（消息总量/活跃群数/参与人数/索引覆盖）、群聊对比卡片（点击跳转消息检索）、发言人排行榜（跨群 Top 15）、各群消息类型分组柱状图、24h 活跃度多线折线图、每日消息趋势柱状图、语义分析摘要（热点话题 + 隐私提醒）。
- 仪表盘新增时间范围选择器：概览/对比/排行榜/类型/24h 共用一组，默认"今天"；趋势/摘要独立一组，默认"近 1 月"；均支持今天/近 7 天/近 1 月/近季度/近 1 年/全部快捷切换。
- `parseSemanticWindow` 新增 `90d`（近季度）和 `1y`（近1年）支持，对齐前端时间选择器窗口。
- 优化配置日志安全：TUI/HTTP 服务启动日志会对 `data_key`、`img_key`、`api_key`、`token`、`secret` 等敏感字段脱敏。
- 优化语义增量索引：HTTP 服务启动后会主动执行一次增量索引，用于补齐程序关闭期间新增的聊天记录。
- 优化向量索引状态口径：构建进度现在按“成功 + 失败 + 待处理”展示，`pending` 不再包含已失败项。
- 优化前端数据库面板：数据库可查询性探测改为限流并发，避免数据库文件较多时瞬时请求过多。
- 同步 TUI 帮助：补充仪表盘、推送页面、实验性语义能力和全局搜索入口。
- GLM 实验性功能接入 `glm-5.1` Chat Completions：会话问答升级为基于检索证据的 LLM 回答，并显示引用证据。
- 会话问答默认使用 GLM 流式输出，前端以打字机效果逐步展示回答。
- 实验性功能页面重构为 GPT 网页端式聊天交互；模型配置、索引状态、删除索引、重建索引和参数调优统一收入对话框下方的“配置与索引管理”二级面板。
- 语义问答/搜索的数据源改为“最近会话 -> username -> 时间窗聊天记录”的作用域逻辑，支持最近会话数量、指定单个 chat、勾选多个会话和时间窗过滤。
- 会话问答新增 LLM 意图路由：GLM 会先输出受限 JSON 计划，系统再按 `sender_messages`、`sender_semantic_search`、`chat_summary`、`stats`、`keyword_search`、`semantic_search` 等 intent 调用结构化查询、LLM 摘要或向量 RAG；前端会显示本次 `intent/entity/topic/route` 调试信息。
- 实体候选支持前端点击确认：存在重名或歧义时，下一次提问会带上确认后的 `username` 精确过滤发送者。
- 直接查询支持 `answer_mode=list/summary/stats`：列表模式返回原始证据，摘要模式会基于结构化证据再调用 GLM 总结，空召回会返回明确原因。
- 优化会话问答 RAG：自动补充命中消息前后上下文，支持前端多轮追问上下文，并强化证据防注入提示。
- 调整 GLM Embedding 默认维度为 `2048`；embedding 批量请求按最多 64 条拆分，单条输入按 3072 token 近似上限截断。
- 优化语义索引入库内容：过滤纯图片/视频/语音占位、语音通话、撤回消息和常见短确认，降低低信息消息对召回和主题分析的干扰。
- 主题趋势和联系人画像在原图表/词频基础上新增 GLM-5.1 摘要，帮助解释趋势、画像和注意点。
- 向量索引重建改为后台任务，接口会立即返回任务已接收，前端通过状态面板查看进度。
- 增量索引改为“扫描会话、只重算新增或内容变更消息”，可覆盖旧消息后续补解析导致的内容变化。
- 索引失败项改为部分可用：存在失败会话时，已完成索引仍可用于语义搜索/问答，失败会话会在状态中单独展示。

### 2026-04-23

- 新增“实验性功能”页面，承载 `GLM 语义检索与重排序` 全量入口（配置、连通性测试、索引管理、语义搜索、会话问答、主题趋势、联系人画像）。
- 语义能力改为索引就绪后可用；前端动作按钮会按索引状态自动禁用/启用。
- 安全调整：`semantic api_key` 无默认值，`GET /api/v1/semantic/config` 不回显真实 key，仅返回 `has_api_key`；保存时留空会保留已存 key。
- 索引状态增强：新增 `last_incremental_at / last_incremental_added / last_incremental_error` 与 `last_rerank_at / last_rerank_applied / last_rerank_error`。
- 增量索引机制升级：除了搜索触发外，服务端新增后台自动监控（检测会话 `NOrder` 变化时自动触发增量构建）。
- 优化向量召回利用率：语义搜索/问答候选池从“只取最近记录”改为“近期记录 + 时间分层抽样”，长时间窗和 `all` 查询能覆盖更早的历史消息；查询前兜底增量增加 30 秒节流，减少连续问答时重复索引检查。
- 新增实体向量索引：联系人、群聊、群成员群昵称、备注名、昵称、微信号会独立向量化；问答路由解析实体时会融合精确匹配、模糊匹配和实体向量召回，减少昵称/别名不在消息正文中导致的漏匹配。
- 新增 Chunk 级语义索引：同一会话会按动态边界（约 30 条/30 分钟、较长沉默间隔、低主题重叠）切分为会话 chunk，并额外生成时间段摘要 chunk、主题词 chunk；语义搜索/问答会融合单条消息召回和 chunk 召回，改善长讨论、跨多条消息主题无法被单条消息命中的问题。
- RAG 问答增强：证据会先去重压缩；低置信度召回会拒答并提示缩小范围；回答 prompt 强制关键事实引用证据编号；前端证据表展示 `source/chunk_type/score/rerank_score`，便于判断答案可信度。
- 主题趋势与联系人画像升级为图表展示（时间窗支持：今天、近 7 天、近 1 月、全部）。
- 历史/检索接口口径修正：`history/search` 新增并统一 `total_count + limit + offset`，过滤改为“先过滤后分页”，修复小时过滤统计不一致问题。

### 2026-04-22

- 微信关键词推送支持 Hermes Agent Weixin Channel，前端可读取/保存 Hermes 微信配置并做配置可用性检查。
- 新增 Hermes Agent QQ 推送渠道，支持读取/保存 `QQ_APP_ID`、`QQ_CLIENT_SECRET`、`QQBOT_HOME_CHANNEL` 并通过 Hermes `QQAdapter` 发送文本与媒体。
- 推送页面能力整合：支持关键词推送、实时全部转发、指定联系人转发、指定群聊转发，并展示各推送方式结果。

### 2026-04-21

- 朋友圈媒体代理解密增强：对齐参考实现修复 `keystream reverse` 与解密校验策略，降低“返回成功但媒体不可播放”概率。
- 新增官方 WASM 优先解密链路（失败回退本地实现），提升视频号样本兼容性。

## 平台与能力

| 能力 | macOS | Windows |
|------|--------|---------|
| 微信版本（已验证） | **Mac 4.1.11.54** | 未充分实机验证 |
| 数据库 data key | **仅 Frida** Hook `CCKeyDerivationPBKDF` → `all_keys.json` | 进程内存扫描 → `all_keys.json` |
| 图片 key | 内存扫描 / kvcomm 推导 | 内存扫描 |
| 数据查询 | HTTP + MCP | HTTP + MCP |
| 数据源 | 内置 `wcdb_api` 兼容链路 | 同左（实验性） |

其他能力：

- 全局搜索：跨库快速搜索 / 深度搜索
- 朋友圈媒体：图片、视频、实况图代理解密
- 关键词推送：前端/TUI，MCP / POST / Hermes 微信 / Hermes QQ
- 时间知识图谱：业务/事件推送、聊天抽取、关系演化、证据链、时间线与图谱问答

## 兼容微信版本

| 平台 | 版本 | 说明 |
|------|------|------|
| **macOS** | **4.1.11.54** | 当前仓库 data key（Frida）与解密链路的**已验证**版本 |
| macOS | 其他 4.x | 未保证；微信升级后 PBKDF/布局可能变化 |
| Windows | 4.x | 仍为内存扫描，**未保证可用**；欢迎 [Issue 反馈](https://github.com/teest114514/chatlog_alpha/issues) 是否需改 Frida |

查看本机微信版本（macOS）：

```bash
defaults read /Applications/WeChat.app/Contents/Info.plist CFBundleShortVersionString
# 或
/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' /Applications/WeChat.app/Contents/Info.plist
```

## macOS 数据库密钥提取（Frida only）

macOS 上 **唯一** 的 data key 获取方式：

1. 结束当前微信  
2. 用 LaunchServices **`open -a WeChat`** 正常启动（挂上沙盒容器，保留原账号数据）  
3. Frida **尽快 attach**，Hook 系统库 `CCKeyDerivationPBKDF`  
4. 在自动登录 / 打开数据库时捕获 32 字节 passphrase，写入 `all_keys.json`  

解密使用 SQLCipher4：`PBKDF2-HMAC-SHA512`（256000 轮）派生后 AES-CBC 解页。

> **不要**对微信二进制直接 `frida.spawn`：会绕过沙盒，常见现象是「全新微信 / 无原用户数据」。  
> 程序默认已使用 `--mode open`；仅调试可设 `CHATLOG_FRIDA_MODE=spawn`（有丢数据环境风险）。

### 正确安装 Frida（必读）

chatlog **不内置** Frida，依赖本机 Python 的 `frida` 包。请用**当前登录用户**安装（**不要** `sudo pip`，避免装到 root 环境而 chatlog 以普通用户跑找不到包）。

```bash
# 1) 确认 Python 3（系统自带或 Homebrew 均可）
python3 --version

# 2) 安装到当前用户（推荐）
python3 -m pip install --user -U frida-tools

# 3) 验证：必须能 import，且版本建议 >= 17
python3 -c "import frida; print('frida', frida.__version__)"
```

若 `import frida` 失败，按下面排查：

| 现象 | 处理 |
|------|------|
| `ModuleNotFoundError: frida` | 确认 `python3 -m pip install --user frida-tools`；同一 `python3` 执行 `import frida` |
| `pip` / `frida` 命令不在 PATH | 不影响：chatlog 用的是 `python3 -c "import frida"`，**不依赖** `frida` CLI 是否在 PATH |
| 用了 `sudo pip install` | 卸载 root 包或改用 `--user`；用普通用户重新 `python3 -c "import frida"` |
| 多个 Python（Homebrew / pyenv） | 保证 **chatlog 调用的 `python3`** 与安装 Frida 的是同一个：`which python3` |
| 公司代理 / SSL | 配置 pip 镜像后再装，例如：`python3 -m pip install --user -U frida-tools -i https://pypi.org/simple` |

可选：若希望脚本路径固定，可设置：

```bash
export CHATLOG_FRIDA_SCRIPT=/path/to/chatlog_alpha/scripts/wechat_key_frida.py
```

未设置时，会依次查找仓库 `scripts/wechat_key_frida.py`，否则使用二进制内嵌脚本。

### 用法

```bash
# 构建
make build   # 或: go build -o bin/chatlog .

# 提取密钥（会结束当前微信，再 open -a 拉起原账号环境；请随后登录或等待自动登录）
./bin/chatlog key

# 仅输出 64 位 hex，便于脚本
./bin/chatlog key --json

# 指定账号数据目录，捕获后写入 all_keys.json
./bin/chatlog key --data-dir ~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/<账号目录>

# 独立脚本（默认 --mode open，与 chatlog 一致）
python3 scripts/wechat_key_frida.py --timeout 180
```

TUI：菜单 **「重启并获取密钥」** → 同一 Frida 路径。

### 注意事项

- 使用 **当前登录用户** 运行 chatlog / 脚本，**避免 `sudo ./bin/chatlog key`**（否则微信可能落到 `/var/root` 容器，表现为空账号）。
- 抓 key 时请保证微信能完成登录；若超时无输出，登录后**打开任意聊天**再试，或加大超时：`./bin/chatlog key --timeout 300`。
- 图片密钥仍可能走进程内存扫描（与 data key 无关）；仅获取图片 key 时若权限不足，再考虑管理员权限（见下文）。

## GitHub 自动构建产物

当前 `Release` 工作流会自动构建以下平台与架构：

- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`
- `windows/arm64`

发布时会在 `dist/` 生成对应压缩包与二进制文件（Windows 为 `.exe`）。

## 快速开始

### 本地运行

```bash
go run .
```

或：

```bash
go build -o chatlog ./cmd/chatlog
./chatlog
```

### 常用命令（CLI）

```bash
chatlog http list
```

```bash
chatlog http call --endpoint history --query chat=<会话ID> --query limit=100 --query format=json
```

### HTTP 接口命令行调用（全接口）

```bash
# 列出所有可调用 HTTP 接口别名
chatlog http list

# 按别名调用（示例：聊天记录）
chatlog http call --endpoint history --query chat=<会话ID> --query limit=100 --query format=json

# 按原始路径调用（示例：执行 SQL）
chatlog http call --path /api/v1/db/query --query group=message --query file=message_0.db --query sql='select count(*) c from MSG'

# 全局搜索（quick / deep）
chatlog http call --path /api/v1/db/search --query keyword=朋友圈 --query mode=deep --query limit=100

# 媒体接口（模板路径参数）
chatlog http call --endpoint image --path-param key=<image_key>

# 朋友圈媒体代理解密
chatlog http call --path /api/v1/sns/media/proxy --query key=<enc_key> --query url='<sns_media_url>'
```

Skill 文档：`skills/chatlog-http-cli/SKILL.md`

## macOS 权限说明（务必阅读）

### data key（Frida）

- **不需要** `sudo` / 关闭 SIP / `task_for_pid` 提权。  
- 需要：本机已正确安装 Frida（见上文「正确安装 Frida」）。  
- 请用**登录用户**运行；`sudo` 反而容易导致微信用户数据目录错误。

### 图片 key / 进程内存读取（可选能力）

图片密钥若走内存扫描，仍依赖 `task_for_pid`。仅在「获取图片密钥」失败且提示权限不足时，再考虑：

1. 以管理员权限启动（注意：与 data key 的 Frida 路径分开使用，避免长期 `sudo` 跑主程序）。  
2. 或对可执行文件使用 setuid（每次重新编译后需重做）：

```bash
BIN_PATH="/你的实际路径/chatlog"
sudo chown root:wheel "$BIN_PATH"
sudo chmod 4755 "$BIN_PATH"
ls -l "$BIN_PATH"   # 期望看到 -rwsr-xr-x
```

3. 部分系统上稳定读进程内存可能还受 SIP 限制；**仅 data key 时无需关闭 SIP**。

## Windows 说明与反馈（重要）

当前 Windows 与 macOS **提 key 路径不一致**：

| 项 | 现状 |
|----|------|
| data key | **进程内存扫描**（非 Frida） |
| 实机测试 | **未充分验证，不保证正常工作** |
| 权限 | 建议**以管理员身份**运行，否则可能无法读微信进程内存 |

**请 Windows 用户反馈：**

1. 当前内存扫描方式在你的环境是否**工作正常**（提 key / 解密 / 查询）？  
2. 是否希望 Windows 也改为与 macOS 相同的 **Frida Hook** 方案？  

反馈请到仓库 Issues（附微信版本、系统版本、成功/失败与日志摘要）：

→ [https://github.com/teest114514/chatlog_alpha/issues](https://github.com/teest114514/chatlog_alpha/issues)

收到足够反馈后，会再决定是否把 Windows data key 更新为 Frida 方式。

## HTTP 接口（摘要）

基础：

- `GET /health`
- `GET /api/v1/ping`

媒体：

- `GET /image/*key`
- `GET /video/*key`
- `GET /file/*key`
- `GET /voice/*key`
- `GET /data/*path`
- `GET /api/v1/sns/media/proxy`

查询（wx-cli 风格）：

- `GET /api/v1/sessions`
- `GET /api/v1/history`
- `GET /api/v1/search`
- `GET /api/v1/unread`
- `GET /api/v1/members`
- `GET /api/v1/new_messages`
- `GET /api/v1/stats`
- `GET /api/v1/favorites`
- `GET /api/v1/sns_notifications`
- `GET /api/v1/sns_feed`
- `GET /api/v1/sns_search`
- `GET /api/v1/contacts`
- `GET /api/v1/chatrooms`

数据库调试：

- `GET /api/v1/db`
- `GET /api/v1/db/search`
- `GET /api/v1/db/tables`
- `GET /api/v1/db/data`
- `GET /api/v1/db/query`
- `POST /api/v1/cache/clear`

语义检索（Ollama Embedding + Rerank，GLM/DeepSeek Chat 可选）：

- `GET /api/v1/semantic/config`
- `POST /api/v1/semantic/config`
- `POST /api/v1/semantic/test`
- `GET /api/v1/semantic/index/status`
- `POST /api/v1/semantic/index/rebuild`
- `POST /api/v1/semantic/index/clear`
- `GET /api/v1/semantic/search`
- `POST /api/v1/semantic/qa`
  - `POST /api/v1/semantic/qa/stream`（SSE 流式问答，前端默认使用）
- `GET /api/v1/semantic/topics`
- `GET /api/v1/semantic/profiles`

时间知识图谱：

- `POST /api/v1/graph/ingest/message`
- `POST /api/v1/graph/ingest/business`
- `POST /api/v1/graph/ingest/event`
- `GET /api/v1/graph/status`
- `POST /api/v1/graph/rebuild`
- `POST /api/v1/graph/pause`
- `POST /api/v1/graph/resume`
- `GET /api/v1/graph/query`
- `GET /api/v1/graph/timeline`
- `GET /api/v1/graph/visualize`
- `POST /api/v1/graph/qa`

关键词推送（前端“关键词推送”页面与 TUI 同步）：

- `GET /api/v1/hook/config`
- `POST /api/v1/hook/config`
- `GET /api/v1/hook/status`
- `GET /api/v1/hook/events`
- `POST /api/v1/hook/events/clear`
- `GET /api/v1/hook/stream`（SSE 实时事件）
- `GET /api/v1/hook/hermes/weixin`
- `POST /api/v1/hook/hermes/weixin`
- `GET /api/v1/hook/hermes/qq`
- `POST /api/v1/hook/hermes/qq`

输出格式：

- 默认 `YAML`
- 可选 `JSON`（`format=json`）

查询接口口径（最新）：

- `GET /api/v1/history`
  - 新增可选过滤参数：`hour`（0-23）、`is_self`（`1/0`）、`sub_type`、`has_media`（`1/0`）
  - `hour` 不传或留空表示“全部小时”
  - 过滤顺序为“先过滤，再分页”，避免先 `limit` 截断导致统计错位
  - 返回字段包含：
    - `total_count`：过滤后的总条数
    - `count`：当前页条数
    - `limit` / `offset`
- `GET /api/v1/search`
  - 支持 `offset`
  - 结果流程为“先聚合排序，再分页”
  - 返回字段包含 `total_count` / `count` / `limit` / `offset`
- `GET /api/v1/stats`
  - 现在为实时计算（已移除服务端缓存）
  - 返回口径字段：`query_since` / `query_until` / `query_range_label`
  - 群聊 `active_senders` 为真实去重发言人数（非 TopN 长度）
- `GET /api/v1/contacts`
  - 默认 `limit=500`
  - 支持 `is_friend` 筛选（`1/0/true/false`）
- `GET /api/v1/chatrooms`
  - 默认 `limit=500`

YAML 可读性优化：

- `history/search/stats` 已改为结构化输出（固定字段顺序，避免 map 随机顺序）
- 合并转发/笔记中的媒体内容，当 host 缺失时不再生成 `http:///...` 空链接，而是回退为文本占位

## 全局搜索

- 前端页面：访问根页面 `http://127.0.0.1:5030/`，切换到“全局搜索”标签页。
- 接口：`GET /api/v1/db/search`
- 参数：
  - `keyword`：搜索关键词
  - `mode`：`quick` 或 `deep`
  - `limit`：结果总数上限，默认 `100`，最大 `500`
- 返回内容包含命中的：
  - 数据库组
  - 数据库文件
  - 表名
  - 列名
  - 行标识
  - 命中内容预览

说明：

- `quick`：优先性能，适合前端实时搜索。
- `deep`：覆盖更全，会额外尝试解析压缩消息体和部分二进制字段，速度更慢。

## 仪表盘

前端入口：根页面 `http://127.0.0.1:5030/` 的"仪表盘"标签页，集成群聊数据可视化。

分组统计：顶部下拉框选择私聊/群聊会话，展示消息类型饼图、活跃时段柱状图和收发比例。

群聊数据概览（6 项）：

1. **概览卡片** — 群聊消息总量、活跃群数、活跃成员（按群累加）、语义索引覆盖条数
2. **群聊对比卡片** — 各群消息类型占比、活跃发言人、高峰时段，点击卡片可跳转对应群聊消息检索
3. **发言人排行榜** — 跨群汇总 Top 15 发言人及消息数
4. **群聊对比图表** — 合并展示各群消息类型结构和 24 小时活跃度，避免重复模块分散展示
5. **消息趋势** — 基于原始消息统计的每日消息量柱状图，不依赖语义索引
6. **热点摘要** — 基于原始消息抽取热点主题；GLM 可用时由 LLM 完成中文分词、同义归并和噪声过滤，后端再按主题短语回扫全量消息统计支撑数；GLM 不可用时自动回落到本地分词兜底。同时统计“被 @ 最多”排行，并支持 Markdown 摘要展示。

时间范围筛选：

- 概览/群聊对比/排行榜/类型对比/24h 活跃度共用一组时间选择器，默认"今天"，支持近 7 天、近 1 月、近季度、近 1 年、全部。
- 消息趋势/热点摘要共用独立时间选择器，默认"近 1 月"，支持今天、近 7 天、近季度、近 1 年；热点摘要需要点击“生成摘要”手动触发，避免进入仪表盘自动消耗 LLM 请求。

说明：

- 概览卡片、群聊对比和排行榜按 `/api/v1/stats` 的 `time` 参数过滤（`last-1d` / `last-7d` / `last-30d` / `last-3m` / `last-1y` / `all`）。
- 消息趋势和热点摘要按 `/api/v1/dashboard/trend` 的 `window` 参数过滤（`today` / `7d` / `30d` / `90d` / `1y`），该接口直接读取原始消息；趋势图使用 `summary=0` 快速返回，热点摘要点击“生成摘要”后才使用 `summary=1`。GLM 输入包含按日期和会话分层抽样并去重后的原始消息、日趋势、LLM 归并主题和被 @ 排行；响应会返回 `topics_source` / `topics_error`，前端会标明主题来自“LLM 主题归并”还是“本地分词兜底”。
- 语义索引覆盖卡片会显示 `检测中 / 未启用 / 构建中 / 未建立 / 已索引条数 / 不可用`，避免接口异常或索引为空时表现为空白。
- 分组统计（私聊/群聊独立分析）使用各面板的 `since` 参数过滤，默认"近 7 天"。

## 实验性语义能力（Ollama Embedding/Rerank + 可选 GLM/DeepSeek Chat）

前端入口：

- 根页面 `http://127.0.0.1:5030/` 的“实验性功能”标签页现在是 GPT 网页端式聊天入口。
- 右侧可设置时间窗、最近会话数量、指定单个 chat、勾选多个最近会话和检索深度作为数据源/检索策略。
- 时间窗是默认范围；如果问题中包含“今天/昨天/4月23日/2026-04-23/近一月/历史”等明确时间表达，后端会自动覆盖默认时间窗。
- 对话框下方的“配置与索引管理”二级面板中提供模型参数、连通性测试、索引状态、删除索引、重建索引（断点续传）和主题/画像工具。

配置与测试：

- 支持配置 `ollama_base_url`、`embedding_provider`、`rerank_provider`、`chat_provider`、`api_key`、`base_url`、`deepseek_api_key`、`deepseek_base_url`、`embedding_model`、`rerank_model`、`chat_model`、`chat_max_tokens`、`chat_temperature`、`embedding_dimension`、`recall_k`、`top_n`、`similarity_threshold`。
- 支持配置 `index_workers`（并发索引线程数，默认 1，最大 32）。
- 语义能力属于实验性固定能力（前端不可关闭）；`POST /api/v1/semantic/test` 仅做当前表单配置的临时连通性测试，不保存配置、不启动索引、不改变功能状态。Embedding 未配置或不可连接时，索引、检索和问答禁止启动。
- Ollama 默认地址为 `http://127.0.0.1:11434`，默认使用 `qwen3-embedding:8b` 和 `dengcao/Qwen3-Reranker-8B:Q5_K_M`。
- 本地 Ollama 模型采用串行调度：同一时间只运行一个 Ollama 模型，避免 embedding、rerank、chat 同时占用内存/显存；同一阶段会复用已加载模型，阶段切换、任务结束或连通性测试结束后主动释放。代价是切换 embedding/rerank/chat 阶段时会有冷启动开销。
- 性能提示：`qwen3-embedding:8b`、8B 级 rerank/chat 模型对内存和 CPU/GPU 压力较高，16GB 内存机器建议保持 `index_workers=1`，必要时改用 `qwen3-embedding:4b` 或更小模型；Ollama 场景调高并发通常不会线性加速，反而可能增加排队、换模和内存压力。
- 费用提示：GLM、DeepSeek 等远程 API 会按模型、输入 token、输出 token 和请求量计费。重建向量索引、开启 LLM Chunk 摘要、时间知识图谱抽取/校验、热点摘要、主题画像和会话问答都可能产生大量请求；建议先用小时间窗/少量会话测试，再进行全量重建或高并发抽取。
- `api_key` 仅用于 GLM Chat 或 GLM provider，`deepseek_api_key` 仅用于 DeepSeek Chat；两者均无默认值，配置接口不回显真实 key，仅返回 `has_api_key` / `has_deepseek_api_key` 标记。
- `POST /api/v1/semantic/config` 时若 `api_key` 留空，将保留已保存 key（不会清空）。
- 默认模型：
  - embedding provider：`ollama`
  - embedding：`qwen3-embedding:8b`
  - rerank provider：`ollama`
  - rerank：`dengcao/Qwen3-Reranker-8B:Q5_K_M`
  - chat provider：`glm`
  - chat：`glm-5.1`（可选；未配置 GLM API Key 时，会话问答、LLM 摘要、时间知识图谱抽取不可用）
- DeepSeek Chat 可选配置：`chat_provider=deepseek`，默认 `deepseek_base_url=https://api.deepseek.com`，默认模型 `deepseek-chat`；也可手动改为 `deepseek-reasoner`。
- 默认向量维度为 `4096`，与 `qwen3-embedding:8b` 的 Ollama 输出保持一致；`qwen3-embedding:4b` 会自动识别为 `2560` 维。维度或 embedding 模型变更后需要重建向量索引。
- Embedding 请求限制：单次数组最多 64 条；单条输入最多约 3072 tokens，服务端会按该上限做近似截断并自动拆批。
- `chat_model` 默认通过 GLM Chat Completions 调用，请求路径为 `<base_url>/chat/completions`；如选择 DeepSeek，则请求 `<deepseek_base_url>/chat/completions`；如选择 Ollama Chat，则请求 `<ollama_base_url>/api/chat`。

## 时间知识图谱

- 前端入口：“时间知识图谱”标签页。
- 本地图谱库路径：`<WorkDir>/.chatlog_graph/temporal_graph.db`。
- 图谱 schema 包含 `graph_entities`、`graph_relations`、`graph_events`、`graph_facts`、`graph_evidence`、`graph_jobs`、`graph_meta` 和 `graph_source_records`。
- 抽取模型复用“实验性功能”里的 Chat 配置；默认需要配置 GLM API Key。不做本地规则兜底；未配置 Chat、模型请求失败、JSON 解析失败或模型返回空抽取结果时不会产出图谱结果，并会在图谱状态中展示错误。
- 聊天消息接入：图谱模块会在启动后先全量扫描最近会话并建立来源队列，之后独立轮询最近会话并按每个会话的消息 `seq` 增量入队；不依赖关键词/转发 hook。消息来源会携带前 5 条、后 2 条上下文和会话参与者；历史入队还会额外生成会话 chunk 来源，用于抽取跨多条消息形成的事实和关系变化。点击前端“增量重建”或调用 `POST /api/v1/graph/rebuild` 可手动补齐。
- 图谱聊天数据源会过滤纯媒体占位、撤回通知、语音/通话占位、附件占位、极短确认语和纯 @ 召集内容；已有队列中的同类低信息来源会直接标记为已处理，不再调用 GLM。
- 图谱入库前会做确定性质量增强：基于会话参与者、联系人显示名、wxid 和业务实体提示做别名归一；关系谓词会映射为稳定的规范谓词；“今天/明天/下周/月底/4月25日”等时间表达会结合消息时间解析为绝对时间。
- 抽取队列支持并发 worker：默认 1 个 Chat 抽取 worker、1 个历史入队 worker，可在前端调整；来源会先原子领取为 `processing`，中断重启后自动恢复为 `pending`，避免重复抽取或卡住。
- 性能与费用提示：图谱抽取每条来源通常会调用 Chat 模型做抽取，部分流程还会做证据校验/归一化，远程 GLM/DeepSeek 会产生 token 费用；Ollama 本地 Chat 虽不产生 API 费用，但 8B 级模型抽取速度较慢且占用内存，建议默认并发 1，确认机器资源和模型稳定后再调高。
- 业务数据和外部事件可通过 ingest API 或前端表单推送；接口支持单对象或数组批量提交。
- 业务数据的 `entities`、外部事件的 `actors/targets` 会作为强实体提示入库，并同步传给 Chat 模型作为抽取约束。
- 当 Chat 抽取结果包含 `ended/updated/conflict` 等变更时，后端会关闭同一关系/事实的旧 `active` 版本并写入 `valid_to`，用于展示关系和事实的时间演变。
- 图谱抽取后会再调用 Chat 模型做一次证据校验和归一化：不被证据支持的事实/关系不会入库；保留项会写入 `verified`、`support_score`、`canonical_statement/canonical_predicate` 和可选 `conflict_group`。
- 实体入库会维护 `canonical_key/canonical_name/canonical_id`，用于合并昵称、备注、群昵称和同一实体的不同称呼；前端事实/关系列表会展示验证状态、支持度、归一表述和冲突组。
- 图谱问答优先检索时间图谱中的实体、关系、事实和事件，再调用 Chat 模型生成关于事实、关系变化和证据来源的回答；Chat 未配置时返回本地证据摘要。
- `POST /api/v1/graph/rebuild` 默认只补齐/重跑未完成内容；传 `{"reset":true}` 会清空实体/关系/事件/事实/证据并把原始来源重新置为待抽取。
- `pause/resume` 只控制图谱抽取队列，不影响语义向量索引。
- 图谱状态：`GET /api/v1/graph/status` 会返回 `source_count` / `pending` / `processing` / `processed` / `failed` / `progress_pct`，并展示 `started_at` / `processing_rate_per_minute` / `estimated_seconds_left` 用于估算当前抽取任务剩余时长。刚启动或尚未完成任何来源时预计时长会显示为空。

向量索引：

- 实时状态：`GET /api/v1/semantic/index/status`
  - 状态字段包含：
    - 基础构建状态：`indexed_count` / `processed` / `failed` / `pending` / `total` / `progress_pct`
    - 预计完成状态：`started_at` / `processing_rate_per_minute` / `estimated_seconds_left`
    - 增量状态：`last_incremental_at` / `last_incremental_added` / `last_incremental_error`
    - 重排序状态：`last_rerank_at` / `last_rerank_applied` / `last_rerank_error`
  - `pending` 仅表示未处理会话数；构建进度按 `processed + failed` 计算，失败项会单独展示。
- 索引内容预览：`GET /api/v1/semantic/index/preview?kind=message|entity|chunk|all&limit=20&talker=...`
  - 返回入库文本、类型分布、向量维度、向量范数、前若干维样本、3D 投影坐标和离群点评分，不返回完整高维向量。
  - `talker` 可选；传入 session username 后，message/chunk 按会话过滤，entity 返回该会话相关实体。
- 重建索引：`POST /api/v1/semantic/index/rebuild`
  - `reset=0`（默认）：断点续传，继续上次中断进度
  - `reset=1`：从头重建（先清空索引）
  - 当前为后台任务：接口返回 `accepted=true` 后，通过 `GET /api/v1/semantic/index/status` 查看进度。
- 暂停索引：`POST /api/v1/semantic/index/pause`
  - 会取消当前运行中的索引任务，保留已写入索引和重建断点。
  - 暂停状态会写入索引库元信息，服务重启后仍会保持暂停。
- 恢复索引：`POST /api/v1/semantic/index/resume`
  - 如果暂停前是重建任务，会按 `reset=0` 的断点续传方式继续。
  - 如果暂停前是增量任务，恢复后由实时增量 watcher 或下一次检索前兜底增量补齐。
- 删除索引：`POST /api/v1/semantic/index/clear`
- 本地索引库路径：`<WorkDir>/.chatlog_semantic/vector_index.db`
- 同一索引库内还维护实体索引表，用于联系人、群名、群成员别名召回；索引状态中的 `entity_count` 表示当前实体索引数量。
- 同一索引库内还维护 Chunk 索引表，用于会话片段、时间段摘要和主题词片段召回；索引状态中的 `chunk_count` 表示当前 Chunk 索引数量。

已接入能力（6项）：

1. 语义全局检索：`GET /api/v1/semantic/search?query=...&chat=...&window=7d&source_limit=50`
2. 检索精排：`semantic/search` 默认开启 Ollama rerank
3. 会话级问答（RAG 检索证据 + 前后文扩展 + Chat 流式生成）：`POST /api/v1/semantic/qa/stream`
5. 主题聚类/趋势（统计图表 + LLM 摘要）：`GET /api/v1/semantic/topics`
6. 联系人/发送者语义画像（关键词聚合 + LLM 摘要）：`GET /api/v1/semantic/profiles`

说明：

- 语义问答和搜索在未指定 `chat/chats` 时，会先读取最近会话列表，再按每个会话的 `username` 到向量库中检索指定时间窗内的聊天记录。
- 问答实体解析会优先使用联系人/群聊精确匹配，再融合实体向量索引中的联系人昵称、备注、微信号、群名和群成员群昵称；命中的候选会在前端调试信息里展示来源（如 `entity_exact` / `entity_fuzzy` / `entity_vector`）。
- `chat` 表示单会话强制过滤；`chats` 支持逗号分隔多个 `username`；`window` 支持 `today`、`yesterday`、`7d`、`30d`、`90d`、`1y`、`all` 和 `YYYY-MM-DD`。
- 问题内时间优先级高于前端时间窗，也会同步用于向量 RAG 分支，避免“问题问今天但前端仍按近七天检索”的偏差。
- 前端聊天主入口不再暴露手写 TopN，也不再提供“只检索证据”模式；检索深度用于控制问答证据量：`standard`（8 条）、`deep`（16 条）、`wide`（30 条）。专业参数里的 `recall_k/top_n` 仍用于默认配置和 API 调参。
- 对“某人今天发的消息 / 某人昨天说了什么 / 某人近7天发的消息”这类精确条件问题，问答接口会优先走联系人/群成员实体解析 + 原始消息 sender 过滤，不依赖向量相似度碰运气；其他开放问题仍走向量 RAG。
- 对“某人有没有提到某事”这类混合问题，问答接口会先解析发言人，再拉取该发言人的时间窗消息，并使用 GLM 基于证据判断和总结；避免仅靠消息正文向量匹配昵称。
- 对“今天有哪些图片/文件/语音/视频/表情”这类媒体过滤问题，问答接口会直接按消息类型过滤原始消息，不走向量召回。
- 索引状态新增覆盖度：展示已索引会话数、已知会话数、未覆盖会话数和最近索引消息时间，便于判断为什么某个会话可能问不到。
- 实体解析会在调试信息中返回候选数量和是否歧义；多个联系人或群成员同名时，前端会标出 `candidates=N(歧义)`，并可点击候选“使用”来确认精确 `username`。
- LLM 路由现在会做 schema 校验和一次重试；返回会包含 `answer_mode`（list/summary/stats），空结果会展示明确原因。
- 存在实体歧义时，前端会在证据区域列出候选实体（显示名、类型、来源、username）；确认候选后，下一次问答会通过 `entity_override` 精确过滤发送者。
- 前端问答结果顶部会展示调试信息，例如 `intent=sender_semantic_search | route=llm/direct/sender+llm | entity=张三 | topic=合同延期`，用于排查实体解析、时间窗和检索路径。
- 当前 5/6 项仍以轻量统计为基础，LLM 摘要用于解释结果；后续可替换为更强中文分词、聚类算法或长期画像模型。
- 向量召回不是直接全表暴力比对。系统会按会话范围和时间窗自适应扩大候选池，并使用“近期记录 + 时间分层抽样”混合候选，避免 `all` 或长时间窗只召回最近聊天。
- RAG 召回会融合三类向量证据：单条消息、实体索引、Chunk 索引。Chunk 命中后会回查对应时间段内的原始消息作为证据上下文，摘要/主题 chunk 只负责召回，不直接替代原始聊天证据。
- 可选开启 `enable_llm_chunk` 后，重建索引时会调用 Chat Model 为 chunk 生成更高质量摘要和主题；该能力会增加索引耗时和 API 成本，默认关闭。
- 问答生成前会压缩重复证据，并对弱召回执行低置信度拒答；模型回答要求关键事实使用 `[1]`、`[2]` 等证据编号，不允许引用不存在的编号。
- `realtime_index` 开启时，服务运行期间会根据会话 `NOrder` 变化自动触发增量建索引；语义检索前也会做 30 秒节流的兜底增量，兼顾实时性和连续问答性能。
- HTTP 服务启动后会额外执行一次增量索引，用于补齐程序或微信客户端关闭期间产生、但尚未写入索引库的消息。
- 增量索引会扫描会话内消息并按 `content_hash` 跳过未变化内容；新增消息和内容变更消息会重新向量化。
- 语义索引会跳过低信息内容：纯媒体占位（如 `[图片]`、`[视频]`、`[语音]`）、语音通话、撤回消息和常见短确认。历史接口仍完整返回这些消息。
- 索引存在失败会话时，已完成部分仍可用于搜索/问答；失败会话会在状态字段 `failed_talkers` 中展示。

## 朋友圈媒体代理解密

- 接口：`GET /api/v1/sns/media/proxy`
- 典型参数：
  - `url`：朋友圈图片 / 视频 / 实况图资源地址
  - `key`：对应消息 XML 中的 `<enc key="...">`
- 行为：
  - 图片：优先按 `reversed` keystream 解密，失败再尝试 `raw`
  - 视频：按前 `128 KB` 做 XOR 解密，并使用 `reversed` keystream
  - 文件头校验优先，不会只因为响应头里的 `Content-Type` 看起来像图片/视频就跳过解密
  - 优先使用微信官方 `wasm_video_decode.wasm/js` 生成 keystream，失败时回退到本地 Go 实现
- `sns_feed` / `sns_search` 返回的 `media_list` 已带代理地址，可直接访问。

示例：

```bash
curl "http://127.0.0.1:5030/api/v1/sns_feed?limit=5"
curl "http://127.0.0.1:5030/api/v1/sns/media/proxy?key=2503144471&url=https%3A%2F%2F..."
```

自动补 key：

- 如果 `sns_feed` / `sns_search` 已经解析过对应朋友圈消息，服务端会缓存媒体 `url -> key` 映射。
- 之后请求 `/api/v1/sns/media/proxy?key=0&url=...` 时，会优先尝试从缓存里自动补上真实 key。
- 如果该消息从未被解析过，且请求里又没有提供正确 `key`，则无法解密。

运行前提：

- 若要使用官方 WASM 解密路径，运行环境需要安装 `node`。
- 没有 `node` 时，程序会自动回退到内置 Go 实现，但兼容性可能略差。

## 关键词推送与持久化

- 前端页面：访问根页面 `http://127.0.0.1:5030/`，切换到“关键词推送”标签页。
- 配置项与 TUI 一致：
  - `keywords`（多个用 `｜` 分隔）
  - `notify_mode`（`mcp` / `post` / `both` / `weixin` / `qq` / `all`，也支持 `mcp,weixin`、`mcp,qq` 这类组合值）
  - `post_url`
  - `before_count` / `after_count`
- MCP 主动推送方法名：`notifications/chatlog/keyword_hit`
- 前端“关键词推送”页面会展示所有触发事件，不受 `notify_mode` 影响。
- Weixin Channel 推送：
  - 自动读取 Hermes Agent 的 `HERMES_HOME` 或默认 `~/.hermes`
  - 优先从 `.env` 读取 `WEIXIN_HOME_CHANNEL`、`WEIXIN_ACCOUNT_ID`、`WEIXIN_TOKEN`、`WEIXIN_BASE_URL`
  - 同时支持读取 `config.yaml` 的 `platforms.weixin.token`
  - 若 `.env` 未提供 token / base_url，会继续读取 `weixin/accounts/<account_id>.json`
  - 也会尝试读取 `config.yaml` 的 `platforms.weixin.extra`（如 `account_id/token/base_url/cdn_base_url`）
  - 前端可直接读取并修改上述微信配置，保存时会写回 Hermes Home 下的 `.env`
  - 启用 `weixin` 模式时，会校验 Hermes Agent 已安装，且微信渠道已配置完成
  - iLink 接口限制提醒：
    - 该接口存在会话态限制，长时间未交互后，主动推送可能被拒绝或无效。
    - 经验值：先主动给 `clawbot` 发送一条消息后，通常可连续主动推送约 `10` 次（实际次数会随账号状态与接口策略波动）。
- QQ Channel 推送：
  - 自动读取 Hermes Agent 的 `HERMES_HOME` 或默认 `~/.hermes`
  - 优先从 `.env` 读取 `QQ_APP_ID`、`QQ_CLIENT_SECRET`、`QQBOT_HOME_CHANNEL`、`QQBOT_HOME_CHANNEL_NAME`
  - 也支持读取 `config.yaml` 的 `platforms.qqbot.extra.app_id/client_secret` 与 `platforms.qqbot.home_channel`
  - 兼容读取 `config.yaml` 的 `platforms.qq` 段
  - 前端可直接读取并修改上述 QQ 配置，保存时会写回 Hermes Home 下的 `.env`
  - 启用 `qq` 模式时，会校验 Hermes Agent 已安装，且 QQ 渠道已配置完成
  - home channel 默认按私聊处理；若要主动推送到群聊或频道，请使用 `group:group_openid` 或 `channel:channel_id` 前缀
- 事件持久化文件：
  - 优先：`<DataDir>/chatlog_hook_events.json`
  - 回退：`<WorkDir>/chatlog_hook_events.json`
- 清理方式：
  - 前端“清空事件”按钮
  - 或调用 `POST /api/v1/hook/events/clear`

## MCP

端点：

- `ANY /mcp`
- `ANY /mcp/`
- `ANY /sse`
- `ANY /message`

### Hermes Agent 接入

本项目可作为 Hermes 的 HTTP MCP Server 使用。

1. 先确保 chatlog HTTP 服务已启动（默认 `127.0.0.1:5030`）。

2. 在 `~/.hermes/config.yaml` 增加 MCP 配置：

```yaml
mcp_servers:
  chatlog:
    url: "http://127.0.0.1:5030/mcp"
    enabled: true
    connect_timeout: 60
    timeout: 120
    tools:
      resources: false
      prompts: false
```

3. 或使用 Hermes CLI 直接添加：

```bash
hermes mcp add chatlog --url http://127.0.0.1:5030/mcp
hermes mcp test chatlog
```

4. 在 Hermes 会话中执行：

```text
/reload-mcp
```

加载后，工具名称会以 `mcp_chatlog_` 前缀出现。

## 安全与隐私

- 所有处理在本地完成
- 请妥善保管解密数据与密钥文件

## 免责声明

详见 [DISCLAIMER.md](./DISCLAIMER.md)
