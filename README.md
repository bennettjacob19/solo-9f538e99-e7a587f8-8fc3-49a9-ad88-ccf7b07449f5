# 内网 APT 源（FastAPI）

单发行版、单组件、单架构的 APT 软件源。每次发布先落盘、后切换
`Release`，启用 **Acquire-By-Hash**，并只保留最近两次成功发布所引用的
索引和安装包。拿到旧 `Release` 的客户端仍可按其中的 SHA-256 取回旧索引，
再按索引校验下载安装包；同名同版本重新构建也互不覆盖。

支持对当前 `Release` 做 **GPG 密钥轮换签名**：在 `/swagger-ui` 提交服务本机
预置的 1～2 个密钥指纹，即可为当前 `Release` 重新生成标准 clearsigned
`InRelease`，无需重传 `.deb`、也不产生新发布；常规发版自动沿用当前生效的
密钥组合，换签与发版任意交错，客户端拿到的 `InRelease` 始终由同一个已生效
状态的 `Release` 与密钥组合生成。

## 快速开始（docker compose）

```bash
docker compose up -d --build
curl -s http://127.0.0.1:8080/api/status | python3 -m json.tool
```

上传一批 `amd64` 的 `.deb`（整版发布，一次请求一批）：

```bash
curl -fsS -X POST http://127.0.0.1:8080/api/publish \
  -F files=@hello-internal_1.0.0_amd64.deb \
  -F files=@libfoo_2.1.0_amd64.deb | python3 -m json.tool
```

也可以直接用浏览器打开 <http://127.0.0.1:8080/docs> 的上传表单
（OpenAPI 文档在 `/swagger-ui`）。

## 客户端配置与实测

```bash
sudo ./clients/setup-client.sh http://127.0.0.1:8080 stable main
# 等价于写入 /etc/apt/sources.list.d/internal.list：
#   deb [trusted=yes arch=amd64] http://127.0.0.1:8080/ stable main

sudo apt-get update
apt-get download hello-internal          # 下载并校验
sudo apt-get install hello-internal      # 或直接安装
```

仓库未签名，因此用 `trusted=yes`。启用签名后（见下节），把 `trusted=yes`
换成 `signed-by=/usr/share/keyrings/internal.gpg`。

## GPG 签名与密钥轮换

### 1. 预置签名密钥

服务本身不生成、不持有密钥口令：操作员先把 1～2 个**无口令**私钥预置到
GnuPG home（默认在数据卷内 `<data>/gnupg`，可用 `APT_REPO_GPG_HOME` 覆盖，
也可以只读挂载密钥目录）。

```bash
# 生成 old/new 两把密钥，并导出客户端用的公钥到 data/public-keys/
sh scripts/generate-signing-keys.sh ./data/gnupg 2
```

容器内通过环境变量 `APT_REPO_GPG_HOME`（默认 `/data/gnupg`）定位该目录，
镜像已安装 `gnupg`。

### 2. 查询可用指纹并换签

```bash
curl -s http://127.0.0.1:8080/api/signing/keys
# {"available_fingerprints":["<OLD>","<NEW>"],"max_keys":2}

# 为“当前” Release 重新签名（不重传 deb、不新增发布）
curl -s -X POST http://127.0.0.1:8080/api/signing \
  -H 'Content-Type: application/json' \
  -d '{"fingerprints":["<OLD>"]}'
```

返回**原发布号**与本次生效的指纹：

```json
{
  "publication_id": 3,
  "release_sha256": "…",
  "effective_fingerprints": ["<OLD>"],
  "inrelease_sha256": "…",
  "inrelease_url": "/dists/stable/InRelease"
}
```

双签即传两个指纹；再次只传一个指纹即完成退役。整个轮换生命周期：

| 生效密钥 | 只信任旧钥的客户端 | 只信任新钥的客户端 |
| --- | --- | --- |
| 仅旧钥 | `apt-get update` 成功 | 失败（`NO_PUBKEY`） |
| 旧钥 + 新钥（双签） | 成功 | 成功 |
| 仅新钥 | 失败（`NO_PUBKEY`） | 成功 |

双签的 `InRelease` 是**一个** clearsigned 装甲块、内含两个签名（标准 Debian
多签形式）；APT 只要其中一个签名能链接到 `signed-by` 信任的公钥即接受。

### 3. 客户端 `signed-by` 配置

```bash
# 公钥可直接从服务端取回（armored），再 dearmor 成 keyring
curl -s http://127.0.0.1:8080/api/signing/keys/<FPR>/public \
  | gpg --dearmor | sudo tee /usr/share/keyrings/internal.gpg >/dev/null

# 轮换过渡期可让客户端同时信任两把钥：cat old.gpg new.gpg > internal.gpg
sudo ./clients/setup-client.sh http://127.0.0.1:8080 stable main \
  /usr/share/keyrings/internal.gpg
sudo apt-get update
```

### 4. 一致性、失败安全与重启

- **交错一致**：启用签名后，常规发版在同一提交事务内用生效密钥组合签名；
  换签只对当前 `Release` 重签。固定路径 `Release`/`InRelease` 都经发布
  journal 解析到同一生效状态，因此换签与发版任意交错，`InRelease` 内嵌的
  始终是当前正在服务的那份 `Release` 原文。
- **失败安全**：指纹不存在、GPG 签名失败或写入失败都在任何状态变更前
  返回 `400`，原 `Release` 与原 `InRelease` 照常可用；发版阶段签名失败则
  整批发布回滚。
- **重启沿用**：生效状态（指纹集合、对应发布、`InRelease` 哈希）持久化在
  `state.sqlite3`，`InRelease` 按内容哈希存于
  `dists/<suite>/inrelease-by-hash/SHA256/`。重启时 `reconcile()` 重新挂接
  最后生效的 `InRelease`；若内容文件丢失且密钥仍在，则按记录的密钥重新
  签名恢复。

一键实测（真实 `apt-get update` + 各自只信任旧钥/新钥的 `signed-by`，
并在轮换中插入一次常规发版）：

```bash
sh scripts/e2e-signed-apt.sh http://127.0.0.1:8080
```

实测输出：

```
== stage1 old-only sign: client 'old' OK
== stage1 old-only sign: client 'new' rejected (expected)
== interleaved publish: client 'old' OK / 'new' rejected
== stage2 dual sign: client 'old' OK / client 'new' OK
== stage3 new-only sign: client 'old' rejected / client 'new' OK
== OK
```


一键端到端验证（发布两版、`apt-get update`/`download`、旧 Release 客户端
按哈希取包、第三版触发淘汰）：

```bash
sh scripts/e2e-apt.sh http://127.0.0.1:8080
```

实测输出示例：

```
== release 1 published (index 71440bc1...)
== apt-get download smoke-one -> smoke-one_1.0.0_amd64.deb
== release 2 published (index 6fc51fd9...)
== apt-get download smoke-two -> smoke-two_2.0.0_amd64.deb
== previous release index and packages verified via by-hash
== retention keeps exactly the two most recent releases
== OK
```

## 发布语义

| 需求 | 实现 |
| --- | --- |
| 新版编制期间继续供包 | 新索引/包先写入不可变路径（`by-hash/SHA256/<hash>`、内容寻址的 pool 文件），旧 `Release` 与旧索引在此期间保持不变 |
| 切换时索引与包同时可下载 | `Release` 用原子 `rename` 作为唯一提交点；在此之前所有被引用的文件都已 fsync 落盘 |
| 旧 Release 客户端仍可取旧索引 | `Acquire-By-Hash: yes` + `dists/stable/main/binary-amd64/by-hash/SHA256/<sha256>`，`dists/stable/by-hash/SHA256/<sha256>` 亦提供 Release 本体 |
| 同名同版本重发 | pool 文件名带内容哈希：`<pkg>_<ver>_<arch>_<sha16>.deb`，两版并存 |
| 只开放最近两次成功发布 | GC 以 journal 中最新 2 条 `committed` 记录为根，删除其余 by-hash 索引与 pool 文件 |
| 坏包 / 提交前中断两版照旧 | 上传先完整校验；任一文件非法则整批拒绝。提交中断时旧 `Release` 不变，重启后 `reconcile()` 回滚 |
| 重启后仍可取用 | 启动时对比磁盘上 `Release` 的哈希与 journal 中 `staged` 记录：一致则补记为 `committed`，否则标记 `aborted` 并清理 |

### 目录结构（数据卷内）

```
/data
├── export/                                  # 只读 HTTP 根目录
│   ├── dists/stable/Release
│   ├── dists/stable/InRelease               # 固定路径，经 journal 解析到生效状态
│   ├── dists/stable/by-hash/SHA256/<release-sha256>
│   ├── dists/stable/inrelease-by-hash/SHA256/<inrelease-sha256>
│   ├── dists/stable/main/binary-amd64/Packages(.gz)
│   ├── dists/stable/main/binary-amd64/by-hash/SHA256/<index-sha256>
│   └── pool/main/<bucket>/<pkg>/<pkg>_<ver>_<arch>_<sha16>.deb
├── gnupg/                                   # GnuPG home（预置的签名私钥）
├── incoming/<token>/                        # 上传暂存，发布后删除
└── state.sqlite3                            # 发布 journal + 签名生效状态（GC 的依据）
```

`Release` 同时列出 `Packages` 与 `Packages.gz`：APT 2.6 以未压缩名识别
索引目标，只列 `Packages.gz` 会被静默跳过（本项目最初即踩此坑）。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/publish` | multipart 字段 `files`，一次一批，返回 201 与发布记录 |
| POST | `/api/signing` | body `{"fingerprints":[...]}`（1～2 个指纹），为当前 Release 换签，返回原发布号与生效指纹 |
| GET | `/api/signing/keys` | 本机已预置的可签名私钥指纹 |
| GET | `/api/signing/keys/{fpr}/public` | 导出指定指纹的 armored 公钥（供 `signed-by`） |
| GET | `/api/signing/events` | 换签审计记录（`effective`/`rejected`/`failed`） |
| GET | `/api/status` | 当前配置、签名状态、最新发布、发布历史 |
| GET | `/api/publications` | 发布历史（含 `aborted`） |
| GET | `/docs` | 上传表单 |
| GET | `/swagger-ui` | OpenAPI 文档（可在此填写指纹调用 `/api/signing`） |
| GET/HEAD | `/dists/...`、`/pool/...` | 仓库文件（只读，含 `InRelease`） |

错误语义：包非法 / 重复的同名同版本 / 批次超限返回 `400`/`413`，且
仓库状态完全不变；签名指纹非法、密钥缺失或签名失败返回 `400`，原发布与
原签名保持可用；指纹数量越界由 schema 返回 `422`。

## 配置

| 环境变量 | 默认值 |
| --- | --- |
| `APT_REPO_DATA_DIR` | `./data`（容器内 `/data`） |
| `APT_REPO_DISTRIBUTION` | `stable` |
| `APT_REPO_COMPONENT` | `main` |
| `APT_REPO_ARCHITECTURE` | `amd64` |
| `APT_REPO_ORIGIN` / `APT_REPO_LABEL` | `Internal APT Repository` |
| `APT_REPO_RETENTION` | `2` |
| `APT_REPO_MAX_FILE_BYTES` | `536870912` |
| `APT_REPO_MAX_BATCH_FILES` / `_BYTES` | `500` / `4 GiB` |
| `APT_REPO_GPG_HOME` | `<data>/gnupg`（容器内 `/data/gnupg`） |

## 操作约束

- **单写入进程**：发布通过进程内线程锁 + `flock` 串行化，`docker compose`
  固定 `--workers 1`。多副本部署时需改为共享存储上的分布式锁。
- **签名密钥**：服务只调用 `gpg --clearsign`，不生成/托管密钥；私钥以无口令
  形式预置在 `APT_REPO_GPG_HOME`。未配置任何生效指纹时仓库保持 unsigned
  （仅 `Release`，无 `InRelease`）。
- **下载与 GC 竞态**：响应通过已打开的 fd 流式发送，即使文件随后被 GC
  删除，进行中的下载仍能读到完整内容（POSIX inode 语义）。
- 容器以只读根文件系统、非 root（uid 10001）、`no-new-privileges` 运行。

## 本地开发与测试

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest httpx
uvicorn app.main:app --reload          # 数据写入 ./data
pytest -q                              # 40 项测试（需安装 gnupg）
```

测试覆盖：发布/回读、旧 Release 按哈希取旧索引与旧包、同名同版本重发、
两版保留与第三版淘汰、坏包整批拒绝、错误架构拒绝、提交前中断回滚、
提交后崩溃恢复、下载中被 GC、Release 格式与 by-hash 服务、路径穿越；以及
GPG 签名的启用/轮换/退役、old→dual→new 三态 `gpgv` 矩阵、发版沿用生效
密钥、换签与发版交错一致性、签名失败保持旧状态、重启后沿用最后生效状态。
