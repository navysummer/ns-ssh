# ns-ssh 与 OpenSSH 差距清单（2026-11-05 重新核实）

- 基准：OpenSSH 9.9p2（本机 `ssh` / `sshd` 实际行为）
- 项目：`ns-ssh` 工作区（`ssh-core`、`ns-ssh`、`ns-ssh-server`）
- 说明：基于 2026-11-04 审计文档 `openssh-gap-audit.md`，本次对其中标记为「未实现 / 半成品 / 有缺陷」的条目逐条重新核实。审计日之后有 18 个提交，大量条目已被修复。
- 证据口径：只采用可执行代码、算法表、消息分派分支与测试代码；注释/README 不作为状态证据。
- 状态定义：
  - **已实现可用**：有完整实现路径，且与真实 OpenSSH 互通或集成测试有直接证据。
  - **半成品**：主路径存在，但能力子集明显小于 OpenSSH，或存在未接线的配置项。
  - **未实现**：全仓检索不到对应实现路径。
  - **有缺陷**：实现存在，但行为与 OpenSSH/RFC 不一致，或存在可复现的错误/安全默认值问题。

## 1. 结论摘要

原审计 130 项中的 50 项（未实现 18 + 半成品 16 + 有缺陷 16）经重新核实：

| 类别 | 审计时数量 | 现仍待办 | 已由 18 个提交修复 |
|---|---:|---:|---:|
| 未实现 | 18 | 11 | 7 |
| 半成品 | 16 | 10 | 6 |
| 有缺陷 | 16 | 3 | 13 |

**累计已修复 26 项**，剩余 **24 项**仍需处理。具体为：

### 已修复（26 项，不再需要工作）
- **KEX/算法默认值**：K05（group14-sha1 退出默认）、C06（默认 cipher 集合/顺序对齐）、M05（默认不再通告 `none` MAC）、P10（kex-strict Terrapin 防护完整实现）
- **Host key / 证书**：H04（ssh-rsa 退出默认 host key 列表）、H05（证书 host key `*-cert-v01@openssh.com`）、H08（known_hosts `@cert-authority` / `@revoked` 语义）
- **认证**：A05（用户/主机证书认证）、A08（hostbased 双向认证）、A13（服务端 Match LocalAddress/LocalPort/RDomain）、A15（AuthenticationMethods 多因素）
- **通道/会话/转发**：P14（通道 recipient 语义）、P15（窗口调整 deferred 队列）、P16（CHANNEL_EOF/CLOSE 收尾）、F09（ControlMaster/ControlPersist）、F10（ControlMaster 主循环错误处理）、S08（多通道并发）
- **SFTP/scp**：Q02（OpenSSH sftp 退出收尾）、Q03（longname/attrs 真实性）
- **CLI/config**：L04（客户端 Include）、L05（客户端 Match 条件）、L06（未知配置项处理）、L07（失败退出码 255）、V03（服务端未知指令）
- **测试**：W01/W02/W03（零警告已实测为 0）

### 剩余待办（24 项）

#### 未实现（11 项）
| 编号 | 能力项 | 优先级 | 证据 |
|---|---|---|---|
| K07 | `sntrup761x25519-sha512`（含 `@openssh.com`，后量子 KEX，OpenSSH 9.9 默认首选） | P1 | `transport.rs:19,22-33`；`kex.rs` 无命中 |
| C07 | `none` cipher | P3 | `cipher.rs:853-865,869-882` |
| M03 | `umac-64/128`（含 `-etm`） | P2 | `mac.rs:115-127`；`transport.rs:48-56` |
| M04 | `hmac-md5`、`hmac-ripemd160` | P3 | `mac.rs:115-127,129-141` |
| P11 | `first_kex_packet_follows`（猜测标志恒 false，接收端无丢弃逻辑） | P3 | `transport.rs:280,374-384` |
| Q05 | SFTP 扩展 `copy-data` / `expand-path` / `check-file` / `lsetstat` / `users-groups-by-id` / `home-directory` | P2 | `server.rs:3935-3942,4424` |
| Q07 | SFTP 批量/续传命令 `mget`/`mput`/`reget`/`reput`/`df`/`chown` | P2 | `sftp.rs:388-545` |
| A06 | PAM（`UsePAM yes`） | P1 | `config.rs:1868-1885`（接受但不实现） |
| A07 | GSSAPI（Kerberos） | P2 | `config.rs:1871-1876`；`server.rs:1214` 无分支 |
| H06 | SK host key（`sk-ssh-ed25519`/`sk-ecdsa`） | P2 | `auth.rs:43-44`；`hostkey.rs` 无 sk |
| V06 | 服务端 `UsePAM` | P1 | `config.rs:908-1111`（接受但不实现） |

> 注：A06 与 V06 同源（均为 PAM）。A07 与客户端 GSSAPI 同源。H06 与 A09 同源（均为 SK 密钥）。

#### 半成品（10 项）
| 编号 | 能力项 | 优先级 | 证据 |
|---|---|---|---|
| A02 | password（bcrypt `$2*`、yescrypt `$y$` 不支持，未接 PAM） | P1 | `auth.rs:852-862` |
| A03 | keyboard-interactive（服务端固定单轮，无多轮状态机） | P1 | `server.rs:1342-1349` |
| A09 | SK 密钥认证（仅词法识别，无验签） | P2 | `auth.rs:45-46,648-700` |
| Q06 | SFTP 客户端命令集（缺 stat/symlink/version/progress/reget/reput/mget/mput/df/chown/lchmod 等） | P1 | `sftp.rs:388-545` |
| R02 | scp `-p`（`-p` 解析被当未知旗标误吞源参数；不保留 atime/owner） | P3 | `scp.rs:78,131,181-207`；`main.rs:692-730` |
| R04 | scp 多源 / 远程到远程 | P3 | `main.rs:660-715,840` |
| L01 | 客户端参数集（缺 `-B`/`-w`/`-K` 等） | P2 | `main.rs:44-156` |
| L02 | `-Q` 查询类型（缺 `key-sig`/`sig`/`help`） | P2 | `transport.rs:71-78`；`main.rs:241-249` |
| V01 | sshd CLI（缺 `-t`/`-T`/`-6`） | P2 | `server main.rs:14-41` |
| X03 | X11 trusted（`-Y` 与 `-X` 无差别，均 untrusted 伪造 cookie） | P3 | `main.rs:284-294`；`client.rs:1827-1838,3324-3335` |

#### 有缺陷（3 项）
| 编号 | 能力项 | 优先级 | 证据 |
|---|---|---|---|
| P09 | EXT_INFO 条件发送（服务端无条件发送；`server-sig-algs` 仍含 `ssh-rsa`；客户端不通告 `ext-info-c`） | P2 | `server.rs:622-642`；`transport.rs:227-282` |
| R03 | scp `-r` 语义（`_recursive` 解析后从未使用，目录不显式 `-r` 也递归） | P2 | `main.rs:692,703-704`；`scp.rs:69,146` |
| X04 | X11 MIT-MAGIC-COOKIE 写入（默认 `XAuthLocation=None`，`-X` 不写 cookie） | P3 | `client.rs:4218-4231`；`config.rs:642` |

#### 测试/门禁（仍在清单但需确认）
| 编号 | 能力项 | 优先级 | 证据 |
|---|---|---|---|
| T01 | 集成测试并发执行（并行挂起，只能串行） | P1 | `integration.rs` |
| W04 | 零警告门禁固化（将零警告固化为本地门禁） | P2 | 无门禁脚本 |

> 注：原审计中 A06/V06 分开列，此处归并为 PAM 类。原审计中 X03/X04 是"半成品"，本次核实后确认仍是半成品（X03 部分接线、X04 已有写入路径但缺默认值）。原审计中 F09 的 ControlPersist 语义已基本实现（`persist_seconds=None` 时主循环无自动退出分支，与 OpenSSH 默认寿命略有差异，但不影响核心能力）。

## 2. 优先级分组

### P0（安全/阻断互通）
- ~~P04/P07/P14/P15/P16/M05/K05/C06/H04/P10~~ — 均已修复
- **当前无 P0 项**

### P1（主要能力缺口）
- K07 后量子 KEX（sntrup761x25519）
- A02 password bcrypt/yescrypt
- A03 keyboard-interactive 多轮
- A06/V06 PAM（UsePAM）
- Q06 SFTP 客户端命令集补齐
- T01 集成测试并发

### P2（兼容性）
- M03 umac-64/128
- Q05 SFTP 扩展
- Q07 SFTP 批量/续传命令
- A07 GSSAPI
- A09 SK 密钥认证
- H06 SK host key
- L01 客户端参数集
- L02 `-Q key-sig/sig/help`
- V01 sshd CLI -t/-T/-6
- P09 EXT_INFO 条件发送
- R03 scp `-r` 语义
- W04 零警告门禁

### P3（边缘/旧协议）
- C07 `none` cipher
- M04 hmac-md5/ripemd160
- P11 first_kex_packet_follows
- R02 scp `-p`
- R04 scp 多源/远程到远程
- X03 X11 trusted
- X04 X11 cookie 写入

## 3. 需要产品决策的选型（先确认再实现）

与 2026-11-04 审计相同的决策点，仅列出仍未决策的：

1. **PAM / GSSAPI / 证书**：依赖系统库或新增纯 Rust 依赖，与"零第三方依赖"约束冲突。需确认是否允许新增依赖或平台条件编译。
2. **后量子 KEX（sntrup761x25519）**：需要引入 sntrup761 纯 Rust 实现或新依赖。
3. **UMAC**：OpenSSH 默认 MAC 列表包含 umac-64/128；需实现 UMAC 算法（或新依赖）。
4. **SK 密钥（FIDO2）**：需要实现 webauthn 验签或接入外部 provider。
5. **未知配置指令**：已严格报错（与 OpenSSH 一致），无需决策。
6. **scp 协议路线**：OpenSSH 9 默认走 SFTP 协议，`-O` 才用旧 SCP；当前走旧协议。是否切换到 SFTP 需决策。

## 4. 验证入口

- P15：`cargo test -p ns-ssh --test integration large_upload_to_non_echoing_command_completes -- --test-threads=1`
- P14：`cargo test -p ssh-core reply_recipient_maps_local_to_peer_id`
- X02/X03 基线：`cargo test -p ns-ssh --test integration x11_forwarding_round_trip -- --test-threads=1`
- 零警告：`cargo clean -p ssh-core -p ns-ssh -p ns-ssh-server && cargo build --workspace --all-targets 2>&1 | grep -c 'warning:'`
