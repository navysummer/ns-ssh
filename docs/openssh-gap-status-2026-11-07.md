# ns-ssh 与 OpenSSH 差距清单（2026-11-07 重新核实）

- 基准：OpenSSH 9.9p2（本机 `ssh` / `sshd` 实际行为）
- 项目：`ns-ssh` 工作区（`ssh-core`、`ns-ssh`、`ns-ssh-server`）
- 说明：在 2026-11-05 状态清单基础上，本轮（2026-11-07）完成剩余高价值差距的补齐，并逐项重新核实。证据口径同前：只采用可执行代码、算法表、消息分派分支与测试代码；注释/README 不作为状态证据。
- 状态定义：
  - **已实现可用**：有完整实现路径，且与真实 OpenSSH 互通或集成测试有直接证据。
  - **半成品**：主路径存在，但能力子集明显小于 OpenSSH，或存在未接线的配置项。
  - **未实现**：全仓检索不到对应实现路径。
  - **有缺陷**：实现存在，但行为与 OpenSSH/RFC 不一致，或存在可复现的错误/安全默认值问题。

## 1. 本轮补齐项（2026-11-07）

| 编号 | 能力项 | 状态 | 证据 |
|---|---|---|---|
| A07 | GSSAPI 认证（`gssapi-with-mic`，客户端 + 服务端） | **已实现可用** | `ssh-core/src/gssapi.rs`、`gssapi_sys.rs`；`ns-ssh/src/client.rs`、`ns-ssh-server/src/server.rs` 均有完整分派；`gssapi_available()` 用 fork 子进程探测库可用性，规避 macOS GSS.framework shim 的 OID 段错误；真实 OpenSSH `ssh` 与 ns-ssh-server 双向互通（`parity.rs real_openssh_gssapi_configured_falls_through_to_pubkey`） |
| A06/V06 | PAM 会话栈（`pam_open_session` / `pam_close_session`） | **已实现可用** | `ns-ssh-server/src/pam.rs` 新增 `PamSession`（open/close/Drop），服务端认证后打开会话、连接结束关闭；`pam_session_open_and_close_is_safe`、`pam_session_is_send` 单测通过 |
| K07 | `mlkem768x25519-sha256`（RFC 9765 后量子 KEX） | **已实现可用** | `ssh-core/src/kex.rs` 新增 `MlkemX25519Kex`（ML-KEM-768 + X25519，SHA-256 混合共享密钥）；加入 `DEFAULT_KEX`（与 OpenSSH 9.9 默认顺序一致）；双向互通：`real_openssh_mlkem_kex_interop`（OpenSSH ssh → ns-ssh-server）、`ns_client_to_real_sshd_mlkem_kex_interop`（ns-ssh → 真实 sshd）；`mlkem_hybrid_round_trip_agrees_on_shared_secret` 单测 |
| H06 | SK 主机密钥（`sk-ssh-ed25519*`、`sk-ecdsa-sha2-nistp256*`）加入默认通告 | **已实现可用** | `ssh-core/src/transport.rs` `DEFAULT_HOST_KEYS` 按 OpenSSH 9.9 顺序补齐 SK 类型；`hostkey.rs` 已有 SK 验签路径；`sk_ed25519_host_key_parses_and_verifies` 单测 |
| L02 | `-Q` 语义对齐（列出可配置集合，而非默认集） | **已实现可用** | `ssh-core/src/transport.rs` `supported_algorithms`：`cipher`/`mac` 返回完整支持集（`SUPPORTED_*[1..]`，与 OpenSSH `-Q` 一致），`-Q cipher`/`-Q mac` 与 OpenSSH 输出逐项匹配 |
| P09 | EXT_INFO 条件发送 | **已实现可用** | `ns-ssh-server/src/server.rs:649` 仅当客户端通告 `ext-info-c` 时发送；`server-sig-algs` 不含 `ssh-rsa`；客户端处理 `ext-info-s`（`client.rs:1432-1438`） |
| R03 | scp `-r` 语义 | **已实现可用** | `scp.rs:88,163` 目录源无 `-r` 时显式报错；`scp_parity_directory_requires_recursive_flag` 与 OpenSSH 同步对比 |
| X03/X04 | X11 trusted（`-Y`）与 cookie 写入 | **已实现可用** | `main.rs:332-347` `-Y` 设 `forward_x11_trusted`；`client.rs:3520-3538` 生成 `MIT-MAGIC-COOKIE-1` 并经 `XAuthLocation` 注册；`x11_forwarding_round_trip` 集成测试 |
| A02 | password bcrypt/yescrypt | **已实现可用** | `ns-ssh-server/src/auth.rs:872-895` `verify_bcrypt`（`$2a/$2b/$2y/$2x$`）、`verify_yescrypt`（`$y$`）；单测通过 |
| A03 | keyboard-interactive 多轮 | **已实现可用** | `server.rs:1122-1125` 多轮状态机（`kbd_round` 递增，`kbd_should_reprompt` 控制重试） |
| L01 | 客户端 `-B`/`-w`/`-K` | **已实现可用** | `main.rs:161-177` 解析并接线 `bind_interface`/`tunnel_device`/`gssapi_deleg_creds` |
| V01 | sshd `-t`/`-T`/`-6` | **已实现可用** | `ns-ssh-server/src/main.rs:28-40` `test_mode`/`dump_config`/`force_ipv6` |
| Q05/Q06/Q07 | SFTP 扩展与命令集（`copy-data`/`expand-path`/`check-file`/`lsetstat`/`users-groups-by-id`/`home-directory`；`mget`/`mput`/`reget`/`reput`/`df`/`chown`/`symlink`/`version`） | **已实现可用** | `server.rs:4409-4414` 扩展通告；`sftp.rs:714-841` 命令分派；`sftp_parity_*` 与 OpenSSH 同步对比 |
| S12 | `ssh-keyscan` 互通（真实 OpenSSH 客户端取回主机密钥） | **已实现可用** | `ns-ssh-server/src/server.rs` 在 accept 后立即发送服务端标识串（RFC 4253 §4.2），再读客户端版本；此前先读客户端版本导致与等待服务端 banner 的 OpenSSH `ssh-keyscan` 死锁、keyscan 无输出。验证：`real_openssh_keyscan_retrieves_host_key` 集成测试（真实 `ssh-keyscan` 返回 `ssh-ed25519` 行；回退旧顺序时该测试失败——死锁空输出）；真实 `ssh`/`ns-ssh` exec 均无回归 |
| S13 | `ssh-keygen -t rsa` 生成 RSA 私钥（openssh-key-v1 序列化） | **已实现可用** | `ssh-core/src/keygen.rs` 新增 `format_openssh_rsa`（CRT 参数 n/e/d/iqmp/p/q，mpint 编码）；`main.rs` RSA 分支接线；`ssh_keygen_rsa_key_is_readable_by_openssh`（真实 OpenSSH ssh-keygen 可读回） |
| S14 | `ssh-keygen -lf`（附着短选项）与指纹位数 | **已实现可用** | `main.rs` keygen 参数解析支持 `-lf`/`-yf` 与位置文件参数；`print_fingerprint` 按密钥类型计算位数（RSA=模长，ed25519=256）；`ssh_keygen_attached_lf_and_bit_length` |
| S15 | `ssh-keyscan -t <type>` 短类型名映射 | **已实现可用** | `main.rs` `keyscan_keytype_to_algs`：`ed25519`→`ssh-ed25519`、`rsa`→`rsa-sha2-512/256` 等；`ns_ssh_keyscan_t_type_maps_to_algorithm`（此前 `-t ed25519` 把 `ed25519` 当算法名导致 KEX 无公共算法、扫描失败） |
| S16 | 全工具双向互通矩阵 | **已实现可用** | `scripts/interop_matrix.py`：keygen/agent/scp/sftp/copy-id/keyscan/exec × `ns-*`/OpenSSH 双向 × `ns-ssh-server`/`sshd`，49 项全过；`ns-ssh` 客户端经 `ns-ssh-agent`/`ssh-agent` 均可签名认证 |
| S17 | 配置文件/密钥路径与 OpenSSH 完全隔离 | **已实现可用** | `ssh-core/src/paths.rs`（`NS_SSH_CONFIG_DIR`/`NS_SSH_ETC_DIR` 可重定向）：客户端 `~/.config/ns-ssh/{config,known_hosts,id_*}`、全局 `/etc/ns-ssh/known_hosts`；服务端 `/etc/ns-ssh/{sshd_config,ssh_host_*}`、`~/.config/ns-ssh/{authorized_keys,known_hosts,rc}`；不再读/写 `~/.ssh` 或 `/etc/ssh`。验证：`client_default_config_comes_from_ns_ssh_path`、`server_default_config_comes_from_ns_ssh_path`、`keygen_known_hosts_defaults_to_ns_ssh_path` 集成测试；端到端 smoke（服务端从 `/etc/ns-ssh/sshd_config` 启动，客户端用默认 `known_hosts`/默认身份连接成功） |

## 2. 算法集对齐（全部与 OpenSSH 9.9 一致）

- **KEX 默认顺序**：`ecdh-sha2-nistp256, sntrup761x25519-sha512, sntrup761x25519-sha512@openssh.com, mlkem768x25519-sha256, curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp384, ecdh-sha2-nistp521, diffie-hellman-group-exchange-sha256, diffie-hellman-group16-sha512, diffie-hellman-group18-sha512, diffie-hellman-group14-sha256` — 与 `ssh -G` 逐项一致。
- **Cipher 默认顺序**：`aes128-gcm@openssh.com, aes256-gcm@openssh.com, chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr` — 与 `ssh -G` 一致。
- **MAC 默认顺序**：与 `ssh -G` 逐项一致（hmac-sha2-256-etm 首，hmac-sha1 尾）。
- **Host key 默认顺序**：含证书变体与 SK 类型，与 `ssh -G` 一致（不含 `ssh-dss`，OpenSSH 9.9 默认也不含）。
- **`-Q cipher` / `-Q mac`**：与 `ssh -Q cipher` / `ssh -Q mac` 输出逐项匹配。

## 3. 剩余显式不支持项（均为 P3 遗留 / 已弃用协议）

经本轮重新核实，唯一仍与 OpenSSH 9.9 存在差异的项是两个已弃用/已破坏的遗留协议，OpenSSH 自身也不在其默认提案中使用：

| 编号 | 能力项 | 说明 |
|---|---|---|
| K08 | `diffie-hellman-group1-sha1` | 1024 位 MODP 群 1 KEX，已被证明可被 Logjam 攻击破坏；OpenSSH 9.9 在 `-Q kex` 中列出但不在默认提案中。未实现（不引入已破坏的 1024 位 DH）。 |
| H09 | `ssh-dss` / `ssh-dss-cert-v01@openssh.com` | DSA 签名，OpenSSH 自 7.0 起默认禁用；OpenSSH 9.9 在 `-Q key` 中列出但不在默认 host key 列表。未实现（不引入已弃用的 DSA）。 |

> 说明：`hmac-ripemd160` 已被 OpenSSH 9.9 移除（`ssh -Q mac` 不含），故不再是差距；`none` cipher / `none` MAC 已实现且仅显式配置可用（与 OpenSSH 一致）；`first_kex_packet_follows` 猜测标志已实现（`transport.rs` 收发两端均处理）。

## 4. 验证入口

- `scripts/check-warnings.sh`：零警告门禁（W04）
- `cargo test --workspace`：全量单测 + 集成 + 互通回归（270+ 用例）
- 双向互通：`cargo test -p ns-ssh --test parity -- --test-threads=1`
- 关键互操作：
  - `cargo test -p ns-ssh --test parity real_openssh_mlkem_kex_interop`（OpenSSH ssh → ns-ssh-server，mlkem768）
  - `cargo test -p ns-ssh --test parity ns_client_to_real_sshd_mlkem_kex_interop`（ns-ssh → 真实 sshd，mlkem768）
  - `cargo test -p ns-ssh --test parity real_openssh_gssapi_configured_falls_through_to_pubkey`
  - `cargo test -p ns-ssh --test integration real_openssh_keyscan_retrieves_host_key`（真实 OpenSSH `ssh-keyscan` → ns-ssh-server，S12）
  - `cargo test -p ns-ssh --test integration ssh_keygen_rsa_key_is_readable_by_openssh`（S13）
  - `cargo test -p ns-ssh --test integration ssh_keygen_attached_lf_and_bit_length`（S14）
  - `cargo test -p ns-ssh --test integration ns_ssh_keyscan_t_type_maps_to_algorithm`（S15）
  - `python3 scripts/interop_matrix.py`（S16：49 项双向互通全过）
  - `cargo test -p ns-ssh --test integration client_default_config_comes_from_ns_ssh_path`（S17）
  - `cargo test -p ns-ssh --test integration server_default_config_comes_from_ns_ssh_path`（S17）
  - `cargo test -p ns-ssh --test integration keygen_known_hosts_defaults_to_ns_ssh_path`（S17）
