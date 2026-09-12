<p align="center">
  <img src="assets/readme/hero.svg" width="100%" alt="A3S OCI Runtime 将每个容器绑定到确切的代次、持久化生命周期和以证据为准入条件的执行驱动">
</p>

<p align="center">
  <strong>Language / 语言:</strong>
  <a href="README.md">English</a> ·
  <a href="README.zh-CN.md">中文</a>
</p>

<p align="center">
  <strong>A3S 的底层执行平面：官方 OCI 类型、持久化生命周期重放，以及原生与辅助虚拟机路径共用的经审查 Linux 执行器。</strong>
</p>

<p align="center">
  <a href="https://github.com/A3S-Lab/OCI-Runtime/actions/workflows/ci.yml"><img alt="CI 状态" src="https://img.shields.io/github/actions/workflow/status/A3S-Lab/OCI-Runtime/ci.yml?branch=main&amp;style=flat-square&amp;label=CI"></a>
  <a href="https://github.com/A3S-Lab/OCI-Runtime/releases/latest"><img alt="A3S OCI Runtime 最新版本" src="https://img.shields.io/github/v/release/A3S-Lab/OCI-Runtime?display_name=tag&amp;sort=semver&amp;style=flat-square&amp;color=68c7ff"></a>
  <img alt="OCI 运行时规范 1.3.0" src="https://img.shields.io/badge/OCI_Runtime_Spec-1.3.0-68c7ff?style=flat-square">
  <img alt="Rust 工作区" src="https://img.shields.io/badge/implementation-Rust-dbe7f0?style=flat-square&amp;logo=rust&amp;logoColor=111827">
  <a href="LICENSE"><img alt="MIT 许可证" src="https://img.shields.io/badge/license-MIT-f0b85a?style=flat-square"></a>
</p>

<p align="center">
  <a href="#启动前先检查">检查</a> ·
  <a href="#当前已实现的能力">实现</a> ·
  <a href="#运行时契约">契约</a> ·
  <a href="#平台状态">平台</a> ·
  <a href="#架构">架构</a> ·
  <a href="#运行真实环境验证关卡">资格验证</a> ·
  <a href="#开发">开发</a>
</p>

---

**A3S OCI Runtime** 负责 A3S 中实际的 Linux 容器执行：精确的 OCI
校验、容器与进程状态、单调递增的代次、操作
日志、终态、平台驱动、辅助虚拟机、经过身份认证的
客户机代理，以及运行时范围内的清理。

它的职责不包括拉取镜像、构建镜像、实现 Compose、管理
产品网络或卷，也不充当 Docker 守护进程。这些职责
仍由 [A3S Box](https://github.com/A3S-Lab/Box) 承担；Box 通过
公共 `a3s-oci-sdk` 提供准备好的
bundle、隔离要求和带版本的附件清单。

不依赖具体提供方的 Rust 契约也可独立使用，包版本为
`a3s-oci-core = "=0.3.1"` 和 `a3s-oci-sdk = "=0.3.1"`。其
`sdk/rust/v*` 源码标签与完整 Runtime 二进制发行版相互独立。

> [!WARNING]
> 本仓库正在积极开发中。目前没有任何内置驱动
> 声明为 `supported`。默认主机服务仅提供能力发现；
> Native Linux 只有在显式作为开发实例启用时才为
> `experimental`，Apple Silicon HVF 为 `experimental`，KVM 和 WHPX
> 仍为 `probe-only`。实验性表示经审查的开发配置可以
> 启动，并不意味着已通过生产认证。

> [!NOTE]
> **本运行时不依赖 KVM。** Linux KVM 只是可选的 `dedicated-vm`
> 辅助虚拟机驱动（与 Windows WHPX、macOS HVF 对等）。当 `/dev/kvm`
> 缺失或不可访问时，主机 discovery 与 Native Linux 执行仍须可用。
> Box Sandbox 生产路由是 Native Linux；需要更强隔离时才走
> MicroVM / DedicatedVm（KVM/WHPX/HVF）。fresh-host KVM 矩阵用于把该
> **可选**驱动从 `probe-only` 晋升，不是开发或运行 Native Linux 平面的前置条件。

## 启动前先检查

设计上，第一步成功执行的操作是只读检查：

```bash
git clone https://github.com/A3S-Lab/OCI-Runtime.git
cd OCI-Runtime
cargo run -p a3s-oci-cli -- features
```

在当前分支用于资格验证的 Windows x86_64 主机上，该命令
报告 hypervisor 可用，同时仍如实反映驱动
就绪程度：

```json
{
  "schema_version": "a3s.oci.features.v1",
  "platform": "windows",
  "architecture": "x86_64",
  "drivers": [
    {
      "driver": "libkrun-whpx",
      "status": "available",
      "readiness": "probe-only",
      "isolation_classes": [
        "dedicated-vm",
        "shared-guest-kernel"
      ],
      "evidence": {
        "hypervisor_present": "true",
        "win_hv_platform_dll": "true"
      }
    }
  ]
}
```

证据对象因主机而异，但选择规则始终一致：

| 报告的状态 | 是否允许启动？ | 含义 |
| --- | --- | --- |
| 主机 `available` + `probe-only` | 否 | 仅用于诊断或资格验证 |
| 主机 `available` + `experimental` | 需显式选择启用 | 经审查的开发配置；仍须通过发布关卡 |
| 主机 `available` + `supported` | 是 | 已认证的配置 |
| 主机 `unavailable` 或 `unsupported` | 否 | 缺少前置条件或平台不适用 |

`DriverCapability::can_launch()` 要求主机能力可用，
且就绪状态为 `experimental` 或 `supported`。

## 当前已实现的能力

| 层级 | 已实现的边界 |
| --- | --- |
| 公共 SDK | 使用官方 OCI `Spec`、`Process`、`LinuxResources`、`State` 和 `Features` 类型的异步 `Send + Sync` Rust 契约；类型化 ID、代次、操作上下文、绑定确切制品的逐驱动能力协商、带版本的附件（包括已授权的存储、Linux 网络接口、不透明的网络强制执行/本地重定向证据、可复用的客户机会话身份）、不可变检查点引用与暂停状态的恢复响应、I/O、文件系统会话、统计、事件和稳定的错误类型 |
| 校验与传输 | OCI 1.0.0–1.3.0 schema 与语义校验，保留未知属性并按忽略语义处理以实现前向兼容；精确覆盖 79 项通用配置和 278 条责任方要求的关卡；固定版本的上游 JSON Schema 套件全部 19 个用例；四种启动配置的 configuration/State/Features 矩阵；不可变配置、附件与检查点的 SHA-256 绑定；通过 Unix socket 或受保护的 Windows 命名管道传输的有界 protocol-8 本地 IPC；以及持久化的 Unix/Windows 短生命周期进程 `create/state/start/kill/delete` CLI 适配器，支持响应丢失后的精确重放 |
| 持久化主机服务 | 精确的 create/state/start/kill/delete；驱动声明的可选操作，包括不可变检查点与暂停代次恢复编排；全局幂等日志，涵盖 File upload 和 Filesystem mkdir/move/remove；重放、代次隔离、启动恢复、启动时跨所有日志的孤立项审计、失败代次隔离、以能力句柄为根且通过 Unix 挂载身份进行隔离的状态遍历、本地与辅助虚拟机驱动提交后的重放记录确认、排序列表、有序事件，以及 Native Linux 和 Apple Silicon HVF 上同 UID 的多容器所有者 |
| 共享 Linux 执行器 | 命名空间创建/加入；进入命名空间前对声明的根目录进行准入检查；`pivot_root`；有序 OCI 挂载，支持相对于根的旧式目标路径和可选字段处理；根据先前配置或合成挂载后的有效目录树解析 rootfs 内部绑定源；分离式有序 `idmap`/`ridmap` 绑定挂载；加入挂载命名空间后，在递归私有化的 rootfs 中暂存设备且不向来源命名空间传播；完整的 OCI 1.3 Linux 挂载选项控制注册表；精确的 init/exec argv、环境、cwd、终端默认值、UID/GID、附加组和 umask；挂载处理后按条件创建 `/dev/fd`、`/dev/stdin`、`/dev/stdout` 和 `/dev/stderr` 链接；OCI hook，具备失败即拒绝的私有描述符隔离和绑定确切所有者的 pidfd 进程组监管；用户映射；精确的绝对 `cgroupsPath` 与稳定的相对路径解析，省略时使用受代次隔离的私有路径；完整的 cgroup v2 CPU shares/quota/burst/period/cpuset/idle 映射，并显式拒绝 cgroup v1 realtime；精确的内存 limit/reservation/swap 和 PIDs 创建/更新映射，保留零值并将 OCI `-1` 编码为 `max`；有限总交换量校验；完整的 cgroup v2 块 I/O 默认/逐设备权重与读写 BPS/IOPS 限速映射，支持零速率清除、按键回读、保留未涉及的局部更新、逆序回滚，并显式拒绝叶级权重；动态 HugeTLB 用量/预留控制；按键设置的 RDMA HCA 句柄/对象限制；有界 OCI 1.3 unified 控制文件写入，支持动态启用控制器、内核定义的格式、拒绝与类型化文件冲突、可读取的空操作/回滚快照和只写控制项；以类型化错误拒绝仅限 cgroup v1 的内存及网络 `net_cls`/`net_prio` 控制；全部五个 capability 集合及内核回读；精确验证 `no_new_privileges`；全部 16 种 OCI rlimit 类型及精确内核回读；`oomScoreAdj`、调度策略、I/O 优先级、精确的 `LINUX`/`LINUX32` init personality；全部七种 OCI NUMA 内存策略模式和三个标志及内核回读；由父进程持有的 Intel RDT CLOS、有序 schemata、进程分配、监控和所有者死亡清理；在加入 cgroup 前后应用 exec CPU 亲和性；事务式命名空间 sysctl，通过描述符限定应用、回读和回滚范围；精确的 rootful 块/字符/FIFO 节点、六个默认设备、`/dev/ptmx`、由 PTY 支撑的 `/dev/console`、持久化占位项清理；基于不可变声明/默认设备清单的 BPF，按顺序收窄资源规则；seccomp、PID 1 监管、pidfd、exec、进程 I/O、按 OCI `consoleSize` 初始化的 PTY；有界且由 Host 确认的变更重放日志；绑定父进程的启动/会话辅助进程；绑定 PID 启动时间的所有者死亡墓碑记录；通过描述符限定范围的文件/文件系统会话；暂停/恢复、资源更新、标准化 CPU/内存/PID/块 I/O 统计，以及已验证配置范围内的清理 |
| 辅助虚拟机边界 | 隔离的 libkrun shim；经过身份认证的 protocol v10，兼容 v1-v9；20 个公共工作负载操作和一个有界维护确认操作；覆盖所有克隆实例的关闭；绑定确切代次的虚拟机会话；静态客户机代理后使用同一个 Linux 执行器。平台中立、每代次一台虚拟机的生命周期现已同时支撑公共 HVF 驱动和 Linux KVM 候选驱动，涵盖 bundle 所有权交接、并发 Create 隔离、重试和终态清理、停止状态恢复墓碑记录及有界关闭。持久化恢复记录保留在各代次的共享目录中；特权 OCI 设备源仅在 Guest 本地 devtmpfs 上创建，并在 Create 屏障处移除；关闭流程会在删除 Guest 运行时根目录前逐一处理所有保留的设备目标清单 |
| containerd runtime-v2 | 仅依赖 SDK 的 `containerd-shim-a3s-oci-v2`，以代码定义 `containerd.task.v2.Task` 全部 17 个方法的契约；包含 24 条路由的转换表，其所需 SDK 操作的确切并集共 18 项，用于端点准入；逐驱动协商 `Checkpoint`/`Restore` v1。Task Checkpoint 提交经过摘要校验的目录包；基于检查点的 Create 恢复暂停代次，schema-v10 元数据在 shim 更换后仍保留 CREATED 到 Start 的屏障。shim 还保留了确切的 2.2.2 arm64 Native Linux 开发资格验证、2.2.3 x86_64 回归证据，以及当前覆盖全部 23 个重启/状态重建边界的 2.2.1 WSL2 连续三轮观测。持久化命名空间/task/exec 身份、可重放的 task 和 `DeleteProcess` 回执、有序的输入/信号/尺寸调整/控制日志、有界 FIFO/PTY I/O、确切代次的崩溃清理与重启恢复均予以保留。Schema v9 仍可读取，并引入精确的待处理 Update 请求体；schema v1-v8 按其文档规定的默认值保持兼容。单元覆盖包括包重放与篡改拒绝、恢复意图的 DeleteShim 清理、接管已提交的 Resume、接管已提交的 init/exec Start、终态信号结算、响应回执重放，以及无竞态的输出游标恢复。没有生产驱动声明 Checkpoint 或 Restore。独立的 rootful Native Linux CRIU 构造器声明这两项操作，并已具备有界的真实内核 v3 检查点/恢复生命周期、响应丢失重放、跨两个边界的替代进程恢复验证，以及 PID/网络命名空间拒绝验证；包 v6 集成了该关卡，而留存带标签包、更广泛配置、跨驱动及多架构资格验证仍待完成。 |
| A3S Box 使用方 | 仅通过公共 SDK 使用生命周期和附件；暂停/恢复；进程与文件系统会话；精确的实时清单、标准化统计、有界有序事件，以及可安全重放的完整资源更新；显式 Native Linux Sandbox 生产路由、带校验和的发行版布局安装；在 `/dev/kvm` 缺失且不可访问的 x86_64 和 aarch64 上，Rust/Python/TypeScript/Go SDK 全部通过验证，而默认路径与跨平台切换仍待完成 |
| 留存证据 | Schema 与规范锁定清单；189 对已认证协议故障覆盖；可移植的九阶段 Create/State/Start/Kill/Delete/Wait/Exec/SignalProcess/WaitProcess/Pause/Resume/Processes/Update/Stats/ReadOutput/WriteStdin/CloseStdin/Resize/File/Filesystem 主机重新打开验证，含精确提交后确认；真实 HVF 的九阶段 Host/Guest Create，加上两阶段 Host 关闭中断与清理；通过持久化服务重新打开及虚拟机/会话所有者替换，验证真实 HVF 上 Create、State、Start、Kill、Delete、Wait、Exec、SignalProcess、WaitProcess、Pause、Resume、Processes、Update、Stats、ReadOutput、WriteStdin、CloseStdin、Resize、File、Filesystem 全部操作各自的九个转换阶段；真实 protocol-v10 Apple Silicon Guest 启动；原生 Linux 真实容器验证，分别精确回读 init/exec capability、`NoNewPrivs`、rlimit、OOM 分数、I/O 优先级、调度器、init personality、init NUMA 内存策略、exec CPU 亲和性和命名空间 sysctl；rootless 默认设备与设备策略关卡；跨两次 Host 重新打开、精确重放 Pause/Resume 操作 ID 并使用原子进度计数器的浸泡测试；所有者死亡时安全终止；精确的 `startContainer` Hook 进程组所有者死亡恢复；同一 Host 上连续三轮真实 containerd 2.2 生命周期/重启/I/O 矩阵，覆盖已删除 exec ID 复用、`DeleteProcess` 与 task Delete 响应丢失重放、提交后客户机日志回收，以及已提交 init-Start、exec-Start、init-Kill、Pause、Resume、Update、WriteStdin、CloseStdin、SignalProcess 和 ResizePty 的 shim 替换关卡；提交后 `WriteStdin` 与 `CloseStdin` 强制清理；全新虚拟机 HVF 浸泡测试；失败即拒绝的 Linux KVM 生命周期/恢复/25 轮浸泡测试入口，加上真实 x86_64 上九阶段 Create/State/Start/Kill/Delete/Wait/Exec/SignalProcess/WaitProcess/Pause/Resume/Processes/Update/Stats/ReadOutput/WriteStdin/CloseStdin/Resize/File/Filesystem 所有者替换；以及 WHPX 正常路径与所有者死亡/服务重启资格验证 |

shim 恢复现在会先核对 Runtime 中确切的 `Stopped` 记录，再
重放待处理的 init 信号。如果本地元数据没有退出信息，一次有界、
绑定确切代次的 Wait 会导入 Runtime 的持久化退出记录；随后信号日志
继续推进，无需第二次 Kill。2026 年 8 月 24 日连续三轮 Ubuntu
arm64/containerd 2.2.2 矩阵在 Host PID 保持不变的情况下，留存了这一终态
init-Kill 边界的证据，包括退出码为 42 的 shim 和
containerd Wait/Delete 证据，以及独立的零存活残留审计。

exec 恢复采用同样的权威退出记录规则，且不延迟
存活进程：重放待处理的进程信号前，先执行一次精确的
零超时 `WaitProcess`。持久化退出记录会将 exec 移至 `Exited`，记录
首次观测时间，并结算待处理序列，而不再次调用
`SignalProcess`；`DeadlineExceeded` 则证明 exec 仍存活，并保留
正常的身份稳定重放路径。

`DeleteProcess` 现在先写入精确的响应回执，再以原子方式
从 shim 主元数据中移除已停止的 exec。如果崩溃后 exec 仍在主
记录中，回执仅表示尚未提交的意图，状态重建时
将其丢弃。如果 exec 已不存在，替代 shim 会重放回执中的
PID、退出状态和纳秒级退出时间。同一 exec ID 的新持久化
实例会清除旧回执，而完整的 task Delete 或 DeleteShim 会移除
该日志。

Task Delete 现在先保存 `a3s-oci-shim-task-delete-v1.json`，再分派
受代次隔离保护的 Runtime delete。回执绑定命名空间、task
实例、容器身份、代次、bundle、PID、退出状态和
纳秒级退出时间。若主元数据仍在且 Runtime 代次仍存活，
则标记为未提交意图并消耗该回执；task 移除后，
不携带元数据的替代实例会校验服务命名空间、task ID 和
bundle，并返回与首次完全一致的响应。这个仅用于重放的 shim 在
发送响应后会发出退出信号，因此 containerd 2.2.3 的泄漏清理不会
留下无人持有、永久等待的替代进程。

恢复还会先将已校验的 task 发布到内存状态中，再
启动任何输出泵。这样，能够立即重放的输出块便可
针对已恢复的 task 提交持久化游标，避免与
尚不存在的状态条目产生竞态。确定性的 FIFO 回归测试覆盖这一顺序；
如果输出泵部分启动失败，则先停止所有已创建的输出泵，
再回滚已发布的 task。

提交后 `WriteStdin` 强制清理现在具备独立的精确边界。该
关卡暂停 Host，直到 schema-v10 元数据保留 exec 实例 1、
待处理序列 1 和精确的 stdin 字节，然后暂停 shim，并直接
通过公共 SDK 提交同一个 `write-stdin-1` 身份。exec
必须仅因一次输入效果以 23 退出，同时 init 在原 PID
和代次上保持 Running。shim 收到 `SIGKILL` 后，DeleteShim 不得重新分派
待处理字节；它会移除确切的 Runtime 代次、工作负载进程、
bundle、cgroup 和 shim 状态，同时保留调用方持有的容器
元数据。

提交后 `CloseStdin` 强制清理现在也具备对应的精确边界。
Host 暂停时，`CloseIO` 经由 task shim 声明的
 ttrpc 端点到达 shim，schema-v10 元数据保留 exec 实例 1、stdin 状态
Closing，且没有待处理写入。随后暂停 shim、恢复 Host，
并直接通过公共 SDK 提交绑定同一实例的
`close-stdin-1` 身份。EOF 使 exec 以 29 退出，而 init 仍在
原 PID 和代次上保持 Running。shim 收到 `SIGKILL` 后，DeleteShim 不得
分派第二次关闭；它会移除确切的 Runtime 代次、工作负载进程、
bundle、cgroup 和 shim 状态，同时保留调用方持有的容器
元数据。聚焦此边界的单元测试从一次已记录的 Runtime close 开始，
证明清理不会增加该计数，并将 Kill 和强制 Delete
限定到确切代次。

提交后 `ResizePty` 强制清理现在也具备对应的自动化
边界。默认忽略的真实 containerd 关卡创建终端 exec、暂停
Host、经 shim 已校验的 ttrpc 端点发送 `ResizePty`，并
要求 schema-v10 元数据保留 exec 实例 1，待处理序列
为 1，尺寸为 166x52。然后暂停 shim、恢复 Host，并直接
通过公共 SDK 提交绑定同一实例的 `resize-1`
身份。该关卡通过 `/proc/<pid>/fd/0` 和
`TIOCGWINSZ` 读取实时 PTY 尺寸，随后终止 shim，并要求原始响应
确实丢失。DeleteShim 不得再次分派尺寸调整；它仅移除确切的
Runtime 代次、工作负载进程、bundle、cgroup 和 shim 状态，同时
保留调用方持有的容器元数据。聚焦此边界的单元测试从
一次已记录的 Runtime resize 开始，证明清理不会改变该
计数，并将 Kill 和强制 Delete 限定到确切代次。

包含此关卡的所有非破坏性 CI 目标均通过，包括 Linux、musl、
macOS、Windows 和 Native Linux arm64。源码修订
`2fef85c6e68a07f114d211175b77841301d57985` 还在 Ubuntu 24.04.3 LTS/WSL2
x86_64 上通过了三轮完整 containerd 2.2.1 矩阵，耗时分别为 91.96、91.89
和 91.92 秒，Host PID 始终为 1566。每轮都经过全部 23 个
守护进程重启及提交后状态重建边界，包括当前的
`ResizePty` 强制清理关卡。静态 musl CLI、agent、shim、资格验证
可执行文件及 Cargo.lock 的 SHA-256 值依次为
`e22a08d884ad59187fce39e170f6ca21d367a77c2d3a1a297cb8650adf6f7561`、
`c73cc2356552de6f2def62598a44fb370df7300a56af5c7be33e63d148b865e2`、
`c4c8ce162cdb0c031eac6e792e2bbdf9c99c30e7ef971ca8791b123f2b4ce00c`、
`ba458b70cb1c879ed78095d326ccfe8992b22f12198728b45cc8d50a52e0451f`
和 `1f00f4ec1b0f1ba9f3e39daf2b8782e42c922d9fa696aaa07c709c38123edca0`。
默认 containerd 始终以 PID 184 运行。最终审计确认，在移除两个
隔离根目录前，task、容器、存活 Runtime 容器、匹配进程、挂载和
cgroup 的数量均为零。这份 WSL2 源码构建记录
仅作观测，不提升确切的 containerd 2.2.2 Ubuntu
arm64 开发支持声明；确切发行包的版本范围资格验证和
其余 R7 发布关卡仍待完成。

源码修订 `9726719e5a66156cd61f8be36ca00998bbcfc871` 在
Ubuntu 24.04 x86_64/containerd 2.2.3 上连续通过三轮完整
矩阵，耗时分别为 117.37、119.36 和 118.94 秒，Host PID 始终为 2678296。
发布版 CLI、agent、shim、资格验证可执行文件及 Cargo.lock 的 SHA-256
值依次为
`80d0b69686c73516fc3a507f2545af77b405918584176bdb0a96ab3bcf067102`、
`68219e592a061b9dba7f491d54716354195cd8f8005fa792ab367681dda5352e`、
`99bacac7a308e4830ca55101ef8148a511526722cf9006d8a37ef9cba89dbf50`、
`3e752abc8ada3b8e3dae9d86e370feb7d17bf04c2245f13888d52ba7537b2fd2`
和 `c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`。
套件使用专用的私有 containerd 根目录、状态、socket 和 systemd
单元；生产 containerd 全程以 PID 2485480 运行。
探测后及每轮测试后的独立审计均确认，匹配的 task、
容器、bundle、存活 Runtime 记录、cgroup、快照、shim 进程、
资格验证进程和工作负载进程数量均为零。

源码修订 `a3865075d8ced661447a85196e17136379535fa7` 在
Ubuntu 24.04 x86_64/containerd 2.2.3 上连续通过三轮完整
矩阵，耗时分别为 89.96、93.40 和 94.55 秒，Host PID 始终为 2504484。
发布版 CLI、agent、shim、资格验证可执行文件及 Cargo.lock 的 SHA-256
值依次为
`80d0b69686c73516fc3a507f2545af77b405918584176bdb0a96ab3bcf067102`、
`68219e592a061b9dba7f491d54716354195cd8f8005fa792ab367681dda5352e`、
`ca14a7d28f3b95656b831006c22e2e88561c272a19c48aab19b43d6592ca652c`、
`c560b1d92d4e786a026fd2c8002bcb0330c06d620304a08c5df4951ebdaf9ce4`
和 `c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`。
套件使用专用的私有 containerd 根目录、状态、socket 和 systemd
单元；生产 containerd 全程以 PID 2485480 运行。
每轮测试后的独立审计均确认，匹配的 task、容器、
bundle、存活 Runtime 记录、cgroup、挂载、shim 进程、agent 或 Host
子进程、资格验证进程、僵尸进程和已准备操作的数量均为零。

源码修订 `5a6d5f2d817d5951929c2394dff57ef925dd5822` 连续通过三轮
完整 Ubuntu arm64/containerd 2.2.2 矩阵，耗时分别为 65.15、
66.76 和 64.11 秒，Host PID 始终为 436920。发布版
Host、agent、shim、资格验证可执行文件及 Cargo.lock 的 SHA-256 值依次为
`53bf14d72adb347b35d19f936bf91d15adcc3cce65aa88f63886746f07f5ddb2`、
`28dad74972b28b400a9e5e9f9b38ba59aeaf6662532dfefc7dd5527ff17d6b48`、
`801c6ebd6bb6a41f1049dbd64d6ae60165a0914254edb953b2eaf633c6c368f2`、
`fa3a513bf2f5aba01a511bc953dcfc5cb1bb05080fbd58bb993d9a0a44a10363`
和 `c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`。
每轮均留存了确切的序列 1 SIGTERM、exec 正常退出码 29、
替代 shim 与重启后 containerd 的 Wait 证据、首次及
重放 `DeleteProcess` 的 PID、状态和退出时间戳，以及原始
运行中 init 的 PID。每轮后的独立审计均确认，匹配的
 task、容器、bundle、cgroup、挂载、存活 Runtime 记录、shim、
agent、资格验证进程及 Host 子进程数量均为零，僵尸进程和已准备
操作也均为零。原先安装的 shim 已恢复，其 SHA-256 为
`a0e7dce493308ebea0b4642dd81a9e489109a8b3709f2a1ede62b015cc123482`；
测试 Runtime 根目录、发布构建目标、检出目录和日志已移除。

共享 Linux 执行器已实现 OCI 1.3 `linux.netDevices`。
运行时校验有界且确定性的迁移计划，要求使用独立的
网络命名空间，拒绝确切的目标名称冲突，支持末尾追加
`%d` 的模板，保留稳定的链路属性和永久全局
地址，并启用每个迁移后的接口。Create 失败时，按逆序
回滚此前的迁移；仅在 created 状态持久化提交后才释放
回滚租约。rootless 执行会在发生变更前拒绝请求，
因为当前辅助进程契约并未授予主机
网络设备权限。Native Linux 关卡使用真实 dummy 接口，
验证迁移、重命名、地址/MTU/MAC 保留、目标冲突、部分
回滚、rootless 拒绝及清理。

rootful 公共 `a3s.oci.attachments.v3` 配置在此 OCI 机制之上增加了
由调用方签发的不可变命名空间、接口和清理身份。它
要求使用确切的目标接口名而非 `%d`，将这三个
身份全部绑定到持久化重放证据，并区分运行时创建的
命名空间的释放与所加入的调用方命名空间的保留。它从不
接收或决定 IPAM、DNS、路由、别名或网络策略。

必需扩展 `dev.a3s.network.enforcement@1` 为一个确切的、
已加入的调用方命名空间添加不透明的调用方强制执行身份，
并可选添加节点本地重定向身份，均绑定代次和 SHA-256。其封闭
schema 无法承载主机名/IP 规则、路由、端点、凭据、租户
元数据或策略决策。Host 独立协商该扩展，将其
原样传递给驱动，并在重启后重新校验确切的 `ContainerRecord` 证据。
rootful Native Linux 现在仅在具有网络设备
权限时声明版本 1；其真实主机关卡留存命名空间/接口身份、
重定向/拒绝行为、Host 重新打开重放，以及调用方持有机制
保持不变的证据。rootless Native Linux 和虚拟机驱动不声明此扩展。

暂停和恢复仍是分别协商的运行时操作，具备稳定的
`OperationContext` 身份、确切代次隔离、持久化重放和
重启核对。其已提交的 `ContainerPaused` 和
`ContainerResumed` 观测现在通过类型化
`RuntimeEvent::operation_id` 暴露确切变更；Host 同时对照持久化
事件声明和旧版 `operation-id` 属性进行校验。不含
类型化投影的旧 event-v1 记录仍可通过这一已校验属性读取。
Native Linux 浸泡测试 schema v2 现在保留每个 Pause 和 Resume 操作 ID，
在各自独立的 Host Service 重新打开后重放已提交响应，并
记录原子工作负载计数器，证明暂停期间没有进展，而 Resume
及其后的第二次重新打开后进展恢复。带标签包资格验证 v4
将这份 OAR-02 证据绑定到确切的暂存 runtime 和 Agent 制品。
Runtime 不决定工作负载何时空闲或何时唤醒；该策略由
调用方掌握，并由调用方发出显式操作。

公共 `a3s.oci.attachments.v4` 配置确立了可复用的
客户机会话边界。SharedGuestKernel create 或 restore 必须绑定一个
逻辑会话 ID、正数实例编号、不可变信任域、
1 到 64 的容量、运行时所有权，以及显式的空时销毁或
同信任域保留模式。Protocol 7 和持久化 `ContainerRecord`
证据对降级、重启和操作 ID 复用实施隔离。共享 HVF/KVM
驱动核心实现了会话范围的共享目录与所有权标记、串行化
准入、容量和代次隔离、两种重置模式、成员局部
故障清理、无竞态的并行会话回收、会话恢复
报告，以及单一所有者关闭。生产环境的
HVF、KVM 和 WHPX 注册仍只声明已通过资格验证的
附件配置，直到留存相应的真实主机重启、清理与
浸泡测试证据，并实现这些配置逐层累积的存储/网络传输。

跨所有者替换时，会话准入同样遵循失败即拒绝原则：若没有
进程内所有者或正在进行的交接准入，持久化的
`.guest-sessions/<id>/` 根目录不能被视为空池，因此当之前的虚拟机
可能仍然存在时，第二台虚拟机不能悄然复用同一逻辑身份。

共享执行器也已实现 OCI 1.3 `linux.resources.hugepageLimits`。
SDK 保留规范规定的完整 `uint64` 范围，而
执行器根据实时 cgroup-v2 清单校验每个规范页大小
名称，仅在请求时启用 `hugetlb`；当内核提供预留记账时，
同时应用用量和预留限制。Create 和
实时 Update 使用内核可表示的值，支持回读和逆序回滚；
部分更新保持省略的页大小不变。在 `control-workload-v1` 中，
HugeTLB 仍是仅作用于工作负载的精确限制，不会复制到
管理资源包络。当运行器暴露 `hugetlb` 时，Native Linux CI 会在
x86_64 和 aarch64 上回读所选主机页大小的控制项。

OCI 1.3 `linux.resources.rdma` 作为独立的按键索引 cgroup-v2
控制器实现。每个设备可限制 HCA 句柄、HCA 对象或两者；
设备策略变更前会检查设备名和可用的内核条目。
Create 和实时 Update 保留省略字段，将内核的有符号
计数器上限归一化为 `max`，回读每个生效值，并按逆序
回滚已应用的设备。仅在请求时才要求 RDMA，并且在
`control-workload-v1` 中仅作用于工作负载。当运行器同时暴露控制器和
可用的 InfiniBand 设备时，Native Linux 资格验证会回读
control 与 workload 条目。

OCI 1.3 `linux.resources.unified` 接受有界的 cgroup-v2 控制文件映射。
执行器为每个键校验一个安全文件名，拒绝运行时持有的
`cgroup.*` 状态及已由类型化 OCI 资源管理的文件，保留
稳定的写入顺序，并借助实时内核清单处理运行时未知的
控制器名称。在创建叶节点前启用所需控制器；
控制器缺失或无法启用、控制文件缺失或不可写时，
都会在设备策略变更前返回类型化错误。Create 和 Update
按稳定顺序写入每个值，不强加通用的回读格式。
Update 使用可读控制项抑制空操作并实现逆序回滚，
同时仍允许只写控制项。`control-workload-v1` 仅将它们应用于
workload 叶节点；Native Linux 资格验证从两个子节点回读
`memory.high`，在条件允许时验证由内核规范化的部分 `io.max` 写入，
并测试 rootful 和委派权限的 rootless 实时更新。

当前 `A3S-Lab/Box@a16772c3` 的 Box 适配器会对照
确切的运行时绑定重新检查每次读取。文件上传/下载和文件系统
stat/mkdir/move/list/remove 现在使用同一个跨平台会话门面；
分派前检查能力与 Box 代次，重新校验响应目标
与结构，并对一次明确可重试的变更响应使用
相同上下文重放，确保运行时仅产生一次效果。部分产品
资源请求会编译为一份完整的 OCI `LinuxResources` 契约，
在分派前持久化登记，并在响应丢失后以同一个运行时操作
重放。Runtime 确认会以原子方式更新 Box 重启意图，
不改变最初的 create 身份。

新的变更记录使用 `a3s.oci.operation.v6`。版本 3 的 File 上传和
Filesystem mkdir/move/remove 仍可读取；版本 4 还保留
每个精确的 checkpoint 请求和类型化不可变响应；版本 5 添加
精确的 restore 请求、分配的代次和暂停运行响应；
版本 6 则保留每个精确的 TEE 证明挑战与不可变证据
响应。版本 1 至 5 对各自编码的操作仍保持可读。
Host 在确认驱动重放证据之前，先提交已记录到日志的
结果，因此断连会返回可重试错误，下一任所有者会重放
Host 结果，而不再次分派变更。在驱动证据
释放后，Host 日志仍是防止修改请求后重用身份的永久屏障。

持久化状态现在将其规范根目录固定为一个目录能力句柄。所有
后代项的读取、枚举、创建、替换和隔离移动均通过
保留的目录句柄解析。macOS、Linux 和 Windows 关卡证明，
环境根路径重命名、布局或事务中的符号链接/重解析点
替换、外来文件系统句柄、同设备 Linux 绑定挂载
替换，或竞态中的 Windows 文件/目录目标替换，都无法
重定向变更。Windows 相对于保留的目标父目录句柄提交
每个已打开的源对象，并通过同一个
打开的对象应用文件 DACL。文件替换仅容忍有界、短暂的 Windows
目标共享锁。打开存储时，会在驱动恢复或开始处理请求之前，
递归审计已提交的代次、操作、存活容器、进程、隔离项和事件
之间的关系，同时保留幂等崩溃重放所需的
显式中间状态。

确切的 containerd API、身份、安装、重启、清理和
资格验证边界详见
[containerd Runtime V2](docs/containerd-runtime-v2.md)。

契约 v1 固定运行时类型 `io.containerd.a3s-oci.v2`、task 服务
`containerd.task.v2.Task` 和 Linux 归档条目
`containerd-shim-a3s-oci-v2`。将该条目安装到
`/usr/local/bin/containerd-shim-a3s-oci-v2`。命名空间和 task ID 使用
`sha256-length-framed-u64be-v1` 编码生成稳定的 SDK 容器 ID；
Host 分配 Create 返回的单调递增运行时代次，
shim 将其持久化，并在之后每个请求中寻址该确切代次。
同一张代码定义的表将每个 Task 分支和 FIFO 泵映射到相应公共
SDK 操作。RuntimeInfo 将确切的 18 操作并集发布为
`dev.a3s.oci.containerd-sdk-operations`；缺少任何成员的端点都会被 shim
拒绝，且测试会检查其 crate 清单，确保 A3S Box 和驱动
实现位于这一适配器边界之外。
有界进程 I/O 路径在每个 shim 步骤最多读写 64 KiB，
非终端模式下将 stdout 和 stderr 分开，终端模式下则将输出
合并到 PTY 流。内核接受的每个 FIFO 前缀都会在下一次写入前
推进持久化字节游标，因此取消操作不会提交尚未写入的
后缀，替代实例恢复时也不会丢失数据。

Create 恢复覆盖远程提交边界的两侧。shim 会在分派前
持久化完整的 bundle、隔离、I/O、rootfs 所有权、task
实例和稳定操作身份。真实故障关卡
可在分派前暂停 Host，在意图持久化后暂停 shim，
通过公共 SDK 直接提交确切的 Create，再在完整元数据存在前终止
shim。DeleteShim 必须接入该唯一代次，
移除其确切进程、运行时状态、rootfs 和 bundle，同时保留
调用方持有的 containerd 元数据；重复代次或驱动重路由
都会留下确切证据并导致关卡失败。

上述确切的 Box 修订还会校验其托管主目录，持久化准备
快照 lower 层、命名卷和网络，编译由产品持有的 OCI
bundle，并启动或复用本运行时中受身份隔离保护的长生命周期 Native
Linux 所有者。其 x86_64 和 aarch64 Linux 阻断式验证任务通过显式
生产路由驱动 Rust、Python、TypeScript 和 Go 的 Sandbox
生命周期、exec、文件系统、按路由统计、
暂停/恢复、快照恢复、重启和清理。

Box 完成度与 Runtime 就绪程度衡量的是不同范围。Box 可以
基于 Runtime 已验证的部分能力完成当前产品契约；本仓库
仍负责全部 20 个公共工作负载操作、每个声明的驱动、所有者替换
语义、OCI 一致性和发布资格验证。因此，使用方已完成
并不能证明底层运行时已完成。

Linux 文件和文件系统调用在每次新建的内部辅助进程中执行，该进程仅继承
确切保留的根目录、用户命名空间和挂载命名空间描述符。
辅助进程认证其父进程，拒绝重复或顺序改变的描述符，
先进入用户命名空间，再进入挂载命名空间，然后执行
有界 `openat2` 操作。因此，容器内 ID 在
rootfs、绑定挂载、ID 映射挂载及容器创建的 tmpfs 文件系统上均保持正确。

完整发布目标涵盖 Linux 容器的 OCI 运行时规范
1.3.0 中每条适用要求，以及每个声明的驱动，而非
精简的 A3S 专用配置。[ROADMAP.md](ROADMAP.md) 将已完成证据与
待完成发布关卡分开记录。

对于运行时能够授予的每个值，capability 集合强制执行始终精确，
并遵循失败即拒绝原则。当当前内核或执行器继承的
权限无法授予已识别的请求 capability 时，init 和 exec 仅移除
那个无法授予的集合成员，并在跨越 exec 边界前向
监管代理发送有界的结构化警告。格式错误或重复的警告
帧会导致拒绝，而不会成为不可信日志文本。

Linux sysctl 现在遵循相同的失败即拒绝边界。SDK 仅接受
已知的 IPC、网络、UTS 域和用户命名空间控制项，支持 OCI 点号或斜杠
表示法。执行器拒绝主机全局控制项及加入同主机相同命名空间的请求，
通过保留的 procfs 应用有界确定性事务，
验证每个值，并在 Create 未提交时恢复先前的值。

Intel RDT 由运行时命名空间父进程持有，而非容器
init 进程。存在 `linux.intelRdt` 时，父进程查找已挂载的
resctrl 文件系统，准备或验证请求的 CLOS，按 OCI 顺序应用
`l3CacheSchema`、`memBwSchema` 和完整的 `schemata`，回读
生效值，并在运行时 hook 执行前分配经认证的 init PID。
专用监控组和运行时创建的 CLOS 目录会在
Delete、关闭、Create 失败或原生所有者死亡恢复时移除。
显式指定的 CLOS 目录和根 CLOS 目录仍由外部持有。

## 运行时契约

### 创建与启动保持分离

```text
creating ── create committed ──▶ created
created  ── start committed  ──▶ running
running  ── init terminated  ──▶ stopped
```

`create` 校验并准备请求的边界，不执行
`process.args`。只有 `start` 才会放行已配置的进程。无效的
状态转换会失败，不会削弱这一屏障。

每条持久化容器记录保留：

- 精确校验后的配置及其摘要；
- 新建记录的完整 `a3s.oci.attachments.v1`、支持存储的 v2、支持网络的 v3 或
  支持客户机会话的 v4 清单及其摘要；
- 使用 shared-guest-kernel 隔离时，确切的可复用客户机会话
  实例；
- 单调递增的运行时代次；
- 运行时选定的驱动及有效隔离方式；
- 活跃的操作意图与终态重放结果；
- 观测到的确切 init 与 exec 进程退出状态；
- 中断变更的恢复或隔离状态。

匹配的 retry 会复现原始结果。过时代次、以不同 payload 复用的
操作 ID、不支持的 OCI 字段、不可用的隔离类，或已记录驱动发生变更，
都会在变更前失败。

### 隔离是要求，而非驱动名称

| 请求 | 边界 | 内核共享 |
| --- | --- | --- |
| `DedicatedVm` | 硬件辅助虚拟机 | 一个工作负载或 pod 独占客户机内核 |
| `SharedGuestKernel` | 硬件辅助虚拟机 | 一个已声明的信任域共享客户机内核 |
| `SharedHostKernel` | Native Linux | 容器共享主机内核 |

`SharedGuestKernel` 请求必须携带 `a3s.oci.attachments.v4` 绑定，
对应一个确切的客户机会话实例。这是持久化身份与权限
证据，并非声称当前注册的辅助虚拟机驱动已提供
池化；能力协商仍会拒绝 v4，直到该驱动声明相应 schema。

调用方请求隔离类。运行时为此类选择一个可启动的所有者，
持久化所选驱动，并将后续每次操作路由回该确切所有者——
即使服务重新打开后驱动注册顺序不同。它从不改写历史状态，
也从不从虚拟机边界回退到主机内核。

### SDK 即执行边界

```rust,no_run
use a3s_oci_runtime::HostRuntimeService;
use a3s_oci_sdk::RuntimeClient;

#[tokio::main(flavor = "current_thread")]
async fn main() -> a3s_oci_sdk::Result<()> {
    let client = RuntimeClient::new(HostRuntimeService::new());
    let info = client.features().await?;

    println!(
        "host={:?} arch={}",
        info.drivers.platform,
        info.drivers.architecture
    );
    for capability in &info.drivers.drivers {
        println!(
            "{:?}: host={:?}, readiness={:?}, launch={}",
            capability.driver,
            capability.status,
            capability.readiness,
            capability.can_launch()
        );
    }
    println!("operations={:?}", info.operations);
    Ok(())
}
```

`RuntimeClient` 可包装进程内服务，也可通过有界本地 IPC 连接。
本地流断开时会如实上报，不会隐藏重放；下一次显式请求会
重新连接并重新协商，以便调用方 retry 或与原始操作身份对账。
前台 `run` 只是 durable create/start/wait/delete 调用的客户端组合；
它不会创建第二套生命周期 API 或状态机。

在 Linux 上，显式 experimental 主机所有者会发布一个 durable SDK
端点，且不会打开 KVM：

```bash
a3s-oci native-linux-host-service \
  --root /run/a3s/oci-native \
  --agent /usr/libexec/a3s-oci-agent
```

所有者在发布 `runtime.sock` 前打开 Native Linux 驱动与持久化状态，
向经身份认证的同 UID 客户端提供独立隔离的容器代次服务，
并在优雅关闭时回收驱动持有的进程。Box 显式
`A3S_BOX_OCI_MIGRATION=sandbox` 生产路由使用此所有者。现有
`native-linux-service` 命令仍是 Sandbox 范围内 FD 3/4/5 的所有者，
用于兼容性与聚焦资格验证。

在 Apple Silicon 上，公共 HVF 所有者在暴露相同 SDK 契约的同时，
将持久化状态与每代虚拟机状态分离：

```bash
a3s-oci macos-hvf-host-service \
  --root "$HOME/Library/Application Support/A3S/oci-hvf" \
  --shim /absolute/path/to/a3s-oci-krun-shim \
  --system-image-manifest /absolute/path/to/system-image.json
```

它准备仅所有者的 `0700` 根目录，发布同 UID 的 `0600`
`runtime.sock`，接受并发客户端，并仅删除其创建的 socket inode。
该服务声明全部 20 个 HVF 驱动操作以及 `features`、`list` 和
`events`，要求 runtime bundle-handoff 扩展，并在优雅关闭时回收
每个存活的专用虚拟机。HVF 驱动仅声明 `DedicatedVm`；共享客户机
池化尚未实现。

运行时契约套件还会在相同 Unix socket 或 Windows 命名管道上，
跨两个不同的 OS 进程重启所有者。替代进程打开相同的 durable
`HostRuntimeService` 状态，而一个保留的客户端恢复确切代次与
存活 exec 目标，重放 create/start/exec 且不重复 test-driver 分派，
并继续 inventory、stdin、signal、wait、output 与 cleanup。这证明
的是通用进程与传输边界，而非真实硬件上的 Native Linux 或
辅助虚拟机重新附着。

真实 Native Linux 关卡现已跨越进程边界，使用实际驱动。
launcher 在 fork 命名空间子进程前绑定 parent-death；所有者
`SIGKILL` 后，替代进程重新校验不可变配置以及 owner/launcher/init
启动时间身份，等待确切工作负载消失，并暴露 stopped cleanup
tombstone。它从不声称 live stream 已重新附着，也不会在没有
经身份认证的 parent 存活并回收时伪造退出码。幂等 kill、空
inventory、显式缺失退出证据、仅 stopped delete，以及
executor/cgroup cleanup 在 x86_64 与 aarch64 上均经机器校验。
Box B2 切换所需的 live process-session 重新附着仍待完成。

## 平台状态

| 主机路径 | 留存的真实证据 | 当前就绪状态与开放关卡 |
| --- | --- | --- |
| Native Linux x86_64/aarch64 | Rootful 与 helper 支撑的 rootless 生命周期，包括全部六个 OCI 默认设备、`/dev/ptmx`、配置 init 的 `/dev/console`、`/dev` 外的显式 FIFO、不可变 declared/default 设备边界，以及有界 A3S Box 设备策略；SDK 服务传输；exec/PTY/I/O；init/exec 调度器与 namespaced-sysctl 回读；cgroup update/stats；hooks；命名空间与 mount profile；多容器隔离；fault cleanup；owner-`SIGKILL` 安全终止与 stopped cleanup；精确 `startContainer` Hook owner-death 进程组 cleanup 与 replacement recovery；25 波 × 4 容器；x86_64/aarch64 经全部四个 SDK 的已安装 Box 生产所有者组合，`/dev/kvm` 缺失且不可访问，加上 fresh-Box-process owner-death/restart 关卡 | 默认 inventory 为 `probe-only`；显式打开的 development driver 为 `experimental`。Live session 重新附着、默认切换、生产安全与 OCI conformance 仍待完成 |
| Linux KVM 辅助虚拟机 | 独立的 device/access/ioctl/API-version 探测；确定性的 x86_64 与 AArch64 runtime archive 与不可变 ext4 root；精确的 libkrun、firmware、exported kernel 与 static Guest Agent 兼容性集合；descriptor-pinned 只读 root attachment；隔离的 create/configure/root/plain-vsock/release context 关卡；带 descriptor-pinned KVM 与 runtime-share 检查、parent-to-worker device/inode 身份绑定、pidfd owner death、kernel-authenticated Unix peer identity、protocol-v10 协商，以及 KVM 不可用时的 fail-closed cleanup 证据的隔离 real-entry worker。两条架构通道均保留 14-case pre-entry compatibility-drift matrix，并调用 KVM-gated 17-case lifecycle matrix。其 versioned 十 case Guest path-isolation entry 检查 traversal、symbolic-link 与 magic-link 逃逸；聚焦回归还会在 descriptor 校验后交换 bundle、rootfs 与 bind-source entry。通道还调用 scoped owner-death/restart 关卡、scoped 25-wave fresh-generation soak，以及九阶段 Create、State、Start、Kill、Delete、Wait、Exec、SignalProcess、WaitProcess、Pause、Resume、Processes、Update、Stats、ReadOutput、WriteStdin、CloseStdin、Resize、File 与 Filesystem owner-replacement 关卡。Guest 在 virtiofs runtime share 上的 durable ownership 遵循 share-root Host UID，而非 Guest `geteuid()`，因此 non-root Host Service 可保留 recovery record 与 device-target manifest。KVM-independent driver preflight 在创建 Guest-visible generation share 前，会拒绝 shared-kernel class、不精确代次、缺失 handoff ownership，以及缺失、linked、non-private、drifted、escaping-rootfs 或 absolute-bind handoff。soak 审计 generation fencing 与 replay，以及每波的 process、marker、endpoint、descriptor、bundle-handoff、runtime-share、recovery-report 与 configured Guest `cgroupsPath` 生命周期。公共候选驱动每确切代次拥有一台 VM，拒绝 host-kernel fallback，将 bootstrap 与 writable share 分离，且仍不可注册 | `probe-only`；2026 年 9 月 11 日 tip `ff97257` existing-host WSL2 x86_64 release-matrix 观测（skip soak）已绿 agent-entry 至 create-reopen，且 `promotes_readiness=false`。2026 年 9 月 8 日裸机 x86_64 观测（`e71a995`/`a35703c`）在短 `RUNNER_TEMP` 下留存 lifecycle、recovery、180/180 operation-stage reopen path 与 25/25 soak。更早的 clean revision 保留 File/Filesystem 各 9/9（`fa4c593`）及先前 lifecycle/soak 行。promotion 仍需 fresh-host x86_64 + AArch64 attestation-bound matrix；Host shutdown 与独立 real-entry negative-isolation profile 仍开放 |
| macOS arm64/HVF | 公共同 UID SDK host service；每确切代次一台 dedicated VM；manifest-bound 不可变 ext4 system image，含 pinned A3S Linux kernel 与 agent；只读 root disk 加独立同 UID mode-0700 writable runtime share，经 retained no-follow directory handle 与 parent-to-worker device/inode 身份绑定固定；Guest-local devtmpfs 上的 privileged OCI device node；真实 protocol-v10 bridge，含全部 21 个 Guest 操作；留存完整 protocol-v9 lifecycle、multi-container、namespace/rootfs enforcement、3 个 no-delete cleanup point、11 个 transport fault point、180/180 workload-operation replacement path、negative asset/authentication 关卡，以及 25 fresh-VM wave；源码 revision `a5a6b53` 通过 revision-bound public-path 关卡，覆盖全部 20 个 driver 操作以及 `features`/`list`/`events`、Host Service `SIGKILL` recovery，以及独立 25/25 fresh-VM soak，零 transient leak | Apple Silicon 上为 `experimental`。当前声明的每个公共 macOS/HVF 功能均已实现，protocol-v10 public path 在记录 revision 上已通过资格验证。Versioned 十 case Guest path-isolation profile 已实现且 CI 已接入；updated revision 上的首个 `available` artifact 仍待完成。Signed release-package qualification、OCI conformance、security review、upgrade/rollback compatibility 与更长 release soak 在 `supported` 之前仍待完成 |
| Windows x86_64/WHPX | 真实 partition/context/guest 关卡、protocol-v9 lifecycle 与 filesystem session、direct driver qualification、protected per-generation share、exact exit replay、两个 recovery fault boundary 处的 owner death、host-service reopen、stopped-only delete 与完整 transient cleanup。当前实现还构建可复现的 x86_64 ext4 system image，pin Linux 6.12.91 与全部 native boot asset，只读 attach root，并保持 runtime share 独立。existing-host 证据现已覆盖 20 个 workload operation 的全部 180/180 operation-stage replacement path，以及独立同进程 8-cycle handle-reclamation 关卡，exact 115 cold、122 baseline 与 122 final handle | `probe-only`；完整 SDK/recovery/negative/soak matrix 仍须在新配置的 WHPX 主机上以这些 exact asset 通过。v7 shim 与 Host 保留 v6 in-process handle-restoration 契约，但 fresh-host release 关卡仍开放 |

Windows WHPX guest handoff 现在携带显式 `windows-virtiofs-acl-v1`
metadata selector。Linux Guest 仅通过已打开 descriptor，将 virtio-fs
已知 synthetic `0755`/`0644` mode 规范化为私有 `0700`/`0600` handoff
契约；受保护的 Windows DACL 仍为权威，其他 mode 均 fail closed。此
兼容路径不改变 `probe-only` readiness 或仍待完成的 fresh-host release
关卡。提交 revision `9d1639a` 在 source-matched immutable image 上通过
完整 local WHPX profile（56/56 sample）、direct-driver 关卡与
owner-death/reopen 关卡；fresh-host release 关卡仍显式开放。

2026 年 9 月 6–7 日的 current-host operation qualification 将证据
扩展到每个 workload operation。Windows 10 Pro 23H2 (AMD64) 上七次
有界运行通过 180/180 operation-stage case（20 operation × 9 retained
fault stage），包括 clock-adjusted Stats replacement case；所有 report
均保留预期 owner/fault crossing、immutable asset hash 与完整
process/share cleanup。独立 `a3s.oci.windows-whpx-handle-reclamation-run.v1`
关卡还通过八次同进程 VM cycle，`115 -> 122 -> 122` cold/baseline/final
handle、零 final delta 与 restored runtime share。这些是 existing-host
观测，并不关闭 freshly provisioned release-host 关卡。

2026 年 9 月 7 日，merged implementation 还通过完整 current-host
`a3s.oci.windows-whpx-soak.v2` run：25/25 serial、3/3 multi-container、
3/3 lifecycle-fault、6/6 parallel、5/5 workload、10/10 typed-negative
与 4/4 owner-kill case，verification 与 final process cleanup 均通过。
这仍是 existing-host 证据；fresh-host promotion 关卡仍显式开放。

同一 merged current-host run 还通过独立 direct-driver 与
owner-death/service-recovery 关卡，包括 exact exit replay、两个
recovery fault boundary、service reopen、stopped-only delete 与完整
cleanup。这些观测不会将 WHPX 提升为 `probe-only` 以上。

Windows WHPX guest handoff 现在携带显式 `windows-virtiofs-acl-v1`
metadata selector。Linux Guest 仅通过已打开 descriptor，将 virtio-fs
已知 synthetic `0755`/`0644` mode 规范化为私有 `0700`/`0600` handoff
契约；受保护的 Windows DACL 仍为权威，其他 mode 均 fail closed。此
兼容路径不改变 `probe-only` readiness 或仍待完成的 fresh-host release
关卡。提交 revision `9d1639a` 在 source-matched immutable image 上通过
完整 local WHPX profile（56/56 sample）、direct-driver 关卡与
owner-death/reopen 关卡；fresh-host release 关卡仍显式开放。

对 Unix 辅助虚拟机 worker，parent-to-worker device/inode handoff 同时
绑定 exact generation-share directory 及其必需的 `run/` state child；
hidden worker command 会拒绝不完整的 identity pair。

所有留存的 Linux KVM entry、compatibility、lifecycle、recovery、
operation-reopen 与 soak artifact 均携带下文所述的 shared provenance
contract。这消除了 artifact identity 歧义；它不能以 unavailable-runner
output 替代成功的 real-KVM 证据。

Linux discovery 与 Native Linux development 在 `/dev/kvm` 缺失或不可用时
必须仍可用。KVM 是可选的辅助虚拟机驱动，从不是 host-kernel execution
的前置条件。Box main commit
`d6861de302e6e165a2fdc473b2d399bb0692048e` 在
[CI run 33497670646](https://github.com/A3S-Lab/Box/actions/runs/33497670646)
上，于 x86_64 与 aarch64 对 Runtime commit
`438e4b7936cd08d408160fe9341a21786f60cd26` 留存了该 installed-product
边界。

2026 年 8 月 15 日，聚焦的 Apple Silicon rerun 通过全部 14 个 journaled
`guest-after-response-write` mutation case，含 post-commit Guest
acknowledgement。File 与 Filesystem 还通过完整九阶段 reopen 与 real
owner-replacement matrix，共 18/18 path。运行使用 agent SHA-256
`eea01813858f5dd16bed70cbfba87221da6daebb4201b7a628665aad3f615a7d`
与 system-image SHA-256
`e888c52e35ba8ed8f747d55bdc32316190dc317865e6919014e434a1e644e6ef`。

最新 WHPX owner-death 关卡从 clean runtime commit `2d91cd0` 发出
`a3s.oci.whpx-recovery-smoke-run.v1`。这关闭了 service-restart 证据项。
immutable-image code 与 qualification artifact 现已存在，但尚未产生
promotion 公共候选所需的 fresh-host matrix。当前 shim 还在 libkrun context
创建前与 VM exit 后立即记录 Windows handle inventory；Host validation 与
hardware soak 会拒绝任何 drift。在 fresh-host matrix 于每个 session 留存
匹配计数之前，这仍是 implementation 证据。

2026 年 9 月 3 日的 current-main qualification 增加了 real-host observation，
但未改变这些 readiness classification。在 x86_64 WSL2 上，pinned Linux KVM
asset 通过 entry、14/14 compatibility drift case、17/17 lifecycle case、
owner-death/restart、25/25 soak wave 与 162/162 operation replacement path。
9 月 3 日 follow-up（clean Runtime revision `fa4c593`）增加 real File 与
Filesystem owner replacement，各 9/9 stage（额外 18/18 path），含
immutable asset provenance 与 zero residue。在 existing Windows 10 x86_64
host 上，pinned WHPX asset 通过 56/56 lifecycle、multi-container、fault、
workload、negative 与 owner-kill sample，51 个 VM handle inventory 全部
恢复。这些结果明确为 observation-only：fresh-host evidence（两条 advertised
architecture）、剩余 WHPX/KVM operation-stage 与 shutdown boundary，以及
signed release artifact 在 promotion 前仍必需。后续 merged Runtime commit
`bf43388dc1a5630f3fbbd699203877cf84f1ee2d` run 在 source-matched
immutable image 上重复 WHPX 56/56 soak、direct-driver 与 service-recovery
关卡；51 个 VM handle inventory 全部恢复，host process inventory 归零。
它仍是 existing host 上的 observation-only，因此不关闭 freshly provisioned
release-host 或 operation-stage 关卡。

同一日期还留存 release-profile Native Linux/containerd observation（source
`878f8414cef3b85bef1b51fe6735017b25828252`）：三轮连续 isolated
containerd 2.2.1 matrix（96.42/96.17/95.31 秒）通过全部 23 个 restart、
rehydration 与 forced-cleanup boundary，使用 static musl CLI/Agent/shim
artifact。default containerd 与 Host Service 保持原 PID，post-run audit
未发现 task、bundle、process、mount、cgroup 或 Runtime residue。记为
observation-only，因使用 WSL2 上的 source-built artifact；它不提升
advertised containerd 或 driver claim。

restart-boundary follow-up（source revision
`fa9393d473c2f2305ce8f7ec67054acea7ea54a0`）在 96.53、96.63 与 96.59
秒内重复相同 isolated containerd 2.2.1 WSL2 x86_64 qualification 三次。
qualification 现记录全部 23 个 restart、shim-rehydration 与
forced-cleanup boundary 的 code-enforced ordered ledger；每轮均完成 exact
inventory。Static-musl CLI、agent、shim 与 qualification artifact，以及
matching Cargo.lock digest 留存于 `compat/containerd-runtime-v2.json`。
default containerd 保持 PID 180，final audit 在移除 private root 与 unit
前，task、container、bundle、Runtime record、shim/workload process、mount
与 cgroup 均为零。这仍是 WSL2 上的 observation-only source-build 证据，
不关闭 cross-driver 或 signed release-package 关卡。

current packaged qualification 使用 source revision
`af8c5f97ac1f4eb506b32e8d57b3d1c0d5fb3645`，经 staged static-musl package
`a3s-oci-runtime-v0.2.0-linux-x86_64` 执行。三轮 isolated containerd 2.2.1
WSL2 x86_64 matrix 在 95.09/95.25/114.44 秒内完成全部 23 个 restart、
shim-rehydration 与 forced-cleanup boundary。package report 与 executable
digest（含 report SHA-256
`d87aa3ff3cd58843d57f51b75b91ca6d05c880f043d24477789105dfc065ba86`）留存于
`compat/containerd-runtime-v2.json`；run 仍为 observation-only，因非 signed
published archive，且不扩展 cross-driver support claim。

2026 年 9 月 6 日，clean current-main revision
`7e14370f02f4187ac0fc3ecb979ad14421bfab92` 还在 WSL2 上通过 pinned x86_64
Linux KVM entry、post-probe fail-closed、14-case compatibility-drift、
17-case lifecycle、owner-death/service-restart 与 25-wave soak 关卡。所有
report 均恢复 endpoint、process、descriptor、VM、runtime-share 与
state-root baseline。这是 observation-only 证据；AArch64、fresh-host
promotion、Host shutdown 与 signed release 关卡仍开放。

同一 current-main source 还通过 Linux KVM File 与 Filesystem
owner-replacement matrix，各 9/9 Host/Guest stage（18/18 path），含完整
cleanup 与 immutable asset provenance。这些是 x86_64 observation artifact；
fresh AArch64 operation-stage 证据与 promotion 关卡仍开放。

2026 年 9 月 8 日，clean current-main revision
`e71a995`（virtiofs durable-owner fix）与 follow-on merge `a35703c` 在
Zorin OS 18.1（`Linux 7.0.0-31-generic`）裸机 x86_64 上留存 observation，
使用真实 `/dev/kvm`。Non-root Host virtiofs share 在 Host Service UID 下
存储 durable file；Guest Agent 在 `/run/a3s-oci-runtime` 下的 ownership
检查现遵循 runtime-share root owner，而非 `geteuid()`。在 `RUNNER_TEMP=/tmp`
与 source-matched immutable system image 下，host 通过 Linux KVM lifecycle、
owner-death/recovery、全部二十个 operation-stage reopen matrix（180/180
path）与 25-wave soak。同一 revision `a35703c` 还通过 rootful Native Linux
CRIU checkpoint 关卡（`open_experimental_with_criu`、pinned CRIU 4.2.1），
含 `available` positive report（SHA-256
`05eccd22bca338f89d11fa8b2a971c58ce4e4ff34fc246c1b2203162f7cbe57b`）以及
private-PID 与 configured-network negative report。这仍是 observation-only
证据：AArch64、freshly provisioned multi-architecture promotion、Host
shutdown 与 signed release 关卡仍开放，Linux KVM 候选仍为 `probe-only`。

2026 年 9 月 11 日，tip `ff97257` 在 existing-host WSL2 x86_64 `/dev/kvm`
上留存 Linux KVM release-matrix 观测（`host_class=existing`，
`A3S_OCI_LINUX_KVM_SKIP_SOAK=1`）：agent-entry、compatibility-drift、
lifecycle、recovery 与 create-reopen 均为 `available`
（`promotes_readiness=false`；report SHA-256
`1bd77d6c9091168220ce4d35d0d5f19d1a381498f5b048c5588761c8efb09ccd`）。
同 tip 系列还绿了 existing-host KVM Live recovery 的
`new_exec_io_after_reattach_proven`，以及 SDK local-connect EACCES/EPERM →
`PermissionDenied` 诚实性（#329/#330）。tip 上 existing-host WHPX driver 与
recovery smoke 仍为 `probe-only` 观测。当前 `main` tip `30c118e` 仅在本
README 记录该观测，不改变 readiness。

### W4+ 之前仍开放 / 本机无法完成

权威清单见
[`ROADMAP.md` Fresh-host promotion checklist](ROADMAP.md#fresh-host-promotion-checklist)。
existing-host 绿从不设置 `promotes_readiness=true`。

| 项 | 本机（已使用 Windows + WSL）状态 |
| --- | --- |
| Fresh WHPX R2（`promotes_readiness=true`） | **阻塞** — 需要新装 WHPX Windows 主机 |
| Fresh KVM R2L x86_64 | **阻塞** — 需要新装 Linux KVM 主机（重装 WSL 不算 fresh） |
| Fresh KVM R2L AArch64 | **阻塞** — 需要 AArch64 KVM 主机 |
| WHPX/KVM `probe-only` → `experimental` | **阻塞** — 依赖上述 fresh 矩阵 |
| 与当前 `main` 对齐的 promote | **硬件阻塞** — 检出当前 `main`。最新已发布归档是 [`v0.3.6`](https://github.com/A3S-Lab/OCI-Runtime/releases/tag/v0.3.6)（`b34c81c`），只是 `v0.3.5`（`139850c`）之上的文档和版本字符串归档。不晋升 readiness |

| 项 | 诚实 fresh-host 之后 |
| --- | --- |
| W4 Box cutover（`microvm` / `sandbox` 走 SDK，无 silent fallback） | 开放；禁止过早合入 |
| 默认 supervised create | 开放；`A3S_OCI_NATIVE_SESSION_SUPERVISOR=1` 仍为 opt-in |
| `HostRuntimeService` 公开注册 KVM | 开放；fresh 矩阵通过前公开候选保持 `probe-only` |

| 项 | 策略 |
| --- | --- |
| B2 单报告 self-certify | 设计禁止（`b2_process_session_recovery_closed=false`） |
| 在本机签 `operator_attests_fresh_provisioning=true` | 禁止 |
| 把 existing-host 绿写成 promote | 禁止 |

本机仍可跑 `host_class=existing` 观测（含 soak）；该证据不解锁 W4+。


## 架构

```text
A3S Box（当前 Sandbox 使用方；显式 Native Linux 生产路由
         负责 bundle/资源准备并使用长期 SDK 所有者；
         default、MicroVM 与 cross-platform cutover 仍待完成）
a3s-oci CLI
containerd runtime-v2 shim
                         │
                         ▼
                  RuntimeClient
             in-process 或有界本地 IPC
                         │
                         ▼
              ┌──────────────────────┐
              │ HostRuntimeService   │
              │ validation           │
              │ generations + replay │
              │ recovery + quarantine│
              └──────────┬───────────┘
                         ▼
                 DriverRegistry
             隔离所有者只选择一次
                 ┌───────┴────────┐
                 │                │
       NativeLinuxDriver     utility-VM driver
          host kernel        KVM · HVF · WHPX
                 │                │
                 │        isolated libkrun shim
                 │                │
                 │        authenticated guest agent
                 └───────┬────────┘
                         ▼
                   LinuxExecutor
          namespaces · mounts · hooks · pidfds
          cgroups · process I/O · confined filesystem · exact cleanup
```

只有隔离的 `a3s-oci-krun-shim` 加载 checksum-pinned native libkrun
asset。SDK、CLI discovery path、durable host service 与 Native Linux
driver 不会初始化 hypervisor library。

在 Linux x86_64 与 AArch64 上，`a3s-oci-krun-shim context-smoke` 校验并
加载所选 native bundle，检查 firmware-exported kernel，并 create、configure、
release 一个 libkrun context。该命令不会打开 `/dev/kvm`、进入 VM，或
改变 KVM driver 的 `probe-only` readiness。更强的 pre-entry 关卡还会从
同一 target manifest 绑定 exact static agent 与 immutable root disk：

```bash
a3s-oci-krun-shim system-image-context-smoke \
  --system-image-manifest /absolute/path/to/system-image.json
```

它用只读 descriptor pin manifest 与 raw image，在 native API 使用前
立即 recheck 每个 byte，只读 attach root，然后 release context。它仍不
进入 KVM，也不声称 guest execution。

公共 Linux API 暴露 `KvmRuntimeDriver::open_candidate`，配置为
`KvmRuntimeDriverConfig`，含 isolated shim、writable runtime root 与
immutable system-image manifest。它单独准备 empty private bootstrap root
与 exact-generation runtime share，将全部 20 个 workload operation 与
六个 OCI hook phase 委托给 shared utility-VM core，并禁用 Native Linux
fallback。其 capability 刻意保持 `probe-only`，因此 `HostRuntimeService`
在下方 real-host promotion 关卡通过前，会拒绝 normal registration。

独立的 authenticated entry 关卡增加 UID-owned mode-`0700` generation
share、同 UID Unix endpoint、pidfd-bound shim owner 与 direct isolated VM
worker。worker 在打开 `/dev/kvm` 前 revalidate 每个 non-KVM entry asset，
pin device 并 require API version 12 后重复完整 compatibility 与 device
check。它仅通过 immutable system root 进入。Host 在 protocol-v10 token
negotiation 前，只接受 kernel-reported direct worker child：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-agent-entry.sh
```

独立的 compatibility matrix 在 configured worker boundary 处停止，不要求
KVM：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-compatibility-drift.sh
```

其 14 个 case 覆盖 manifest 与 raw-image replacement、同 size content
mutation 与 symlink；architecture 与 runtime-target mismatch；Guest Agent
version 与 digest drift；以及 runtime archive、libkrun、firmware 与 exported
kernel provenance drift。每个 case 必须 fail，且无 KVM-device access 或 VM
entry，并恢复 endpoint、shim-process、token-handoff 与 runtime-share
inventory。machine-readable result 使用
`a3s.oci.linux-kvm-compatibility-drift.v2`。

在无可用 KVM 的主机上，authenticated entry command 必须在 non-KVM setup
后 fail，保留 nested KVM evidence，并恢复 endpoint、process 与 handoff
inventory。当 KVM 可用时，关卡先要求 real authenticated boot，然后在
`/dev/kvm` 与 API version 12 校验后、libkrun 进入 VM 前，运行 hidden
qualification-only failure。Shim schema v7 记录该 exact boundary，script
拒绝任何 endpoint、process、token 或 runtime-share residue。此 implementation
不提升 driver：x86_64 与 AArch64 上成功的 real-entry evidence，加上完整
lifecycle、recovery 与 soak matrix 仍必需。

script 将 normal entry 留存于
`a3s.oci.linux-kvm-agent-entry.v1`，injected boundary 留存于
`a3s.oci.linux-kvm-post-probe-failure.v1`。两者用
`a3s.oci.linux-kvm-provenance.v1` 包装 raw v10/v7 Host 与 shim report。
common object 要求 clean checkout，绑定 Git object format、actual checkout
commit 与 tree、Linux platform 与 target architecture，并对 CLI、shim、
runtime-assets manifest、selected runtime file 与 system-image manifest 做
hash。它还记录 exact build profile、qualification profile、`libkrun-kvm`
driver 与 `dedicated-vm` isolation class。其他 KVM 关卡复用同一 contract，
因此来自不同 source 或 runtime byte 的 otherwise green report 无法满足
promotion 关卡。

KVM-gated lifecycle entry 复用 Apple Silicon qualification 的同一 Utility
VM implementation，而非维护第二套 Linux-only test harness：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-lifecycle.sh
```

独立的 owner-death/restart entry 经 explicitly scoped Unix Host Service
exercise 该 candidate，但不使其 normally registerable：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-recovery.sh
```

Create operation-stage entry 使用独立 qualification scope，并在全部四个
Host 与五个 Guest request/response transition 处替换 real KVM VM/session
owner：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-create-reopen.sh
```

State 在 exact setup Create 后使用相同 qualification scope。它在 distinct
replacement Guest 中 rebuild 该 Created container，并对 original durable
generation 重新发出 State：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-state-reopen.sh
```

Start 保留相同 setup Create 与 exact Start identity。replacement Guest 要么
dispatch prepared Start 一次，要么在 Host replay durable response 前
reconstruct 已 committed Running state：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-start-reopen.sh
```

Kill 保留 exact setup Create、Start 与 signal-9 Kill identity。replacement
Guest reconstruct Running workload，要么 dispatch prepared Kill 一次，要么
在 Host replay durable response 前 rebuild 已 committed Stopped tombstone：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-kill-reopen.sh
```

Delete 保留上述三个 setup identity 加上 exact stopped-only Delete identity。
前八条 path rebuild Stopped tombstone 并 dispatch Delete 一次。final
committed path 启动 distinct empty KVM owner，不 rebuild workload，让 Host
replay completed journal 而无需再次 driver dispatch：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-delete-reopen.sh
```

Wait 使用相同 exact stopped setup，并将 current target 解析到 durable
generation。前八条 path rebuild Stopped Guest tombstone，dispatch original
15-second Wait 一次，并 cache signal-9 result。committed final path 已有
该 cache，因此 replacement 与后续 Wait call 均 replay，无需再次 driver 或
Guest dispatch：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-wait-reopen.sh
```

Exec 保留 exact setup Create 与 Start identity，加上一个 nonce-bound、
long-running terminal process request。前八条 path 仅 recover Running init
process，并在 API retry 后 dispatch unchanged Exec 一次。committed final
path 在 recovery 中 recreate init 与 Exec，将 positive PID rebind 到 durable
response，让 Host replay Exec 而无需再次 API-driven dispatch：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-exec-reopen.sh
```

SignalProcess 保留 committed terminal Exec 并发送 exact signal 10。前八条
path rebuild init 与 Exec，但 leave Prepared signal 供 API retry dispatch
一次。committed final path 等待 rebuilt Exec readiness marker，在 recovery
中 reapply signal 一次，让 Host replay completed journal 而无需再次 driver
dispatch：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-signal-process-reopen.sh
```

WaitProcess 以 signal 10 终止同一 committed non-init Exec，并 wait 最多
15 秒获取 exact exit。前八条 path rebuild 并 terminate Exec，然后在 API
retry 上 dispatch resolved WaitProcess target 一次，并 cache
`signal=10, oom_killed=false`。committed final path 已有 durable cache，
因此 replacement 与后续 WaitProcess call 均不 driver dispatch：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-wait-process-reopen.sh
```

Pause 保留 exact setup Create 与 Start identity，并在 freeze generation 前
verify nonce-bound init marker。前八条 path rebuild unpaused init，并在 API
retry 上 dispatch unchanged Pause 一次。committed final path 在 recovery
中 reapply Pause，将 paused record rebind 到 replacement PID，让 Host
replay 而无需再次 API-driven dispatch：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-pause-reopen.sh
```

Resume 保留 exact setup Create、Start 与 Pause identity。每个 replacement
Guest 在 nonce-bound init marker 后 reconstruct freezer history。前八条
path 在 API retry 上 dispatch unchanged Resume 一次；committed final path
在 recovery 中 reapply Resume，让 Host replay 而无需再次 API-driven
dispatch：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-resume-reopen.sh
```

Processes 保留 exact setup Create、Start 与 live terminal Exec identity。
每个 replacement Guest recreate init 与 Exec，fresh positive PID 与两个
nonce-bound marker，然后 receive read-only Processes query 一次，因无
durable query-response journal。returned inventory 必须恰好包含这两个
target，generation 不变，包括 first owner 已写入 complete response 之后：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-processes-reopen.sh
```

Update 保留 exact setup Create 与 Start identity，加上 complete Linux
resource profile。前八条 replacement Guest 在 rebuild running init 后
receive unchanged request 一次。当 first owner 已 commit response 时，
recovery 将 resource profile reapply 到 fresh cgroup，Host replay response
而无需再次 API-driven dispatch。Direct Stats 验证 512 MiB limit 与 live
counter：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-update-reopen.sh
```

Stats 保留 committed Create、Start 与 Update setup，并将 query 本身视为
read-only。每个 replacement Guest receive 一次 fresh Stats request，包括
first owner 已写入 complete response 之后。final path 要求 replacement
snapshot 更新且 distinct，同时两个 snapshot 均保留 exact generation 与
updated resource profile：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-stats-reopen.sh
```

ReadOutput 保留 committed Create、Start 与 non-terminal capture Exec setup。
每个 replacement Guest receive 一次 fresh request，process target、cursor、
byte limit 与 timeout 不变，包括 first owner 已 deliver complete
nonce-bound stdout chunk 之后。Recovery rebind 两个 setup PID，fence stale
Host 与 Guest generation，并移除两个 marker 与全部 transient owner state：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-read-output-reopen.sh
```

WriteStdin 保留 committed Create、Start 与 non-terminal pipe-backed Exec
setup。前八条 replacement owner 从 Prepared Host journal dispatch unchanged
bytes 一次。在 `guest-after-response-write`，recovery 将 committed write
rehydrate 到 rebuilt Exec，API retry 返回而无需再次 driver dispatch。每条
path 验证 exact effect marker、request identity、stale Host 与 Guest fence
与 complete cleanup：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-write-stdin-reopen.sh
```

CloseStdin 保留相同 setup 与 pipe-backed Exec，该 Exec 仅在 observe EOF 后
写入 exact effect marker。前八条 replacement owner 从 Prepared Host journal
dispatch unchanged close 一次。在 `guest-after-response-write`，recovery
在 Host service open 完成前 close rebuilt Exec input，因此 API retry 返回
而无需再次 driver dispatch。每条 path 验证 exact process target、EOF
marker、stale Host 与 Guest fence 与 complete cleanup：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-close-stdin-reopen.sh
```

Resize 保留 exact terminal dimension 与 nonce-bound PTY Exec。前八条
replacement owner dispatch prepared resize 一次；final path 在 recovery 中
reapply committed dimension，并 replay Host response 而无需第二次 driver
dispatch：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-resize-reopen.sh
```

File 经相同九个 Host/Guest transport boundary 验证 upload，使用 private
writable `/tmp` mount。Recovery 验证 exact durable request 与 generation，
idempotently replay acknowledged upload，从 replacement Guest download
bytes，reject changed 与 stale identity，并在 force-delete 前 remove file：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-file-reopen.sh
```

Filesystem 验证 mkdir，含对应 directory metadata 与 Stat effect。它使用
相同 durable journal、replacement-owner replay、changed 与 stale-generation
fence、explicit Remove 与 zero-residue check：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-filesystem-reopen.sh
```

bounded soak 使用独立 qualification scope 与一个 durable Host Service：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-soak.sh
```

当 KVM 可用时，lifecycle entry 下载 pinned Alpine fixture，在 private
runtime share 下准备两个 bundle，并运行 17 个 case：一个 full lifecycle、
一个 multi-container lifecycle、一个 versioned Guest-isolation entry、三个
no-delete cleanup boundary，以及全部 11 个 transport fault point。Guest-
isolation entry 含 bundle、rootfs、bind-source、File 与 Filesystem boundary
的十个 ordered hostile-path case。它要求 exact owning operation 返回 typed
`permission-denied` error，canary 不变，container state 缺失，且 fixture/
runtime cleanup 完整。`a3s.oci.linux-kvm-lifecycle-matrix.v2` report
留存每个 nested runtime report，以及 endpoint、process、runtime-state、
bootstrap、token/recovery 与 marker cleanup check。无可用 KVM 时跳过
fixture download 并 emit `status: unavailable` 与 zero case。这使 CI 如实
反映 runner capability；它不算 hardware pass。`a3s.oci.linux-kvm-recovery-
matrix.v2` entry 在 KVM unavailable 时 likewise 跳过 Alpine。有 KVM 时 kill
live Host Service，require authenticated SIGKILL recovery，open distinct
replacement socket owner，replay exact stopped state 与 Wait，并证明
stopped-only Delete 加 transient cleanup。soak 在 unavailable host 上也
跳过 Alpine；其 retained aggregate schema 为
`a3s.oci.linux-kvm-soak-matrix.v2`。有 KVM 时运行 25 fresh generation，并
要求每个 process、descriptor、endpoint、handoff、share、recovery record 与
Guest marker 在每波后回到 baseline。Available lifecycle、recovery 与 soak
report（含 integrated Guest-isolation entry）仍须来自 fresh x86_64 与
AArch64 KVM host。其他 real-entry negative-isolation profile 仍是独立
promotion evidence。

`a3s.oci.linux-kvm-create-reopen-matrix.v1` entry 在 KVM unavailable 时也
跳过 Alpine。有 KVM 时，在九个 real Host/Guest interruption point 上保留
exact durable generation 与 Create operation identity，包括在 distinct
replacement Guest 中 rehydrate committed `guest-after-response-write`
outcome。所有 case force-delete 并恢复 bootstrap、endpoint、process、
bundle-handoff、runtime-share、recovery-report 与 marker inventory。
`a3s.oci.linux-kvm-state-reopen-matrix.v1` 关卡对 State 应用相同九点。前
八点 retain exact Created record 且不返回 response；`guest-after-response-
write` 在 disconnect probe 证明 owner loss 前 deliver exact response。
Replacement recovery 必须 rebuild Created state，preserve setup Create
identity 与 generation，返回 recovered durable record，并恢复相同 cleanup
inventory。`a3s.oci.linux-kvm-start-reopen-matrix.v1` 关卡随后对 Start 应用
相同点。前八条 path retain Created state，经 replacement driver dispatch
exact Start 一次。final path retain Running state；recovery recreate 并
start workload，rebind replacement PID，regenerate exact marker，让 Host
replay completed journal 而无需再次 API-driven Start dispatch。
`a3s.oci.linux-kvm-kill-reopen-matrix.v1` 关卡对 Kill 应用相同九点。前八条
path retain Running state；replacement recovery recreate 并 start workload，
repair setup response，dispatch unchanged SIGKILL 一次。final path retain
Stopped state；recovery recreate、start 并 kill replacement workload 以
reconstruct Guest tombstone，然后 Host replay completed Kill journal 而无需
再次 API-driven dispatch。每条 path 验证 replacement marker 并使用
stopped-only Delete。`a3s.oci.linux-kvm-delete-reopen-matrix.v1` 关卡随后
对 Delete 应用全部九点。前八条 path retain Stopped state 与 Prepared
journal；replacement recovery 以 original setup identity recreate、start
并 kill workload，然后 dispatch unchanged Delete 一次。committed final path
retain empty inventory 与 SucceededEmpty journal，因此 distinct empty
replacement owner 在 Host replay 前不做 workload recovery 或 driver Delete。
`a3s.oci.linux-kvm-wait-reopen-matrix.v1` 关卡在全部九点 rebuild stopped
tombstone。前八条 path dispatch exact resolved Wait target 一次，并 durable
cache `signal=9, oom_killed=false`；committed final path 保留该 cache，让
replacement 与后续 Wait call replay 而无需 driver dispatch。每条 path reject
stale generation（Host 与 Guest boundary），使用 stopped-only Delete，并
恢复全部 inventory。`a3s.oci.linux-kvm-exec-reopen-matrix.v1` 关卡对
terminal Exec 应用全部九点。前八条 path retain Prepared journal，仅 recover
Running init process，并 dispatch byte-identical process、terminal、I/O、
generation 与 operation identity 一次。committed final path retain Succeeded
process journal，recreate init 与 Exec（fresh positive PID），rebind setup
与 Exec response，并 replay Host request 而无需再次 driver dispatch。每条
path 验证 distinct nonce-bound init 与 Exec marker，reject changed request
与 stale generation，force-delete workload，并恢复全部 inventory。
`a3s.oci.linux-kvm-signal-process-reopen-matrix.v1` 关卡 retain exact
terminal Exec，并在全部九点 apply signal 10。前八条 path retain Prepared
signal journal，rebuild init 与 Exec，并在 API retry 上 dispatch unchanged
target 与 signal 一次。committed final path retain SucceededEmpty journal，
rebuild init 与 Exec，wait nonce-bound Exec readiness marker，并在 recovery
中 reapply signal 恰好一次；Host replay 随后不再 driver dispatch。每条 path
验证 separate signal marker，reject signal drift 与 stale Host/Guest
generation，force-delete workload，并恢复全部 inventory。WaitProcess 的
equivalent coverage 使用
`a3s.oci.linux-kvm-wait-process-reopen-matrix.v1`。前八条 path 无 Host exit
cache，因此 recovery rebuild 并 terminate exact Exec，然后一次 resolved
WaitProcess dispatch 持久化 `signal=10, oom_killed=false`。在
`guest-after-response-write`，cache 已 durable；recovery 仍 recreate 并
terminate Exec，但 omit 它于 live inventory，replacement 与后续 wait 均以
零 driver dispatch replay。每条 path 复用全部 setup identity，reject stale
Host 与 Guest generation，force-delete workload，并恢复每个 inventory。
Pause 的 equivalent coverage 使用 `a3s.oci.linux-kvm-pause-reopen-matrix.v1`。
前八条 path retain Running state 与 Prepared Pause journal，rebuild unpaused
init，并 dispatch unchanged Pause 一次。committed final path retain paused
state 与 Succeeded journal；recovery start replacement init，wait marker，
reapply Pause，并在 Host replay 前 report recreated-paused-running evidence。
每条 path fence changed request 与 stale Host/Guest generation，force-delete
paused generation，并恢复每个 inventory。Resume 使用
`a3s.oci.linux-kvm-resume-reopen-matrix.v1`。每个 replacement owner
reconstruct Create、Start 与 Pause（rebound PID）。前八条 path retain paused
state 与 Prepared Resume journal，然后 unchanged dispatch 一次。committed
final path retain unpaused state 与 Succeeded journal；recovery reapply
Resume，Host replay 不再 additional API-driven dispatch。每条 path fence
changed request 与 stale Host/Guest generation，force-delete resumed
generation，并恢复每个 inventory。Processes 使用
`a3s.oci.linux-kvm-processes-reopen-matrix.v1`。每个 replacement owner
reconstruct Create、Start 与 committed terminal Exec，rebind 两个 positive
process PID，并 verify 两个 nonce-bound marker。因 query 为 read-only，全部
九条 path 在 reopen 后 dispatch Processes 恰好一次，包括 delivered final
response path。每个 inventory 仅含 init 与 original Exec target，generation
不变，PID 为 replacement。每条 path reject stale Host/Guest generation，
force-delete workload，并恢复每个 inventory。Update 使用
`a3s.oci.linux-kvm-update-reopen-matrix.v1`。前八条 path preserve Prepared
journal，并在 recovery 后 dispatch unchanged complete Linux resource request
一次。committed final path preserve Succeeded journal；recovery 将 request
reapply 到 fresh cgroup，Host replay 不再 additional API-driven dispatch。
每条 path 经 direct Guest Stats 验证 512 MiB limit 与 live counter，reject
changed request 与 stale Host/Guest generation，force-delete workload，并
恢复每个 inventory。Stats 使用
`a3s.oci.linux-kvm-stats-reopen-matrix.v1`。每个 replacement owner
reconstruct Create、Start 与 committed Update，然后 dispatch 一次 fresh
read-only query。在 `guest-after-response-write`，first delivered snapshot
与 newer replacement snapshot 均 retain exact generation 与 updated resource
profile。每条 path reject stale Host/Guest generation，force-delete workload，
并恢复每个 inventory。ReadOutput 使用
`a3s.oci.linux-kvm-read-output-reopen-matrix.v1`。每个 replacement owner
reconstruct Create、Start 与 live non-terminal Exec（rebound PID），然后
dispatch 一次 fresh query，process target、cursor、byte limit 与 timeout
不变。在 `guest-after-response-write`，delivered first chunk 与 replacement
chunk 均等于 nonce-bound stdout。每条 path reject stale Host/Guest
generation，force-delete workload，并恢复每个 inventory。WriteStdin 使用
`a3s.oci.linux-kvm-write-stdin-reopen-matrix.v1`。前八条 path retain
Prepared Host journal，并在 recovery 后 dispatch exact bytes 一次。在
`guest-after-response-write`，recovery 将 committed bytes 写入 rebuilt
pipe-backed Exec，API retry 不再 additional dispatch。每条 path reject
changed bytes 与 stale Host/Guest generation，verify nonce-bound effect
marker，force-delete workload，并恢复每个 inventory。CloseStdin 使用
`a3s.oci.linux-kvm-close-stdin-reopen-matrix.v1`。前八条 path retain
Prepared Host journal，并在 recovery 后 dispatch exact EOF 一次。在
`guest-after-response-write`，recovery close rebuilt pipe-backed Exec，API
retry 不再 additional dispatch。每条 path reject changed process target 与
stale Host/Guest generation，verify nonce-bound EOF marker，force-delete
workload，并恢复每个 inventory。Resize、File 与 Filesystem 使用相同九阶段
关卡；current x86_64 证据现已覆盖全部 20 个 workload operation。Host
shutdown 仍是 explicit readiness 关卡。

| 所有者 | 保留 | 不得吸收 |
| --- | --- | --- |
| A3S Box 产品平面 | 期望状态、镜像/构建、命名卷、产品网络、Compose、健康/重启策略、日志保留与密钥授权 | 实际 PID/VM 身份或 runtime operation journal |
| OCI Runtime 控制平面 | 精确 OCI 校验、实际状态、代次、重放、退出状态、驱动选择、恢复与清理 | Registry pull、镜像构建、Compose 或静默 isolation fallback |
| 平台执行平面 | Linux 强制执行、辅助虚拟机、传输、进程控制与 runtime attachment | 产品编排或第二套 durable lifecycle |

## 运行真实环境验证关卡

可移植工作区关卡为：

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

当前 release workflow 产生的完整 Runtime tag 包含全部五个 archive 的
signed SLSA build provenance 与 `SHA256SUMS`，以及可移植 Sigstore bundle。
遵循 [Release verification](docs/release-verification.md) 以强制
repository、workflow、tag 与 digest identity。验证成功不会提升所选 driver
advertised readiness，也不会替代其 real-host 关卡。每个 Linux host-runtime
archive 还携带 digest-and-mode-bound `package-manifest.json`，链接其 exact
runtime、Agent、containerd shim、qualification report 与 containerd
compatibility contract；packaged verifier 可在安装前 offline 校验。

真实 execution 关卡需要 prepared host 与 isolated runtime root。

| 主机 | 入口 | 指南 |
| --- | --- | --- |
| Linux x86_64/aarch64 | `bash .github/scripts/native-linux-smoke.sh`、`bash .github/scripts/native-linux-checkpoint.sh`（需 exact CRIU binary），以及带 pinned KVM manifest 的 `bash .github/scripts/linux-kvm-lifecycle.sh` | [Native Linux development](docs/linux-native.md) |
| Apple Silicon | `cargo run -p a3s-oci-cli -- hvf-smoke`，随后 signed utility-VM profile | [macOS HVF development](docs/macos-hvf.md) |
| Windows x86_64 | `scripts/windows-whpx-driver-smoke.ps1` 与 `scripts/windows-whpx-recovery-smoke.ps1`（需 verified container-rootfs archive 与 `windows-system-image` manifest） | [Windows WHPX development](docs/windows-whpx.md) |

Linux smoke 为 rootless v4 关卡准备 explicit user-owned cgroup-v2 subtree。
Tokio 启动前，CLI retain 该 exact delegation，启动 parent-bound effective-root
helper，并永久 drop runtime owner 到 real identity。普通 rootless launch 使用
helper 提供六个 OCI default device node，并安装与 rootful execution 相同的
immutable inventory boundary；它不会发明 `linux.resources.devices` policy。
独立 A3S Box profile 还 exercise bounded device-access BPF replacement 与
rollback。Runtime commit `bed43d2` 在 CI run `31714178349` 上于 x86_64 与
aarch64 通过 full policy profile。v4 关卡验证 create、live update/stats、
workload-proven pause/resume、durable event、全部六个 node、请求的 exact
policy update，以及完整 cgroup、runtime、session 与 marker cleanup。更广
delegated profile 仍是 unadvertised promotion work。

rootful device-boundary profile 刻意 omit `linux.cgroupsPath`，grant
`CAP_MKNOD`，并证明仅 declared/default identity 仍可用。它还将 `nodev` bind
source 在 workload 内 remount 为 `dev`，并验证 late device access 仍以
`EPERM` fail。运行聚焦关卡：
`A3S_OCI_NATIVE_FOCUS=device-boundary bash .github/scripts/native-linux-smoke.sh`。

writable OCI cgroup mount 现遵循 OCI 1.3 delegation boundary。executor 仅
对 exact `source: "cgroup"` mount 于 `/sys/fs/cgroup`（无 `ro` option 且
新建 cgroup namespace）变更 ownership。它将 `process.user.uid` map 到 host
UID，preserve group，并仅变更 container cgroup directory 与
`/sys/kernel/cgroup/delegate` 列出的 existing file；若 inventory 缺失，使用
三个 normative fallback file。聚焦 Native Linux 关卡还证明 read-only cgroup
mount 与 unlisted controller file 保持 ownership：
`A3S_OCI_NATIVE_FOCUS=cgroup-ownership bash .github/scripts/native-linux-smoke.sh`。

rootful terminal-init profile 从 `process.terminal` 派生 init I/O，在 launch
前 apply configured 120x40 size，并将 exact PTY slave bind 到 `/dev/console`。
它还于 `/dev` 外 create configured FIFO，含 mapped mode 与 ownership。关卡
运行一次（新 console target）与一次（caller-owned placeholder）；Delete 仅
remove runtime-created target，并将 pre-existing file 恢复不变。

当 container create private mount namespace 但 join existing user namespace
时，executor pin 并 type-check 该 namespace，经 short-lived namespace helper
observe real UID/GID map，并在 entry 前 recheck namespace identity。同一
detached-mount path 随后以 namespace-root ownership 提供六个 default device。
Native Linux multi-container v20 与 real Apple Silicon utility-VM multi-
container v11 均 verify device type、major/minor number、mode、ownership、
workload access 与 cleanup。同一 report 覆盖 image `/dev`（fresh tmpfs），并
要求四个 OCI Linux link 在每个 configured mount 就位后 resolve 到 exact
`/proc/self/fd` target。

mount-option discovery 与 execution 现共享 SDK pinned 61-entry OCI 1.3
registry。executor 消费全部 required 与 recommended control option，不将其
泄漏到 filesystem data，将 unknown string 视为 filesystem-specific data，并对
optional `tmpcopyup` behavior 返回 typed `Unsupported` error。Feature
discovery 按 sorted order 报告 60 个 implemented OCI name 与 `rnodev`
extension，不 advertise `tmpcopyup`。

其余 OCI Linux capability reporting 遵循相同规则。每个 `RuntimeDriver` 在
Host Service open 时 supply 一个 validated `OciLinuxSupport` value。registry
freeze 该 value，若 multi-driver set 中任一 profile 不同则 reject，并据此
build `Features`。Create、Exec 与 Update 在 durable mutation 前 check 同一
value；Linux Agent 在 init、process 与 cgroup planning 复用 shared profile。
AppArmor、SELinux、mount label、unadvertised Seccomp control 与 cgroup-v1-
only resource 因此不能一种方式 report、另一种方式 admit。

configured host service 还 report 每个可改变 runtime behavior 的 built-in
annotation，以及 active driver 实现的 annotation-backed extension。probe-only
discovery 保持 empty，driver-specific extension（如 bundle handoff）仅当
selected driver set 实际 advertise 时出现。

`RuntimeInfo::extensions` 是选择该 driver-specific surface 的 versioned
`a3s.oci.extensions.v1` source of truth。它将 catalog 绑定到 running Host
executable 的 SHA-256，并为每个 launch-ready driver 及其 unique isolation
class 发布 canonical operation-contract 与 attachment version。
`RuntimeNegotiationRequest` 按 typed `IsolationClass` 选择，若任一 requested
version 缺失则在 workload preparation 前 fail。legacy flat `operations` 与
`attachments` field 仅 expose 对每个 registered driver 安全的 intersection；
older peer 的 response 默认 empty catalog，不能 silently satisfy negotiation。

`a3s.oci.attachments.v2` 将 already-authorized storage bind 到 exact OCI
mount、immutable caller-issued allocation identity、matching read-only 或
read-write access、caller ownership 与 detach-only cleanup。runtime 从不
resolve named volume 或 snapshot，也从不 delete caller-owned backing resource。
Storage create 要求 SDK protocol 5，而 v1 create manifest 保留 protocol-3
compatibility。每次 restore 要求下文 immutable protocol-8 checkpoint reference。

`a3s.oci.attachments.v3` 将 already-authorized Linux interface bind 到 exact
OCI network namespace 与 `linux.netDevices` entry，以及 immutable namespace、
interface 与 cleanup identity。Runtime-created namespace 随 container release；
joined caller namespace 保留。IPAM、DNS、route、alias、policy 与 backing-
network cleanup 留在 A3S Box。Network create 要求 SDK protocol 6；restore
要求 protocol 8。Rootful Native Linux advertise cumulative v1-v3；rootless
Native 保持 v1-v2，因无 host network-device authority。Dedicated Linux KVM 现
有 internal、fail-closed v2/v3 transport。Caller-owned non-bind `ext4` raw
image 仍在 runtime share 外，descriptor-pinned 为 read-only 或 read-write
virtio-blk device；Guest 在 rewrite 仅 authorized OCI mount source 前 match
libkrun serial、size 与 read-only state。Exact-generation private manifest 还
bind authorized network JSON pointer 与 attachment evidence 到 deterministic
Guest MAC；Guest 仅 rename uniquely matching VMM NIC。Joined caller namespace
与 reusable Guest session 被拒绝。KVM  nevertheless 继续 advertise v1，直到
其 cumulative v2/v3 destructive real-host restart、cleanup、replay 与 soak
qualification 通过。HVF 保持 v1，直到获得 equivalent independent transport
与 evidence。

`dev.a3s.network.enforcement@1` 是 v3 上 independently negotiated required
extension。它将一个 opaque caller-compiled enforcement incarnation 与 optional
opaque local-redirect incarnation bind 到 exact joined caller-owned namespace，
仅使用 positive generation 与 lowercase SHA-256 digest。Runtime 既不 receive
policy content，也不获得 mechanism cleanup authority。exact decoded binding
留存于 `ContainerRecord::network_enforcement`，并在 reopen 后对照 durable
manifest 与 configuration snapshot check。SDK/Host contract 与 rootful Native
Linux implementation 已 qualified；rootless Native 与 VM driver 在各自
authority model 与 driver-specific real-host qualification 完成前继续 omit
该 capability。

`a3s.oci.attachments.v4` 将 SharedGuestKernel request bind 到一个 reusable
guest-session ID 与 positive incarnation、request 的 immutable trust domain、
capacity 上限 64 member、runtime ownership 与 explicit empty-session reset
mode。Create 要求 SDK protocol 7，restore 要求 protocol 8。exact binding
留存于 `ContainerRecord`，并在 reopen 后 revalidate 对照 durable manifest。
common HVF/KVM implementation 强制执行 admission、capacity、reset、
generation rotation、member cleanup 与 shared-owner reclamation，但无
production utility-VM driver advertise v4，直到其 prerequisite storage/network
transport 与 real-host restart/leak qualification 通过。fail-closed composition
规则见 [attachment contract](docs/attachment-contracts.md)。

SDK protocol 8 freeze `a3s.oci.checkpoint-reference.v1`：一个 exact paused
source generation、configuration 与 attachment digest、driver/isolation、
platform 与 architecture、Host executable 与 driver-build evidence、
driver-defined format，以及 exact artifact digest 与 size。Checkpoint 仅接受
already-paused running generation 并保持 paused；restore 返回 new paused
running generation，并 require explicit later `resume`。Artifact storage、
lineage、retention 与 object policy 仍由 caller 持有。Host 现拥有 durable
checkpoint 与 restore orchestration。Checkpoint fence exact paused source 与
全部 process I/O。Restore 先 replay 任何 committed v5 或 v6 outcome，不
reopen caller data；否则 validate immutable artifact 与 exact runtime/driver
compatibility，然后 allocate generation，dispatch idempotent driver restore，
并 commit paused running record。Terminal restore failure 仅 quarantine 其
allocated generation，以便 ID 可 monotonically reuse。registry 仅 accept
`Checkpoint` 来自 explicitly advertising current-platform driver，并仅在与
`Checkpoint` 一起 accept `Restore`。default Native Linux inventory 与
ordinary experimental constructor 均不 advertise 任一 operation。独立 rootful
`open_experimental_with_criu` constructor bind 一个 exact CRIU executable 并
advertise Checkpoint 与 Restore。其 `native-linux-criu` v1 backend advertise
两项 operation，atomically publish 一个 streaming digest-bound artifact，经
CRIU recreate newer exact paused generation，经 Host boundary replay
checkpoint/restore response loss，leave source paused，并有 bounded real-
kernel positive gate 加 private-PID 与 configured-network-namespace negative
gate。其 v3 gate 还在 Restore driver call 与 completed Host-operation
directory sync 后 replace runtime owner；fresh service 与 driver reopen 相同
root，从 retained immutable image recreate live paused generation，replay
exact response，preserve artifact，并 clean 每个 restore journal、staging、
executor 与 session path。Package qualification v6 以 staged static CLI 与
Agent 运行相同 three-report gate，bind runtime 与 host-provided CRIU digest，
并将 report 留存于 archive。2026 年 9 月 8 日 bare-metal x86_64 observation
（clean revision `a35703c`）在 pinned CRIU 4.2.1 上 retain 相同 three-report
gate；它是 source-built observation evidence，不关闭 tagged multi-architecture
或 production readiness。更广 namespace 与 descriptor profile、cross-driver 与
retained tagged multi-architecture qualification，以及 production readiness
仍开放。见 [immutable checkpoint contract](docs/checkpoint-contract.md)。

containerd runtime-v2 shim 现 expose 该 optional contract，但不将其纳入
endpoint 18-operation base admission set。paused Task Checkpoint 写入
`a3s-oci-checkpoint-v1.bin` 加 atomically committed `a3s-oci-checkpoint-v1.json`
reference manifest 到 containerd requested directory。Create 带该 directory
validate immutable package 并 call SDK Restore。虽 SDK restore 返回 paused
running generation，shim 报告 CREATED，直到 first Start 执行一次 replay-
stable Resume；schema-v10 metadata 与 schema-v2 create intent 在 shim crash
后 recover barrier 两侧。Unsupported selected driver 仅对 optional request
返回 Unimplemented。Incremental checkpoint 与 non-neutral runc checkpoint
option 仍 rejected。

SDK protocol 9 增加 policy-neutral TEE mechanism boundary。dedicated-VM
create 或 restore 可 require 恰好一个 `dev.a3s.tee.amd-sev-snp@1` 或
`dev.a3s.tee.intel-tdx@1` launch extension，mode 为 explicit `hardware` 或
`simulated`。独立 durable `attest` operation 携带 exact 64-byte report-data
binding，返回 bounded opaque provider evidence 加 launch measurement、
configuration 与 attachment digest、driver 与 driver-build identity，以及
exact Host artifact。Runtime validate 与 replay 这些 binding，但不 verify
provider claim 或做 authorization decision；Box 或 Cloud 拥有 appraisal 与
policy。driver 仅在与至少一个 exact TEE extension 及 dedicated-VM isolation
一起时 advertise `Attest`。无 production driver advertise 任一 TEE extension
或 `Attest`，直到 hardware execution、evidence collection、restart、upgrade
与 destructive real-host qualification 通过。见 [TEE launch and attestation
contract](docs/tee-attestation-contract.md)。

这些 command 可能需要 root privilege、hypervisor access、signed artifact，
或在 explicitly supplied test root 内 destructive cleanup。运行前请阅读链接的
host guide。

## 证据，而非口号

本仓库将发布声明转化为可检查的 inventory：

| 证据 | 当前锁定 |
| --- | ---: |
| 已分类的命名 OCI schema 属性与 enum 值 | 423 |
| OCI schema disposition | 257 enforced · 2 validated · 75 rejected unsupported · 89 rejected inapplicable · 0 pending · 0 conformant |
| 已审查的 schema 证据 | 334 applicable items in 31 bindings · 132 rules · 103 tests |
| OCI Linux configuration 与 Features profile | 190 / 190 schema items: 145 enforced · 45 rejected unsupported; 218 / 218 `config-linux.md`: 206 enforced · 9 validated · 3 conformant; 41 / 41 `features-linux.md` enforced |
| OCI VM configuration profile | 26 / 26 schema items · 24 / 24 normative requirements · 4 validated absolute paths · 20 fail-closed runtime-owned controls |
| Pinned OCI JSON Schema 套件 | 19 / 19 upstream fixtures · 4 / 4 launch profiles with configuration, Features, and created/running/stopped State documents |
| 官方 OCI Runtime Tools bundle 关卡 | Runtime Tools 0.9.0 at `8a4db579f5c88af5a0d036fad34bddc9c1f703f3` · OCI 1.3.0 Native Linux and utility-VM bundles · MUST level · escaping-rootfs negative |
| 15 份 pinned normative OCI 1.3 文档中的 RFC 2119 出现次数 | 764 |
| Typed semantic validation rule | 95 |
| Owner-bound non-semantic rule | 156 |
| OCI normative disposition | 578 enforced · 51 validated · 12 conformant · 14 reviewed external · 0 pending review |
| 已注册 durable commit fault stage | 877 |
| Durable-state replacement qualification | macOS/Linux/Windows 完成，含 real Linux bind mount 与 Windows reparse-point matrix |
| Live containerd terminal init-Kill rehydration | 3 / 3 consecutive same-Host Ubuntu arm64/containerd 2.2.2 matrices on August 24, 2026 |
| Live containerd `DeleteProcess` response replay | 3 / 3 consecutive same-Host Ubuntu arm64/containerd 2.2.2 matrices on August 24, 2026 |
| Live containerd task Delete response replay | 3 / 3 consecutive same-Host Ubuntu x86_64/containerd 2.2.3 matrices on August 24, 2026 |
| Post-commit containerd `WriteStdin` forced cleanup | 3 / 3 consecutive same-Host Ubuntu x86_64/containerd 2.2.3 matrices on August 24, 2026 |
| Post-commit containerd `CloseStdin` forced cleanup | 3 / 3 consecutive same-Host Ubuntu x86_64/containerd 2.2.3 matrices on August 24, 2026 |
| Post-commit containerd `ResizePty` forced cleanup | 3 / 3 consecutive same-Host Ubuntu 24.04.3 LTS/WSL2 x86_64 observations on August 28, 2026 |
| Before/after `RuntimeDriver` fault boundary | 52 |
| Authenticated agent operation-stage fault pair | 180 |
| Portable Create/State/Start/Kill/Delete/Wait/Exec/SignalProcess/WaitProcess/Pause/Resume/Processes/Update/Stats/ReadOutput/WriteStdin/CloseStdin/Resize/File/Filesystem host-service reopen pair | 180 |
| Real HVF Create Host/Guest 加 Host shutdown interruption 与 cleanup stage | 11 |
| Real HVF durable Create reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable State reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable Start reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable Kill reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable Delete reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable Wait reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable Exec reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable SignalProcess reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable WaitProcess reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable Pause reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable Resume reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable Processes reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable Update reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable Stats reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable ReadOutput reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable WriteStdin reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable CloseStdin reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable Resize reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable File reopen 加 VM/session-owner replacement path | 9 |
| Real HVF durable Filesystem reopen 加 VM/session-owner replacement path | 9 |
| Real HVF operation replacement coverage | 180 / 180 paths (20 / 20 operations) |
| Real HVF journaled post-response acknowledgement rerun | 14 / 14 mutations on August 15, 2026 |
| Real HVF lifecycle/transport cleanup fault point | 14 / 14 |
| Real HVF immutable-system-image soak | 25 / 25 fresh VMs (75 primary generations) |
| macOS HVF R2M implementation gate | 15 / 15 |
| Public macOS HVF Host Service implementation | Complete; revision `a5a6b53` passed 23/23 operations, owner replacement, and 25/25 fresh VMs |
| Linux KVM 17-case lifecycle entry | Implemented for x86_64 and AArch64; clean revision `e7567f9` retained `available` evidence on x86_64, so fresh-host evidence is 1 / 2 architectures |
| Linux KVM owner-death/restart entry | Implemented for x86_64 and AArch64; clean revision `e7567f9` retained `available` evidence on x86_64, so fresh-host evidence is 1 / 2 architectures |
| Linux KVM bounded soak entry | Implemented at 25 fresh generations for x86_64 and AArch64; clean revision `e7567f9` retained 25 / 25 on x86_64, so fresh-host evidence is 1 / 2 architectures |
| Linux KVM Create operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `c435e26` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and 9 / 180 workload-operation paths |
| Linux KVM State operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `d0c29e2` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 18 / 180 paths |
| Linux KVM Start operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `3bbdeda` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 27 / 180 paths |
| Linux KVM Kill operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `336bd5e` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 36 / 180 paths |
| Linux KVM Delete operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `3227ace` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 45 / 180 paths |
| Linux KVM Wait operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `b491195` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 54 / 180 paths |
| Linux KVM Exec operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `18ecaf1` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 63 / 180 paths |
| Linux KVM SignalProcess operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `2f5456c` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 72 / 180 paths |
| Linux KVM WaitProcess operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `4338d37` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 81 / 180 paths |
| Linux KVM Pause operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `3e9fc4b` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 90 / 180 paths (10 / 20 operations) |
| Linux KVM Resume operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `b4c3a85` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 99 / 180 paths (11 / 20 operations) |
| Linux KVM Processes operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `9a1a37c` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 108 / 180 paths (12 / 20 operations) |
| Linux KVM Update operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `aa0f56a` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 117 / 180 paths (13 / 20 operations) |
| Linux KVM Stats operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `09286d8` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 126 / 180 paths (14 / 20 operations) |
| Linux KVM ReadOutput operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `dd47146` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 135 / 180 paths (15 / 20 operations) |
| Linux KVM WriteStdin operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `17b307d` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 144 / 180 paths (16 / 20 operations) |
| Linux KVM CloseStdin operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `31d35c3` retained 9 / 9 on x86_64, so fresh-host evidence is 1 / 2 architectures and total retained workload-operation coverage is 153 / 180 paths (17 / 20 operations) |
| Linux KVM Resize operation-stage owner replacement | Implemented and CI-wired for both architectures; clean x86_64 qualification retained 9 / 9 stages, and the complete Linux KVM operation-stage implementation set now covers 20 / 20 operations |
| Linux KVM File operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `fa4c593` retained 9 / 9 stages on x86_64 (report `8bd1bb731198c5a28659a47e85d146a5e8285483488a6540acda8d1596d51ec3`), fresh-host evidence remains 1 / 2 architectures |
| Linux KVM Filesystem operation-stage owner replacement | Implemented and CI-wired for both architectures; clean revision `fa4c593` retained 9 / 9 stages on x86_64 (report `205e3b493e218a3fc3d8bc50f4d4b3af14ccf0156846352dfa00bd1d84d67c19`), fresh-host evidence remains 1 / 2 architectures |
| Linux KVM operation-stage owner replacement coverage | 180 / 180 paths implemented and CI-wired across 20 operations; available x86_64 evidence is complete across the retained current and prior clean revisions, while fresh AArch64 evidence is pending |
| Protocol v10 背后的 Guest operation | 21（20 个公共 workload operation + 1 个有界 maintenance acknowledgement） |

这些锁定证明 inventory 与已 exercise 的 boundary，本身并不等同于完整
conformance。OCI 1.3 normative inventory 无 unclassified entry，但 upstream
lifecycle suite、adversarial security、upgrade compatibility 与 exact release-
artifact qualification 均须通过，driver 才能成为 `supported`。

### 仍有意保持开放

- 在具备 CAT/MBA 能力的 Linux 主机上进行 real-kernel Intel RDT qualification；
- 在每个剩余 utility-VM driver 上对 descriptor-confined filesystem session
  进行 real-host qualification；
- production-ready Native Linux 与 utility-VM driver；
- owner death 后 live Native Linux process-I/O reattachment，以及 persistent
  authenticated reaper 可保留时的 exact terminal evidence；
- 已实现 immutable WHPX system root 的 fresh-host qualification，以及已实现
  KVM system root 的 real-entry qualification；
- utility-VM hook recovery 与 security certification；
- default 与 cross-platform A3S Box cutover，以及剩余 containerd compatibility、
  packaging 与 cross-driver 关卡；
- Native Linux CRIU 更广 checkpoint source profile、cross-driver 与 retained
  tagged multi-architecture real-host qualification，以及 production
  checkpoint/restore readiness；
- production SEV-SNP/TDX launch 与 attestation driver、hardware evidence
  qualification，以及 Runtime 之外的 verifier-policy integration；
- exact published-package qualification、upgrade、rollback、security 与
  long-duration release 关卡。

## 工作区结构

```text
crates/sdk/             public async OCI contract, bundle validation, local IPC
crates/core/            lifecycle, isolation, readiness, and capability types
crates/runtime/         durable host service, drivers, probes, state, reports
crates/agent-protocol/  authenticated host/guest wire contract
crates/agent/           static Linux guest agent and shared LinuxExecutor
crates/krun/            isolated shim plus pinned native runtime bundles
crates/cli/             capability inspection and real-host qualification gates
```

## 文档

- [路线图与发布关卡](ROADMAP.md)
- [发布验证](docs/release-verification.md)
- [持久化生命周期与恢复](docs/durable-state.md)
- [SDK 传输](docs/sdk-transport.md)
- [不可变检查点与恢复契约](docs/checkpoint-contract.md)
- [TEE 启动与 attestation 契约](docs/tee-attestation-contract.md)
- [版本化 attachment 契约](docs/attachment-contracts.md)
- [客户机代理协议](docs/agent-protocol.md)
- [OCI 1.3 conformance 契约](docs/oci-conformance.md)
- [规范覆盖](docs/normative-coverage.md)
- [功能覆盖](docs/feature-coverage.md)
- [语义校验](docs/semantic-validation.md)
- [Native Linux 开发](docs/linux-native.md)
- [macOS HVF 开发](docs/macos-hvf.md)
- [Windows WHPX 开发](docs/windows-whpx.md)

## 开发

从仓库根目录运行检查：

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

交叉检查受支持的 Linux 编译目标，无需将父 monorepo 当作 Rust workspace：

```bash
cargo clippy --target x86_64-unknown-linux-gnu \
  --workspace --all-targets -- -D warnings
cargo clippy --target aarch64-unknown-linux-gnu \
  --workspace --all-targets -- -D warnings
```

带 tag 的 archive 包含主机诊断与匹配的平台 asset。Linux x86_64 与 arm64
archive 携带 static-linked musl CLI、agent 与 containerd shim 可执行文件，其
release 关卡拒绝 ELF interpreter 与 dynamic dependency。在 archive 任一 Linux
directory 前，其 exact CLI 与 Agent 运行完整 Native Linux SDK、rootless、
owner-death、Hook-recovery、OAR-01 network-enforcement、fault-cleanup 与
bounded-soak matrix，且 `/dev/kvm` 已移除。archive 保留
`qualification/native-linux-package.json` schema v7，加十三个 digest-bound、
regular、nonsymlink 从属 report，normalized 为 mode `0644`。其中三个 report
以 staged binary 运行 OAR-03 CRIU checkpoint/restore、replacement-process
recovery 与 PID/network namespace rejection 关卡。第四个以 exact commit
`8a4db579f5c88af5a0d036fad34bddc9c1f703f3` 运行官方 OCI Runtime Tools 0.9.0，
针对 Native Linux 与 utility-VM OCI 1.3.0 bundle configuration 及
escaping-rootfs negative。在 x86_64 与 AArch64 上，第五个 report 经 staged CLI
与 durable Host Service 启动 pinned upstream lifecycle profile。compatibility
lock 提供 architecture-matched Alpine 3.22.5 minirootfs，含 exact URL、size
与 SHA-256 provenance，因 Runtime Tools 本身仅携带 amd64 fixture。builder 在
安装到 upstream harness 期望的文件名前，拒绝 unsafe archive path、缺失 BusyBox
identity 与 architecture drift。全部九个选定 test 均执行：七个通过原始 TAP
assertion，而 `start` 与 `pidfile` 在语义上保留 conformant，对应两个 exact、
source-audited Runtime Tools harness defect。upstream AArch64 configuration 的
native 与 32-bit ARM seccomp ABI 均用 architecture-scoped syscall table 编译。
report 记录 rootfs source、两个 defect identifier、全部 retired CLI journal、
clean service shutdown，并在两种 Linux architecture 上 qualify pinned core
lifecycle profile，不隐藏两个 raw TAP failure。workflow 还在 pinned commit
`9539417f3e3cfa4eb84c319cd71f4d52f1f08645` 构建 upstream CRIU v4.2.1。CRIU
与 Runtime Tools 仍由 host 提供且在 archive 外；其 exact identity 与 executable
digest 由 package report 绑定。pinned core profile 不 qualify inherited stdio
descriptor transport、terminal console socket、`LISTEN_FDS`、更广 upstream
suite 或非 Linux platform。package availability 永不会 override exact binary
`features` result 所报告的就绪状态。

## 许可证

A3S OCI Runtime 在 [MIT License](LICENSE) 下提供。

