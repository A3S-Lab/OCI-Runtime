<p align="center">
  <img src="assets/readme/hero.svg" width="100%" alt="A3S OCI Runtime：将每个容器绑定到精确 generation、持久生命周期与证据门控的执行 driver">
</p>


<p align="center">
  <strong>Language / 语言:</strong>
  <a href="README.md">English</a> ·
  <a href="README.zh-CN.md">中文</a>
</p>

<p align="center">
  <strong>A3S 的底层执行平面：官方 OCI 类型、持久生命周期重放，以及跨越 native 与 utility-VM 路径的同一套已审阅 Linux 执行器。</strong>
</p>

<p align="center">
  <a href="https://github.com/A3S-Lab/OCI-Runtime/actions/workflows/ci.yml"><img alt="CI status" src="https://img.shields.io/github/actions/workflow/status/A3S-Lab/OCI-Runtime/ci.yml?branch=main&amp;style=flat-square&amp;label=CI"></a>
  <a href="https://github.com/A3S-Lab/OCI-Runtime/releases/latest"><img alt="Latest A3S OCI Runtime release" src="https://img.shields.io/github/v/release/A3S-Lab/OCI-Runtime?display_name=tag&amp;sort=semver&amp;style=flat-square&amp;color=68c7ff"></a>
  <img alt="OCI Runtime Specification 1.3.0" src="https://img.shields.io/badge/OCI_Runtime_Spec-1.3.0-68c7ff?style=flat-square">
  <img alt="Rust workspace" src="https://img.shields.io/badge/implementation-Rust-dbe7f0?style=flat-square&amp;logo=rust&amp;logoColor=111827">
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-f0b85a?style=flat-square"></a>
</p>

<p align="center">
  <a href="#启动前先检查">检查</a> ·
  <a href="#当前已实现内容">实现</a> ·
  <a href="#运行时契约">契约</a> ·
  <a href="#平台状态">平台</a> ·
  <a href="#架构">架构</a> ·
  <a href="#运行真实门禁">资格验证</a> ·
  <a href="#开发">开发</a>
</p>

---

**A3S OCI Runtime** 负责 A3S 的实际 Linux 容器执行：精确的 OCI
校验、容器与进程状态、单调 generation、操作
日志、终端状态、平台 driver、utility VM、经过认证的
guest agent，以及运行时作用域内的清理。

它故意不拉取镜像、不构建镜像、不实现 Compose、不拥有
产品网络或卷，也不会变成 Docker daemon。这些职责
留在 [A3S Box](https://github.com/A3S-Lab/Box)；Box 通过公共
`a3s-oci-sdk` 提供已准备好的 bundle、隔离要求，以及版本化的
attachment 清单。

提供商中立的 Rust 契约也可独立使用：
`a3s-oci-core = "=0.3.1"` 与 `a3s-oci-sdk = "=0.3.1"`。它们的
`sdk/rust/v*` 源码标签与完整 Runtime 二进制发布彼此独立。

> [!WARNING]
> 本仓库处于积极开发中。当前没有内置 driver 被声明为
> `supported`。默认宿主服务仅暴露发现能力；Native Linux
> 仅在显式以开发实例打开时才变为 `experimental`，Apple Silicon HVF
> 为 `experimental`，而 KVM 与 WHPX 仍为 `probe-only`。Experimental
> 表示已审阅的开发配置文件可以启动；并不意味着已通过生产认证。

## 启动前先检查

第一个成功的操作故意是只读的：

```bash
git clone https://github.com/A3S-Lab/OCI-Runtime.git
cd OCI-Runtime
cargo run -p a3s-oci-cli -- features
```

在用于当前分支的合格 Windows x86_64 宿主上，该命令会报告
可用的 hypervisor，但仍拒绝夸大 driver 就绪度：

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

evidence 对象因宿主而异。选择规则不会：

| 报告状态 | 可否启动？ | 含义 |
| --- | --- | --- |
| 宿主 `available` + `probe-only` | 否 | 仅诊断或资格验证 |
| 宿主 `available` + `experimental` | 需显式选择加入 | 已审阅的开发配置文件；发布门禁仍适用 |
| 宿主 `available` + `supported` | 是 | 已认证配置文件 |
| 宿主 `unavailable` 或 `unsupported` | 否 | 缺少先决条件，或平台不适用 |

`DriverCapability::can_launch()` 同时要求宿主能力为 available，
以及 readiness 为 `experimental` 或 `supported`。

## 当前已实现内容

|层 |实施边界|
| ---| ---|
|公共SDK |使用官方 OCI `Spec`、`Process`、`LinuxResources`、`State` 和 `Features` 类型的异步`Send + Sync` Rust 合约；类型 ID、生成、操作上下文、每个驱动程序的精确工件功能协商、版本化附件（包括已授权存储）、Linux 网络接口、不透明网络执行/本地重定向证据、可重用访客会话身份、不可变检查点引用和暂停恢复响应、I/O、文件系统会话、统计信息、事件和稳定错误 |
|验证和运输| OCI 1.0.0–1.3.0 模式和语义验证，具有前向兼容的未知属性保留和忽略语义、精确的 79 项通用配置和 278 项要求所有者门、详尽的 19 例固定上游 JSON 模式套件、四个启动配置文件配置/状态/功能矩阵、不可变配置、附件和检查点 SHA-256 绑定、通过 Unix 套接字的有界协议 8 本地 IPC 或受保护的 Windows 命名管道，以及具有精确响应丢失重放功能的耐用 Unix/Windows 短进程 `create/state/start/kill/delete` CLI 适配器 |
|持久的主机服务|精确的创建/状态/启动/终止/删除、驱动程序通告的可选操作（包括不可变检查点和暂停生成恢复编排）、全局幂等性日志（包括文件上传和文件系统 mkdir/移动/删除）、重放、生成防护、启动恢复、启动范围内的跨日志孤儿审计、失败生成隔离、使用 Unix 安装身份防护进行基于功能的状态遍历、提交后重放记录对本地 Linux 和 Apple Silicon HVF 的本地和utility VM驱动程序、排序列表、有序事件以及相同 UID 多容器所有者的确认
|共享Linux执行器|命名空间创建/加入、命名空间条目之前声明的根目录准入、`pivot_root`、具有根相对遗留目标和可选字段处理的有序 OCI 挂载、早期配置或合成挂载后从有效树解析的 rootfs 内部绑定源、分离有序`idmap`/`ridmap` 绑定、无需捐赠者传播的递归私有挂载 rootfs 设备暂存、完整的 OCI 1.3 Linux 挂载选项控制注册表、精确的 init/exec argv、环境、cwd、终端默认值、UID/GID、补充组和 umask、挂载处理后的条件 `/dev/fd`、`/dev/stdin`、`/dev/stdout` 和 `/dev/stderr` 链接、具有失败即关闭私有描述符隔离和精确所有者 pidfd 的 OCI 挂钩进程组监督、用户映射、精确的绝对和稳定的相对 `cgroupsPath` 分辨率以及省略时的私有生成隔离路径、具有显式 cgroup v1 实时拒绝的完整 cgroup v2 CPU 共享/配额/突发/周期/cpuset/空闲映射、精确的内存限制/保留/交换和 PID 创建/更新映射（保留零）和 OCI `-1` 编码为 `max`，有限总交换验证、完整的 cgroup v2 块 I/O 默认/每设备权重和读/写 BPS/IOPS 节流映射，具有零速率清除、键控读回、部分更新保留、反向回滚和显式叶权重拒绝、动态 HugeTLB 使用/保留控制、键控 RDMA HCA 句柄/对象限制、具有动态控制器启用的有界 OCI 1.3 统一控制文件写入、内核定义格式、类型化文件冲突拒绝、可读无操作/回滚快照和只写控制支持、仅类型化拒绝 cgroup v1 内存和网络`net_cls`/`net_prio` 控制、所有五个具有内核回读功能集、精确的`no_new_privileges` 验证、具有精确内核回读的所有 16 个 OCI rlimit 类型、`oomScoreAdj`、调度程序策略、I/O 优先级、精确`LINUX`/`LINUX32` init 个性、所有七种 OCI NUMA 内存策略模式和三个带内核回读的标志、父级拥有的 Intel RDT CLOS、有序模式、进程分配、监控和所有者死亡清理、围绕 cgroup 成员身份应用的 exec CPU 亲和力、具有描述符限制的应用、回读和回滚的事务命名空间 sysctls、精确的根块/字符/FIFO 节点、六个默认设备、`/dev/ptmx`、PTY 支持的`/dev/console`、持久占位符清理、具有有序资源规则缩小的不可变声明/默认设备库存 BPF、seccomp、PID 1 监督、pidfds、exec、进程 I/O、带有 OCI `consoleSize` 初始化的 PTY、有界主机确认的突变重放日志、父级绑定启动/会话帮助程序、PID 启动时间限制的所有者死亡逻辑删除、描述符限制的文件/文件系统会话、暂停/恢复、资源更新、规范化 CPU/内存/PID/块 I/O 统计信息以及合格配置文件的范围清理 |
|实用程序-VM 边界 |独立的 libkrun shim、具有 v1-v9 兼容性的经过身份验证的协议 v10、20 个公共工作负载操作以及一个有界维护确认、克隆范围关闭、精确生成 VM 会话以及静态guest agent背后的相同 Linux 执行器。平台中立的每代一个虚拟机生命周期现在支持公共 HVF 驱动程序和 Linux KVM 候选者，包括捆绑包所有权切换、并发创建防护、重试和终端清理、停止恢复逻辑删除以及有界关闭。持久恢复记录保留在每代共享上，特权 OCI 设备源仅在来宾本地 devtmpfs 上创建并在创建屏障处删除，并且在删除来宾运行时根之前关闭会消耗每个保留的设备目标清单 |
|容器运行时-v2 |仅 SDK `containerd-shim-a3s-oci-v2` 具有针对 `containerd.task.v2.Task` 所有 17 种方法的代码拥有合约、24 条路由转换表（其确切的 18 次操作需要 SDK 联合门端点准入）以及每个驱动程序 `Checkpoint`/`Restore` v1 协商。任务检查点提交经过摘要验证的目录包；检查点支持的 Create 恢复暂停的生成，而 schema-v10 元数据在 shim 替换过程中保留其 CREATED-to-Start 屏障。该填充程序还保留了精确的 2.2.2 arm64 Native Linux 开发资格、2.2.3 x86_64 回归证据以及覆盖所有 23 个重新启动/补液边界的当前三遍 2.2.1 WSL2 观察。保留持久的命名空间/任务/执行身份、可重放任务和`DeleteProcess`收据、排序输入/信号/调整大小/控制日志、有界 FIFO/PTY I/O、精确生成崩溃清理和重新启动恢复。 Schema v9 保持可读性并引入了精确的待更新主体；模式 v1-v8 在其记录的默认值下保持兼容。单元覆盖范围包括包重放和篡改拒绝、恢复意图删除Shim 清理、承诺恢复采用、承诺 init/exec Start 采用、终端信号解决、响应接收重放和无竞争输出游标恢复。没有生产驱动程序宣传检查点或恢复。单独的 rootful Native Linux CRIU 构造函数通告这两种操作，并具有有界的真实内核 v3 检查点/恢复生命周期、响应丢失重放、双边界替换进程恢复以及 PID/网络命名空间拒绝资格； v6 包集成了该门，同时保留了标记包、更广泛的配置、跨驱动程序和多架构资格保持开放。 |
| A3S Box消费者|仅限公共 SDK 生命周期和附件；暂停/继续；进程和文件系统会话；精确的实时库存、标准化统计数据、有界有序事件和重放安全的完整资源更新；显式的 Native Linux Sandbox 生产路由、校验和发布布局安装以及完整的 Rust/Python/TypeScript/Go SDK 在 x86_64 和 aarch64 上传递，`/dev/kvm` 不存在且无法访问，而默认和跨平台切换保持开放 |
|保留证据|架构和规范锁、189 对经过身份验证的协议故障覆盖、便携式九阶段 Create/State/Start/Kill/Delete/Wait/Exec/SignalProcess/WaitProcess/Pause/Resume/Processes/Update/Stats/ReadOutput/WriteStdin/CloseStdin/Resize/File/Filesystem 主机重新打开并提供准确的提交后确认、真正的 HVF 九阶段 Host/Guest Create 加两阶段主机关闭中断和清理，所有九个真正的 HVF 创建、状态、启动、终止、删除、等待、执行、SignalProcess、WaitProcess、暂停、恢复、进程、更新、统计、ReadOutput、WriteStdin、CloseStdin、调整大小、文件和文件系统通过持久服务重新打开和虚拟机/会话所有者替换进行转换，真正的协议 v10 Apple Silicon Guest 启动，具有独特的精确 init/exec 功能的本机 Linux 真实容器， `NoNewPrivs`、rlimit、OOM 分数、I/O 优先级、调度程序、init 个性、init NUMA 内存策略、执行 CPU 亲和性和命名空间 sysctl 读回、无根默认设备和设备策略门、在两个主机重新打开和原子进度计数器之间精确暂停/恢复操作 ID 重放、所有者死亡安全终止、精确`startContainer` Hook 进程组所有者死亡恢复，以及三个连续的同一主机实时 Containerd 2.2 生命周期/重新启动/I/O 矩阵，其中删除了 exec-ID 重用、丢失 `DeleteProcess` 和任务删除响应重放、提交后来宾日志回收和提交的 init-Start、exec-Start、init-Kill、Pause、Resume、Update、WriteStdin、 CloseStdin、SignalProcess 和 ResizePty 垫片替换门、提交后 `WriteStdin` 和 `CloseStdin` 强制清理、新鲜 VM HVF 浸泡、失败即关闭 Linux KVM 生命周期/恢复/25 波浸泡条目以及真正的 x86_64 九阶段Create/State/Start/Kill/Delete/Wait/Exec/SignalProcess/WaitProcess/Pause/Resume/Processes/Update/Stats/ReadOutput/WriteStdin/CloseStdin/Resize/File/Filesystem 所有者替换，以及 WHPX 标称加上所有者死亡/服务重启资格 |

垫片恢复现在可以协调之前的精确运行时`Stopped`记录
重放待处理的初始化信号。如果本地元数据没有出口，则有界
精确生成等待导入运行时的持久退出；信号杂志
然后在没有第二次杀戮的情况下前进。连续三届Ubuntu
2026年8月24日的arm64/containerd 2.2.2矩阵保留了这个终端
通过一个未更改的主机 PID 进行 init-Kill 边界，包括 exit-42 shim 和
容器等待/删除证据和独立的零活性残留审计。

Exec 恢复应用相同的权威退出规则，而不延迟
实时进程：在重放挂起的进程信号之前，它会执行精确的操作
零超时`WaitProcess`。持久退出将执行程序移动到`Exited`，记录
第一个观察时间，并解决未决序列，无需第二个
`SignalProcess`； `DeadlineExceeded` 证明 exec 仍然存在并保留
正常的身份稳定重放路径。

`DeleteProcess` 现在在原子删除之前写入准确的响应收据
来自主垫片元数据的已停止执行。如果 exec 仍留在该 main 中
崩溃后的记录，收据只是一个未承诺的意图和补液
丢弃它。如果执行人员缺席，则替换填充程序会重放收据的
PID、退出状态和纳秒退出时间。耐用的新化身
相同的执行ID清除旧收据，完整任务Delete或DeleteShim删除
杂志。

任务删除现在在分派之前存储`a3s-oci-shim-task-delete-v1.json`
代围栏运行时删除。收据绑定命名空间、任务
化身、容器身份、生成、捆绑、PID、退出状态和
纳秒退出时间。保留主要元数据以及实时运行时生成
标记未承诺的意图并消耗收据；任务删除后，
无元数据替换验证服务名称空间、任务 ID 和
捆绑并返回确切的第一个响应。那个只重放的垫片表明它
响应后退出，所以containerd 2.2.3泄漏清理不能离开
一个无主的替换进程永远等待。

恢复还会将经过验证的任务发布到内存状态之前
启动任何输出泵。因此，立即可重放的输出块可以
将其持久光标提交给恢复的任务，而不是与
缺少状态条目。确定性 FIFO 回归涵盖了该排序，
部分泵启动故障会停止之前创建的每个泵
已发布的任务被回滚。

提交后`WriteStdin`强制清理现在有自己的确切边界。的
gateway 停止主机，直到 schema-v10 元数据保留 exec 化身 1，
挂起的序列 1 和确切的标准输入字节，然后停止填充程序并提交
直接通过公共 SDK 获得相同的`write-stdin-1`身份。执行官
必须从一个输入效果退出 23，同时 init 仍以其原始状态运行
PID 和生成。在 shim `SIGKILL` 之后，DeleteShim 不得重新调度
待处理字节；它消除了确切的运行时生成、工作负载进程，
捆绑包、cgroup 和 shim 状态，同时保留调用者拥有的容器
元数据。

提交后`CloseStdin`强制清理现在具有匹配的精确边界。
当主机停止时，`CloseIO`通过其通告的方式到达任务垫片
ttrpc 端点和 schema-v10 元数据保留 exec 化身 1、stdin 状态
关闭，并且没有待处理的写入。然后垫片停止，主机恢复，并且
直接通过相同的化身绑定`close-stdin-1`身份
公共 SDK。 EOF 使 exec 退出 29，而 init 仍保持运行状态
原始PID和生成。在 shim `SIGKILL` 之后，DeleteShim 不得调度
第二次关闭；它消除了确切的运行时生成、工作负载进程，
捆绑包、cgroup 和 shim 状态，同时保留调用者拥有的容器
元数据。聚焦单元边界从一个记录的运行时关闭开始，
证明清理叶子在隔离 Kill 和强制删除时计数不变
到确切的一代。

提交后`ResizePty`强制清理现在具有自动匹配功能
边界。被忽略的真实容器门创建一个终端执行程序，停止
主机，通过 shim 验证的 ttrpc 端点发送 `ResizePty`，并且
需要 schema-v10 元数据来保留带有挂起序列的 exec 化身 1
1 为 166x52。然后它停止 shim，恢复主机，并提交相同的内容
直接通过公共 SDK 绑定化身`resize-1` 身份。的
门通过 `/proc/<pid>/fd/0` 读取实时 PTY 尺寸，并且
`TIOCGWINSZ`，然后杀死垫片并要求原始响应为
丢失了。 DeleteShim 不得调度第二次调整大小；它只删除确切的
运行时生成、工作负载进程、bundle、cgroup 和 shim 状态
保留调用者拥有的容器元数据。聚焦单元边界开始
通过一个记录的运行时调整大小并证明清理留下的数据
保持不变，同时屏蔽 Kill 并强制删除到确切的一代。

所有非破坏性 CI 目标都通过此门，包括 Linux、musl、
macOS、Windows 和本机 Linux arm64 覆盖范围。源码修订
`2fef85c6e68a07f114d211175b77841301d57985`也通过了三项完整
Ubuntu 24.04.3 LTS/WSL2 x86_64 上的 91.96、91.89 中的 containerd 2.2.1 矩阵
91.92 秒，通过未更改的主机 PID 1566。每次通过都跨越了所有 23 个
守护进程重启和提交后补充边界，包括当前的
强制清理`ResizePty`门。 static-musl CLI、代理、垫片、资格
可执行文件，Cargo.lock SHA-256 值是
`e22a08d884ad59187fce39e170f6ca21d367a77c2d3a1a297cb8650adf6f7561`,
`c73cc2356552de6f2def62598a44fb370df7300a56af5c7be33e63d148b865e2`,
`c4c8ce162cdb0c031eac6e792e2bbdf9c99c30e7ef971ca8791b123f2b4ce00c`,
`ba458b70cb1c879ed78095d326ccfe8992b22f12198728b45cc8d50a52e0451f`,
和`1f00f4ec1b0f1ba9f3e39daf2b8782e42c922d9fa696aaa07c709c38123edca0`。
默认 Containerd 在 PID 184 处保持活动状态。最终审核发现零
任务、容器、实时运行时容器、匹配进程、挂载或
cgroups 在两个孤立的根被移除之前。此源构建 WSL2 记录
仅用于观察，不会推广确切的 containerd 2.2.2 Ubuntu
arm64 开发声明；确切的发布包范围资格和
其余 R7 释放门保持打开状态。

源码修订`9726719e5a66156cd61f8be36ca00998bbcfc871`通过三项
连续完成 Ubuntu 24.04 x86_64/containerd 2.2.3 矩阵
117.37、119.36 和 118.94 秒到未更改的主机 PID 2678296。
发布 CLI、代理、填充程序、资格可执行文件和 Cargo.lock SHA-256
值为
`80d0b69686c73516fc3a507f2545af77b405918584176bdb0a96ab3bcf067102`,
`68219e592a061b9dba7f491d54716354195cd8f8005fa792ab367681dda5352e`,
`99bacac7a308e4830ca55101ef8148a511526722cf9006d8a37ef9cba89dbf50`,
`3e752abc8ada3b8e3dae9d86e370feb7d17bf04c2245f13888d52ba7537b2fd2`,
和`c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`。
该套件使用专用的私有 Containerd 根、状态、套接字和 systemd
单位；生产容器始终保持活跃状态​​，PID 为 2485480。
探测和每次通过后的独立审核都发现零匹配任务，
容器、捆绑包、实时运行时记录、cgroup、快照、shim 进程、
资格流程或工作负载流程。

源码改版`a3865075d8ced661447a85196e17136379535fa7`通过三项
连续完成 Ubuntu 24.04 x86_64/containerd 2.2.3 矩阵
89.96、93.40 和 94.55 秒至未更改的主机 PID 2504484。
发布 CLI、代理、填充程序、资格可执行文件和 Cargo.lock SHA-256
值为
`80d0b69686c73516fc3a507f2545af77b405918584176bdb0a96ab3bcf067102`,
`68219e592a061b9dba7f491d54716354195cd8f8005fa792ab367681dda5352e`,
`ca14a7d28f3b95656b831006c22e2e88561c272a19c48aab19b43d6592ca652c`,
`c560b1d92d4e786a026fd2c8002bcb0330c06d620304a08c5df4951ebdaf9ce4`,
和`c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`。
该套件使用专用的私有 Containerd 根、状态、套接字和 systemd
单位；生产容器始终保持活跃状态​​，PID 为 2485480。
每次通过后的独立审核发现零匹配的任务、容器、
捆绑包、实时运行时记录、cgroup、安装、shim 进程、代理或主机
儿童、资格流程、僵尸或准备好的操作。

源码修改`5a6d5f2d817d5951929c2394dff57ef925dd5822`通过三项
在 65.15 中连续完成 Ubuntu arm64/containerd 2.2.2 矩阵，
66.76 和 64.11 秒，通过未更改的主机 PID 436920。
主机、代理、填充程序、资格可执行文件和 Cargo.lock SHA-256 值是
`53bf14d72adb347b35d19f936bf91d15adcc3cce65aa88f63886746f07f5ddb2`,
`28dad74972b28b400a9e5e9f9b38ba59aeaf6662532dfefc7dd5527ff17d6b48`,
`801c6ebd6bb6a41f1049dbd64d6ae60165a0914254edb953b2eaf633c6c368f2`,
`fa3a513bf2f5aba01a511bc953dcfc5cb1bb05080fbd58bb993d9a0a44a10363`,
和`c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`。
每一遍都保留精确的序列-1 SIGTERM，正常执行退出 29，
replacement-shim 和 restarted-containerd 等等证据，第一个和
重放`DeleteProcess` PID、状态和退出时间戳，以及原始的
运行 init PID。每次通过后的独立审核发现零匹配
任务、容器、捆绑包、cgroup、安装、实时运行时记录、垫片、
代理、资格或主机子进程和零僵尸或已准备好
操作。原始安装的垫片已在 SHA-256 处恢复
`a0e7dce493308ebea0b4642dd81a9e489109a8b3709f2a1ede62b015cc123482`；
测试运行时根、发布目标、签出和日志已被删除。

OCI 1.3 `linux.netDevices` 由共享 Linux 执行器实现。的
运行时验证有界确定性移动计划，需要单独的
网络命名空间，拒绝精确的目标名称冲突，支持附加
`%d`模板，保留稳定的链接属性和永久全局
地址，并将每个移动的接口启动。失败的创建会提前滚动
以相反的顺序向后移动；回滚租约仅在以下时间后释放
创建的状态是持久提交的。无根执行拒绝请求
在突变之前，因为当前的助手合约没有授予宿主
网络设备权限。 Native Linux gateway 使用真正的虚拟接口来
练习移动、重命名、地址/MTU/MAC 保留、目标冲突、部分
回滚、无根拒绝和清理。

rootful public `a3s.oci.attachments.v3` 配置文件添加了不可变的调用者发布
围绕该 OCI 机制的命名空间、接口和清理标识。它
需要精确的目标接口名称而不是`%d`，绑定所有三个
将身份识别为持久的重放证据，并区分运行时创建的
从保留已加入的调用者命名空间中释放命名空间。它从来没有
接收或决定 IPAM、DNS、路由、别名或网络策略。

所需的 `dev.a3s.network.enforcement@1` 扩展添加了一个不透明的，
生成和 SHA-256 绑定的调用者强制身份加上可选的
节点本地重定向身份到一个精确加入的调用者命名空间。它关闭了
架构不能携带主机名/IP 规则、路由、端点、凭据、租户
元数据，或政策决定。 Host自主协商，通过
对驾驶员没有改变，并在之后重新验证确切的`ContainerRecord`证据
重新启动。 Rootful Native Linux 现在仅在有网络时才公布版本 1
设备权限；它的真实主机门保留命名空间/接口身份，
重定向/拒绝行为、主机重新打开重放和调用者拥有的机制
保存。 Rootless Native Linux 和 VM 驱动程序不会对其对外声明。

暂停和恢复保持单独协商的运行时操作，具有稳定的
`OperationContext` 身份、精确生成的击剑、持久重放以及
重新启动对账。他们的承诺`ContainerPaused`和
`ContainerResumed` 观察现在通过类型化揭示了确切的突变
`RuntimeEvent::operation_id`；主机根据持久性验证它
事件声明和旧版 `operation-id` 属性。较旧的事件 v1 记录
如果没有类型化投影，则通过该经过验证的属性仍然可读。
本机 Linux 浸泡模式 v2 现在保留每个暂停和恢复操作 ID，
在单独的主机服务重新打开后重放每个提交的响应，并且
记录原子工作负载计数器，证明在暂停和更新时没有任何进展
恢复和第二次重新开放后的进展。标记包资格 v4
将此 OAR-02 证据绑定到确切的分阶段运行时和代理工件。
运行时不会决定工作负载何时空闲或应该唤醒；呼叫者拥有
该政策并发布明确的操作。

公共`a3s.oci.attachments.v4`配置文件建立了可重用的
访客会话边界。 SharedGuestKernel 创建或恢复必须绑定一个
逻辑会话ID、积极化身、不可变信任域、容量
从 1 到 64，运行时所有权，以及显式的空销毁或
相同信任域保留模式。协议 7 且耐用 `ContainerRecord`
证据围栏降级、重启和操作 ID 重用。共享HVF/KVM
驱动程序核心实现会话范围的共享和所有权标记，序列化
准入、容量和生成防护，两种重置模式、成员本地
故障清理、竞争安全并行会话回收、会话恢复
报告和一业主关闭。生产
HVF、KVM 和 WHPX 注册继续仅宣传其合格的
附件配置文件，直到相应的真实主机重新启动、清理和
保留浸泡证据，并且它们的累积存储/网络传输
已实施。

会话准入在所有者更换后也无法关闭：持久的
`.guest-sessions/<id>/` root 不能被视为没有空池
进程内所有者或主动切换准入，因此第二个虚拟机无法静默
当先前的虚拟机可能仍然存在时，重用逻辑标识。

OCI 1.3 `linux.resources.hugepageLimits` 也由共享实现
执行人。 SDK 保留了完整的规范`uint64` 范围，而
执行器根据实时 cgroup-v2 验证每个规范页面大小名称
库存，仅在请求时启用`hugetlb`，并应用使用和
当内核公开预留记帐时，预留限制。创建并
实时更新使用具有读回和反向回滚功能的内核可表示值；
部分更新使省略的页面大小保持不变。在`control-workload-v1`中，
HugeTLB 仍然是一个精确的仅工作负载限制，而不是被复制到
管理信封。 Native Linux CI 读取选定的主机页面大小控件
每当运行程序暴露 `hugetlb` 时，就会返回 x86_64 和 aarch64。

OCI 1.3 `linux.resources.rdma` 作为单独的密钥 cgroup-v2 实现
控制器。每个设备可能会限制 HCA 句柄、HCA 对象或两者；装置
在设备策略突变之前检查名称和可用的内核条目。
创建和实时更新保留省略的字段，标准化内核的签名
计数器上限为`max`，读回每个有效值，并滚动应用
设备以相反的顺序返回。仅在请求时才需要 RDMA，并且保持不变
`control-workload-v1` 中仅工作负载。本机 Linux 资格读取
当运行者公开控制器和工作负载时，控制和工作负载条目会返回
可用的 InfiniBand 设备。

OCI 1.3 `linux.resources.unified` 接受有界 cgroup-v2 控制文件映射。
执行器验证每个密钥一个安全文件名，拒绝运行时拥有的
`cgroup.*` 类型化 OCI 资源已拥有的状态和文件，保留
稳定的写入顺序，并通过运行时携带未知的控制器名称
实时内核库存。在创建叶子之前启用所需的控制器；
控制器不存在或无法启用、控制文件丢失或不可写
控制在设备策略突变之前返回一个类型错误。创建和更新
以稳定的顺序写入每个值，而不强加通用的读回格式。
更新使用可读控件进行无操作抑制和反向回滚，而
只写控件仍然有效。 `control-workload-v1` 仅适用于
工作负载叶；原生 Linux 资格均来自于 `memory.high`
子级，在可能的情况下验证内核规范化的部分 `io.max` 写入，并且
练习有根和委托无根实时更新。

当前位于 `A3S-Lab/Box@a16772c3` 的 Box 适配器会重新检查每次读取
确切的运行时绑定。文件上传/下载和文件系统
stat/mkdir/move/list/remove 现在使用相同的跨平台会话外观；
能力和盒子生成检查发生在调度、响应目标之前
并且形状被重新验证，并且一种明确可重试的突变响应是
使用相同的上下文和一个运行时效果重放。部分产品
资源请求被编译成一个完整的 OCI `LinuxResources` 合约，
在调度之前持久声明，并使用相同的运行时操作重放
失去回应后。运行时确认更新 Box 重启意图
原子地而不改变原始的创建身份。

新的突变记录使用`a3s.oci.operation.v6`。版本 3 文件上传和
文件系统 mkdir/move/remove 保持可读；版本4还保留了
每个精确的检查点请求和类型化的不可变响应；版本 5 添加了
准确的恢复请求、分配的生成和暂停运行响应；和
版本 6 保留了每个确切的 TEE 证明挑战和不可变的证据
回应。版本 1 到 5 对于它们编码的操作仍然是可读的。
主机在确认驱动程序重放之前提交日志结果
证据，因此断开连接会返回可重试的错误，并且下一个所有者会重放
主机结果，无需再次调度突变。主持人杂志
在驱动程序证据被删除后，仍然是永久的更改请求围栏
释放。

持久状态现在将其规范根固定为目录功能。全部
后代读取、枚举、创建、替换和隔离移动是
从保留的目录句柄解析。 macOS、Linux 和 Windows 门证明
环境根重命名、布局或事务符号链接/重解析点
替换、外部文件系统句柄、同一设备 Linux 绑定挂载
替换，或赛车 Windows 文件/目录目标替换不能
重定向突变。 Windows 提交每个已经开源的相对对象
到保留的目标父句柄并通过该句柄应用文件 DACL
相同的打开对象。文件替换仅容忍有限的瞬态 Windows
目标共享锁。递归审核提交的开店情况
生成、操作、活动容器、过程、隔离和事件
驾驶员恢复或请求服务之前的关系，同时保留
幂等崩溃重放所需的显式中间状态。

确切的containerd API、身份、安装、重新启动、清理和
资格边界记录在
[containerd Runtime V2](docs/containerd-runtime-v2.md)。

合约 v1 冻结运行时类型`io.containerd.a3s-oci.v2`，任务服务
`containerd.task.v2.Task`，以及 Linux 归档条目
`containerd-shim-a3s-oci-v2`。将该条目安装为
`/usr/local/bin/containerd-shim-a3s-oci-v2`。命名空间和任务 ID 使用
`sha256-length-framed-u64be-v1`编码产生稳定的SDK容器ID；
Host 分配 Create 返回的单调运行时生成，并且
shim 会持续存在并在以后的每个请求中处理该确切的代。
相同的代码拥有的表将每个任务分支和 FIFO 泵映射到其公共表
SDK操作。 RuntimeInfo 将确切的 18 操作联合发布为
`dev.a3s.oci.containerd-sdk-operations`；垫片拒绝端点丢失
任何成员，其crate清单经过测试以保留 A3S Box 和驱动程序
在此适配器边界之外的实现。
有界进程 I/O 路径每个 shim 步骤最多读取和写入 64 KiB，
将非终端 stdout 和 stderr 分开，并合并终端输出
PTY 流。每个内核接受的 FIFO 前缀都会推进持久字节
光标在下一次写入之前，因此取消永远不会提交未写入的内容
后缀和替换恢复不会丢失。

创建恢复覆盖远程提交边界的两侧。垫片
保留完整的包、隔离、I/O、rootfs 所有权、任务
化身，派遣前稳定的操作身份。真正的过错
门可以在调度之前停止主机，在该意图之后停止垫片
持久，直接通过公共 SDK 提交确切的 Create，并杀死
在完整元数据存在之前填充。 DeleteShim必须加入那一代，
删除其确切的进程、运行时状态、rootfs 和包，并保留
调用者拥有的containerd元数据；重复生成或驱动程序重新路由
留下确切的证据并未能通过大门。

Box 的确切版本还验证了其管理主页，为
快照较低，命名卷和网络，编译产品拥有的OCI
捆绑包，并启动或重用此运行时的身份防护长寿命 Native
Linux 所有者。它阻止 x86_64 和 aarch64 Linux 通道驱动 Rust、Python、
TypeScript 和 Go Sandbox 生命周期、exec、文件系统、路由感知统计信息、
通过显式暂停/恢复、快照恢复、重新启动和清理
生产路线。

框完成度和运行时准备度衡量不同的范围。盒子可以完成
针对合格的运行时切片的当前产品契约；这个存储库
仍然拥有所有 20 个公共工作负载运营、每个广告驱动程序、所有者更换
语义、OCI 一致性和发布资格。一个完整的消费者是
因此，这并不能证明较低级别的运行时已完成。

Linux 文件和文件系统调用在继承的新内部帮助程序中执行
仅保留确切的根、用户命名空间和挂载命名空间描述符。
帮助器验证其父级，拒绝重复或重新排序的描述符，
在挂载命名空间之前输入用户命名空间，然后执行
有界`openat2`操作。因此，容器 ID 在
rootfs、绑定挂载、ID 映射挂载和容器创建的 tmpfs 文件系统。

完整的发布目标是每个适用的 OCI 运行时规范
1.3.0 对 Linux 容器和每个广告驱动程序的要求 — 不是
减少了仅 A3S 的配置文件。 [ROADMAP.md](ROADMAP.md) 保留完整的证据并
分开打开释放门。

能力集执行保持精确，并且对于每个值都是失败即关闭的
运行时可以授予。当正在运行的内核或执行器继承时
权限无法授予认可的请求功能，init 和 exec 删除
仅对不可用的集成员身份发送有界结构化警告
交叉执行之前的监督代理。格式错误或重复的警告
框架无法关闭，而不是成为不受信任的日志文本。

Linux sysctls 现在遵循相同的失败即关闭边界。 SDK只接受
OCI 点或斜杠中的已知 IPC、网络、UTS 域和用户命名空间控制
符号。执行器拒绝主机全局控制和同主机命名空间
连接，通过保留的 procfs 应用有界确定性事务，
验证每个值，如果 Create 未提交，则恢复较早的值。

Intel RDT 由运行时命名空间父级而不是容器拥有
初始化进程。当 `linux.intelRdt` 存在时，父级会找到已安装的
resctrl 文件系统，准备或验证请求的 CLOS，应用
按 OCI 顺序`l3CacheSchema`、`memBwSchema` 和完整的`schemata`，读取
返回有效值，并在运行前分配经过身份验证的 init PID
钩子运行。专用监控组和运行时创建的 CLOS 目录
在删除、关闭、创建失败或本机所有者死亡恢复时删除。
显式和根 CLOS 目录仍属于外部所有。

## 运行时契约

### 创建和开始保持分开

```text
creating ── create committed ──▶ created
created  ── start committed  ──▶ running
running  ── init terminated  ──▶ stopped
```

`create` 验证并准备请求的边界而不执行
`process.args`。只有`start`释放配置的进程。无效
如果没有削弱这一障碍，转型就会失败。

每个耐用容器记录保留：

- 确切的经过验证的配置和摘要；
- 完整的`a3s.oci.attachments.v1`、存储感知 v2、网络感知 v3 或
  guest-session-aware v4 清单及其新创建记录的摘要；
- 使用共享来宾内核时的确切可重用来宾会话化身
  隔离；
- 单调增加的运行时生成；
- 运行时选择的驱动程序和有效的隔离；
- 主动操作意图和终端回放结果；
- 观察到的确切的 init 和 exec-process 退出状态；
- 中断突变的恢复或隔离状态。

匹配重试会重现原始结果。陈旧的一代，重用
具有不同有效负载的操作 ID、不支持的 OCI 字段、不可用
隔离类，或更改记录的驱动程序在突变之前失败。

### 隔离是一个要求，而不是驱动程序名称

|请求 |边界|内核分享 |
| ---| ---| ---|
| `DedicatedVm` |硬件实用程序VM |一个工作负载或 Pod 拥有来宾内核 |
| `SharedGuestKernel` |硬件实用程序VM |一个已声明的信任域共享一个来宾内核 |
| `SharedHostKernel` |原生 Linux |容器共享主机内核 |

`SharedGuestKernel` 请求必须携带 `a3s.oci.attachments.v4` 绑定
一种精确的访客会话化身。这是持久的身份和权威
当前注册的实用程序 VM 驱动程序提供的证据，而不是声明
汇集；能力协商仍然拒绝 v4，直到该驱动程序通告
架构。

调用者请求隔离类。运行时选择一个启动就绪的
该类别的所有者，保留选定的驱动程序，并稍后路由
即使在司机重新开放服务后，操作也会返回到确切的所有者
以不同的顺序注册。它永远不会改变历史状态或下降
从虚拟机边界返回主机内核。

### SDK是执行边界

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

`RuntimeClient` 可以包装进程内服务或通过有界本地连接
工控机。报告本地流损坏，没有隐藏重放；下一个明确的
请求重新连接并重新协商，以便调用者可以重试或协调
原始操作标识。前台`run`只是一个客户端组合
持久的创建/启动/等待/删除调用；它不会创建第二个
生命周期 API 或状态机。

在 Linux 上，明确的实验主机所有者发布了一个持久的 SDK
不打开KVM的端点：

```bash
a3s-oci native-linux-host-service \
  --root /run/a3s/oci-native \
  --agent /usr/libexec/a3s-oci-agent
```

所有者在发布之前打开 Native Linux 驱动程序和持久状态
`runtime.sock`，为独立的围栏容器代提供服务
经过身份验证的相同 UID 客户端，并在优雅的情况下获取驱动程序拥有的进程
关闭。 Box显式`A3S_BOX_OCI_MIGRATION=sandbox`生产路线使用
这位业主。现有的`native-linux-service`命令仍然是
沙盒范围内的 FD 3/4/5 所有者，用于兼容性和重点资格认证。

在 Apple Silicon 上，公共 HVF 所有者公开了相同的 SDK 合约，同时
将持久状态与每代虚拟机状态分开：

```bash
a3s-oci macos-hvf-host-service \
  --root "$HOME/Library/Application Support/A3S/oci-hvf" \
  --shim /absolute/path/to/a3s-oci-krun-shim \
  --system-image-manifest /absolute/path/to/system-image.json
```

它准备一个仅所有者的`0700`根，发布相同的UID`0600`
`runtime.sock`，接受并发客户端，并且仅删除套接字 inode
它创造了。该服务公布所有 20 个 HVF 驱动程序操作以及
`features`、`list` 和 `events`，需要运行时捆绑切换
扩展，并在正常关闭时获取每个实时专用虚拟机。高压真空炉
司机只做广告`DedicatedVm`；未实现共享来宾池。

运行时契约套件还跨两个不同的操作系统重新启动所有者
同一 Unix 套接字或 Windows 命名管道上的进程。更换开启
相同的持久`HostRuntimeService`状态，同时一个保留的客户端恢复
确切的生成和实时执行目标，重放创建/启动/执行而无需
重复测试驱动程序调度，并继续库存、标准输入、信号、等待，
输出和清理。这证明了通用过程和传输边界，
不是本机 Linux 或实用程序虚拟机在真实硬件上的重新连接。

真正的 Native Linux 门现在跨越了与实际的进程边界
司机。启动器在分叉命名空间子级之前是父级死亡绑定的；
在所有者`SIGKILL`之后，替换过程会重新验证不可变的
配置加上所有者/启动器/init 启动时间身份，等待
确切的工作量消失，并暴露出已停止的清理墓碑。它从来没有
声称直播流已重新连接或在没有出现时伪造退出代码
经过身份验证的父母幸存下来并收获了它。幂等杀，清空库存，
明确缺少退出证据、仅停止删除和执行程序/cgroup
清理工作在 x86_64 和 aarch64 上进行机器检查。实时流程会话
对于 Box B2 切换，重新连接仍然保持开放状态。

## 平台状态

|主机路径 |保留真实证据|当前准备就绪并敞开大门|
| ---| ---| ---|
|原生 Linux x86_64/aarch64 |有根和助手支持的无根生命周期，包括所有六个 OCI 默认设备、`/dev/ptmx`、配置初始化`/dev/console`、`/dev` 外部的显式 FIFO、不可变声明/默认设备边界以及有界 A3S Box 设备策略； SDK服务传输；执行/PTY/I/O； init/exec 调度程序和命名空间-sysctl 回读； cgroup 更新/统计信息；钩子；命名空间和挂载配置文件；多集装箱围栏；故障清理；所有者-`SIGKILL`安全终止并停止清理；精确`startContainer` Hook所有者-死亡进程-组清理和替换恢复； 25波×4个容器； x86_64/aarch64 通过所有四个 SDK 安装了 Box 生产所有者组成，`/dev/kvm` 不存在且无法访问，加上新鲜的 Box 进程所有者死亡/重启门 |默认库存`probe-only`；明确打开开发驱动程序`experimental`。实时会话重新连接、默认切换、生产安全性和 OCI 一致性仍然存在 |
| Linux KVM 实用程序虚拟机 |独立的设备/访问/ioctl/API版本探针；确定性 x86_64 和 AArch64 运行时存档和不可变的 ext4 根；精确的 libkrun、固件、导出的内核和静态 Guest Agent 兼容性集；描述符固定的只读根附件；隔离的创建/配置/根/plain-vsock/释放上下文门；一个隔离的真实进入工作线程，具有描述符固定的 KVM 和运行时共享检查、父工作线程设备/inode 身份绑定、pidfd 所有者死亡、内核验证的 Unix 对等身份、协议 v10 协商以及 KVM 不可用时的失败即关闭清理证据。两个架构通道均保留 14 种预进入兼容性漂移矩阵，并调用 KVM 门控的 17 种生命周期矩阵。其版本化的十例来宾路径隔离条目检查遍历、符号链接和魔术链接转义；重点回归还会在描述符验证后交换包、rootfs 和绑定源条目。这些通道还调用作用域所有者死亡/重启门、作用域 25 波新生代浸泡以及九阶段创建、状态、启动、终止、删除、等待、执行、SignalProcess、WaitProcess、暂停、恢复、进程、更新、统计、ReadOutput、WriteStdin、CloseStdin、调整大小、文件和文件系统所有者替换门。 virtiofs 运行时共享上的来宾持久所有权遵循共享根主机 UID，而不是来宾 `geteuid()`，因此非根主机服务可以保留恢复记录和设备目标清单。在创建来宾可见的代共享之前，独立于 KVM 的驱动程序预检会拒绝共享内核类、不精确的代、丢失切换所有权以及丢失、链接、非私有、漂移、转义 rootfs 或绝对绑定切换。浸泡审核生成屏蔽和重放以及每波进程、标记、端点、描述符、捆绑切换、运行时共享、恢复报告和配置的 Guest `cgroupsPath` 生命周期。公开候选人在每一代拥有一个虚拟机，拒绝主机内核回退，将引导程序和可写共享分开，并且保持不可注册| `probe-only`； 2026 年 9 月 8 日在`e71a995`/`a35703c` 的裸机 x86_64 观察保留了生命周期、恢复、180/180 操作阶段重新打开路径以及短 `RUNNER_TEMP` 的 25/25 浸泡。早期的干净修订保留文件/文件系统 9/9（`fa4c593`）和之前的生命周期/浸泡行。 AArch64 仍悬而未决，主机关闭和升级所需的单独真实条目负隔离配置文件也是如此。
| macOS arm64/HVF |公共相同UID SDK主机服务；每一代有一个专用虚拟机；清单绑定的不可变 ext4 系统映像，具有固定的 A3S Linux 内核和代理；只读根磁盘加上单独的相同 UID 模式-0700 可写运行时共享，通过保留的 no-follow 目录句柄和父到工作程序设备/inode 身份绑定固定；特权 OCI 设备节点的来宾本地 devtmpfs 源；真正的 v10 协议桥接器，具有所有 21 个来宾操作；保留完整的协议 v9 生命周期、多容器、命名空间/根文件系统强制、3 个不可删除清理点、11 个传输故障点、180/180 工作负载操作替换路径、负资产/身份验证门和 25 个新 VM 波；源修订版 `a5a6b53` 在所有 20 个驱动程序操作中通过了修订版绑定的公共路径门，加上 `features`/`list`/`events`、主机服务 `SIGKILL` 恢复以及零瞬态泄漏的单独 25/25 新虚拟机浸泡 | Apple Silicon 上的`experimental`。当前公布的每个公共 macOS/HVF 功能均已实现，并且协议 v10 公共路径在记录的修订版中合格。版本化的十案例访客路径隔离配置文件已实现完整且 CI 连线；更新版本中的第一个 `available` 工件仍在等待中。签署的发布包资格、OCI 一致性、安全审查、升级/回滚兼容性以及更长的发布时间保留在 `supported` 之前
| Windows x86_64/WHPX |真正的分区/上下文/来宾门、协议 v9 生命周期和文件系统会话、直接驱动程序资格、受保护的每代共享、精确退出重放、两个恢复故障边界处的所有者死亡、主机服务重新打开、仅停止删除以及完整的瞬时清理。当前的实现还构建了一个可重现的 x86_64 ext4 系统映像，固定 Linux 6.12.91 和所有本机启动资产，附加只读根目录，并保持运行时共享独立。现有主机证据现在涵盖了 20 个工作负载操作中的所有 180/180 个操作阶段替换路径，以及一个独立的同进程 8 周期句柄回收门，具有精确的 115 个冷句柄、122 个基线句柄和 122 个最终句柄 | `probe-only`；完整的 SDK/恢复/负/浸泡矩阵仍必须通过新配置的 WHPX 主机上的这些确切资产。 v7 shim 和主机保留 v6 进程内处理恢复契约，但新主机发布大门仍然打开 |

Windows WHPX 来宾切换现在带有显式 `windows-virtiofs-acl-v1`
元数据选择器。 Linux Guest 仅标准化 virtio-fs 的已知合成
`0755`/`0644`通过其私有`0700`/`0600`切换合约
打开的描述符；受保护的 Windows DACL 仍然具有权威性，并且所有
其他模式失败关闭。此兼容性路径不会改变
`probe-only` 准备就绪或出色的新主机释放门。
提交的修订版`9d1639a`通过了完整的本地WHPX配置文件
（56/56 个样本）、直接驱动门和所有者死亡/重新打开门
源匹配的不可变图像；新主机的发布门仍然是明确的。

2026 年 9 月 6 日至 7 日的当前主办方运营资格延长至
每个工作负载操作的证据。 Windows 10 Pro 上的七次有界运行
23H2 (AMD64) 通过了 180/180 个操作阶段案例（20 个操作 x 9 保留
故障阶段），包括时钟调整的统计替换情况；全部
报告保留了预期的所有者/故障交叉、不可变的资产哈希值，以及
完成进程/共享清理。独立者
`a3s.oci.windows-whpx-handle-reclamation-run.v1`门也过了八
具有 `115 -> 122 -> 122` 冷/基线/最终句柄的同一进程 VM 周期，
最终增量为零，并恢复了运行时份额。这些是现有主机
观察，并且不要关闭新配置的发布主机门。

2026年9月7日，合并实施还通过了完整的当前-
主机`a3s.oci.windows-whpx-soak.v2`运行：25/25串口，3/3多容器，
3/3 生命周期故障、6/6 并行、5/5 工作负载、10/10 类型否定以及
4/4 所有者杀死案例，经过验证和最终流程清理通过。
这仍然是现有的宿主证据；新主晋级门依旧
明确的。

相同的合并当前主机运行通过了独立的直接驱动程序和
所有者死亡/服务恢复门，包括精确的退出重放，以及恢复
故障边界、服务重新打开、仅停止删除和完全清理。
这些观察结果不会促使 WHPX 超出`probe-only`。

Windows WHPX 来宾切换现在带有显式 `windows-virtiofs-acl-v1`
元数据选择器。 Linux Guest 仅标准化 virtio-fs 的已知合成
`0755`/`0644` 模式通过其私有 `0700`/`0600` 切换合约
打开的描述符；受保护的 Windows DACL 仍然具有权威性，并且所有
其他模式失败关闭。此兼容性路径不会改变
`probe-only` 准备就绪或出色的新主机释放门。
提交的修订版`9d1639a`通过了完整的本地WHPX配置文件
（56/56 个样本）、直接驱动门和所有者死亡/重新打开门
源匹配的不可变图像；新主机的发布门仍然是明确的。

对于 Unix 实用程序-VM 工作线程，父节点到工作线程的设备/inode 切换绑定
确切的世代共享目录及其所需的 `run/` 状态子目录；
隐藏的工作命令拒绝不完整的身份对。

全部保留Linux KVM入门、兼容性、生命周期、恢复、
操作重新打开，并且浸泡工件带有共享来源合约
如下所述。这消除了工件身份的模糊性；它没有
用不可用的运行程序输出来代替成功的真实 KVM 证据。

当 `/dev/kvm` 存在时，Linux 发现和 Native Linux 开发必须有效
missing or unusable. KVM 是一个可选的实用程序 VM 驱动程序，而不是先决条件
用于主机内核执行。 Box main commit
`d6861de302e6e165a2fdc473b2d399bb0692048e` 保留已安装的产品
boundary in
[CI run 33497670646](https://github.com/A3S-Lab/Box/actions/runs/33497670646)
在 x86_64 和 aarch64 上针对运行时提交
`438e4b7936cd08d408160fe9341a21786f60cd26`.

2026 年 8 月 15 日，一次重点关注的 Apple Silicon 重放通过了所有 14 个期刊
`guest-after-response-write` 提交后 Guest 的突变案例
确认。文件和文件系统也通过了完整的九个阶段
重新打开和真实所有者替换矩阵，总共 18/18 条路径。使用的运行
代理 SHA-256
`eea01813858f5dd16bed70cbfba87221da6daebb4201b7a628665aad3f615a7d`
和系统映像 SHA-256
`e888c52e35ba8ed8f747d55bdc32316190dc317865e6919014e434a1e644e6ef`。

最新WHPX所有者死亡之门出炉
`a3s.oci.whpx-recovery-smoke-run.v1` 来自干净的运行时提交`2d91cd0`。
这将关闭服务重新启动证据项。不可变图像代码和
资格神器现在已经存在，但他们还没有生产出
宣传公共候选人所需的新主持人矩阵。当前的垫片
还在 libkrun 上下文之前记录其 Windows 句柄清单
创建和VM退出后；主机验证和硬件浸泡拒绝任何
漂移。在新主机矩阵出现之前，这仍然是实施证据
保留每个会话中的匹配计数。

2026 年 9 月 3 日当前主赛资格新增真主观察
不改变这些准备状态分类。在 x86_64 WSL2 上，固定
Linux KVM 资产通过入门，14/14 兼容性漂移案例，17/17
生命周期案例、所有者死亡/重启、25/25 浸泡波和 162/162 操作
替换路径。 clean Runtime 修订版的 9 月 3 日后续活动
`fa4c593`添加了真正的文件和文件系统所有者替换，通过了9/9阶段
对于具有不可变资产来源的每个操作（18/18 附加路径）
和零残留。在现有的 Windows 10 x86_64 主机上，固定的 WHPX
资产通过了 56/56 生命周期、多容器、故障、工作负载、负面和
所有者杀死样本，所有 51 个虚拟机句柄库存均已恢复。这些结果
明确仅观察：广告中两者的新宿主证据
体系结构、剩余的 WHPX/KVM 操作阶段和关闭边界，并签署
升级之前仍然需要发布工件。随后的运行从
合并运行时提交`bf43388dc1a5630f3fbbd699203877cf84f1ee2d`重复了
WHPX 56/56 浸泡、直接驱动和服务恢复门
源匹配的不可变图像；所有 51 个虚拟机句柄库存均已恢复并且
主机进程库存返回零。它仍然只是观察
现有主机，因此不会关闭新配置的发布主机
或操作阶段门。

同一天还保留了一个发布配置文件 Native Linux/containerd
来自来源`878f8414cef3b85bef1b51fe6735017b25828252`的观察：三
连续隔离的containerd 2.2.1矩阵（96.42/96.17/95.31秒）
通过了所有 23 个重启、补水和静态强制清理边界
musl CLI/Agent/shim 工件。保留默认的containerd和Host Service
在其原始 PID 上，运行后审计发现没有任务、捆绑包、进程、
mount、cgroup 或运行时残留。它被记录为仅观察，因为
它使用 WSL2 上的源构建工件；它不宣传广告
容器或驱动程序声明。

源修订版的重启边界后续
`fa9393d473c2f2305ce8f7ec67054acea7ea54a0` 重复相同的隔离
containerd 2.2.1 WSL2 x86_64 资格在 96.53、96.63 和 3 次
96.59 秒。该资格现在记录一个由代码执行的有序分类账
对于所有 23 个重新启动、垫片补水和强制清理边界；每个
通完成准确盘点。静态 musl CLI、代理、垫片和
资格工件加上匹配的 Cargo.lock 摘要保留在
`compat/containerd-runtime-v2.json`。默认的containerd保持在PID 180，
最终审计发现任务、容器、捆绑包、运行时记录为零，
专用根和单元之前的 shim/工作负载进程、挂载或 cgroup
被删除。这仍然是 WSL2 的仅观察来源构建证据，
不关闭跨驱动程序或签名的发布包大门。

当前打包的资格使用源修订版
`af8c5f97ac1f4eb506b32e8d57b3d1c0d5fb3645` 并通过以下方式行使
分阶段 static-musl 包
`a3s-oci-runtime-v0.2.0-linux-x86_64`。三个隔离的containerd 2.2.1 WSL2
x86_64 矩阵在所有 23 个矩阵中用时 95.09/95.25/114.44 秒完成
重新启动、垫片补水和强制清理边界。包裹报告
和可执行摘要（包括报告 SHA-256
`d87aa3ff3cd58843d57f51b75b91ca6d05c880f043d24477789105dfc065ba86`) 是
保留在`compat/containerd-runtime-v2.json`；
运行仍然只是观察，因为它不是签名发布的
存档并且不扩展跨驱动程序支持声明。

2026年9月6日，清洁电流-主改版
`7e14370f02f4187ac0fc3ecb979ad14421bfab92`也通过了固定的x86_64 Linux
KVM 输入、探针后失败即关闭、14 例兼容性漂移、17 例
WSL2 上的生命周期、所有者死亡/服务重启和 25 波浸泡门。全部
报告恢复了它们的端点、进程、描述符、VM、运行时共享和
状态根基线。这是仅观察到的证据； AArch64，新鲜主机
促销、主机关闭和签名发布大门仍然开放。

同样的current-main源码也通过了Linux KVM File and Filesystem
所有者替换矩阵，每个 9/9 主机/访客阶段（18/18 路径），其中
完整的清理和不可变的资产来源。这些是x86_64观察
文物；新的 AArch64 运行阶段证据和升级门仍然存在
打开。

2026年9月8日，清洁当前-主要修订
`e71a995`（virtiofs 持久所有者修复）和后续合并 `a35703c` 保留了
Zorin OS 18.1 (`Linux 7.0.0-31-generic`) 上的裸机 x86_64 观察
真正的`/dev/kvm`。非根主机 virtiofs 共享将持久文件存储在
主机服务UID；guest agent所有权检查
`/run/a3s-oci-runtime` 现在跟随运行时共享根所有者而不是
`geteuid()`。具有`RUNNER_TEMP=/tmp`和源匹配的不可变系统
图像，主机通过了Linux KVM生命周期，所有者死亡/恢复，全部二十
操作阶段重新打开矩阵（180/180 路径）和 25 波浸泡。的
相同的修订版 `a35703c` 也通过了 rootful Native Linux CRIU 检查点
门（`open_experimental_with_criu`，固定 CRIU 4.2.1），带有 `available`
阳性报告（SHA-256
`05eccd22bca338f89d11fa8b2a971c58ce4e4ff34fc246c1b2203162f7cbe57b`) 加上
专用 PID 和配置网络负面报告。这仍然是
仅观察证据：AArch64，新配置的多架构
升级、主机关闭和签名发布大门保持开放，并且 Linux
KVM 候选者仍然是`probe-only`。


## 架构

```text
A3S Box (current Sandbox consumer; explicit Native Linux production route
         owns bundle/resource preparation and uses the long-lived SDK owner;
         default, MicroVM, and cross-platform cutover remain open)
a3s-oci CLI
containerd runtime-v2 shim
                         │
                         ▼
                  RuntimeClient
             in-process or bounded local IPC
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
             isolation owner selected once
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

仅隔离的 `a3s-oci-krun-shim` 加载校验和固定的本机 libkrun
资产。 SDK、CLI 发现路径、持久主机服务和 Native Linux
驱动程序不初始化虚拟机管理程序库。

在 Linux x86_64 和 AArch64 上，`a3s-oci-krun-shim context-smoke` 验证并
加载选定的本机包，检查固件导出的内核，以及
创建、配置和释放一个 libkrun 上下文。该命令不
打开`/dev/kvm`，进入虚拟机，或更改KVM驱动程序的`probe-only`准备情况。
更强的预入口门还绑定了精确的静态代理和不可变的
来自同一目标清单的根磁盘：

```bash
a3s-oci-krun-shim system-image-context-smoke \
  --system-image-manifest /absolute/path/to/system-image.json
```

它使用只读描述符固定清单和原始图像，重新检查每个
紧接在本机 API 使用之前的字节，以只读方式附加根，然后
释放上下文。它仍然不进入 KVM 或要求来宾执行。

公共 Linux API 通过以下方式公开 `KvmRuntimeDriver::open_candidate`
`KvmRuntimeDriverConfig` 包含隔离的垫片、可写运行时根目录、
和不可变的系统映像清单。它准备一个空的私有引导程序
root 与精确生成运行时共享分开，委托所有 20 个
通过共享实用程序 VM 进行工作负载操作和六个 OCI 挂钩阶段
core，并禁用 Native Linux 回退。它的能力刻意保留
`probe-only`，所以`HostRuntimeService`拒绝正常注册，直到
真主晋级门下通。

单独的认证入口门添加了UID拥有模式-`0700`生成
共享、相同 UID Unix 端点、绑定 pidfd 的 shim 所有者和直接隔离
虚拟机工作者。工作人员在打开之前重新验证每个非 KVM 条目资产
`/dev/kvm`，然后重复完整的兼容性和设备检查
固定设备并需要 API 版本 12。它只能通过
不可变的系统根。主机仅接受内核报告的直接工作线程
Protocol-v10 令牌协商之前的子进程：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-agent-entry.sh
```

单独的兼容性矩阵在配置的工作边界处停止，并且
不需要KVM：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-compatibility-drift.sh
```

14个案例涵盖清单和原始图像替换、相同大小的内容
突变和符号链接；架构和运行时目标不匹配；客座代理
版本和摘要漂移；和运行时存档、libkrun、固件和导出
内核来源漂移。每种情况都必须在没有 KVM 设备访问或 VM 的情况下失败
进入和恢复端点、填充进程、令牌切换和运行时共享
库存。机器可读的结果使用
`a3s.oci.linux-kvm-compatibility-drift.v2`。

在没有可用 KVM 的主机上，经过身份验证的条目命令必须在以下时间后失败：
非 KVM 设置，保留嵌套的 KVM 证据，并恢复端点、进程和
交接库存。当KVM可用时，门首先需要一个真实的
经过身份验证的启动，然后运行隐藏的仅资格失败
`/dev/kvm` 和 API
版本 12 已在 libkrun 进入 VM 之前进行验证。 Shim 模式 v7 记录
该确切边界和脚本拒绝任何端点、进程、令牌或
运行时共享残留。此实现不会提升驱动程序：
x86_64 和 AArch64 上成功的真实进入证据以及
仍然需要完整的生命周期、恢复和浸泡矩阵。

该脚本保留正常输入
`a3s.oci.linux-kvm-agent-entry.v1` 和注入边界
`a3s.oci.linux-kvm-post-probe-failure.v1`。两者都包装原始 v10/v7 主机和
shim 使用 `a3s.oci.linux-kvm-provenance.v1` 进行报告。共同的对象需要
干净的签出，绑定 Git 对象格式、实际签出提交和树，
Linux 平台和目标架构，并对 CLI、shim、运行时资产进行哈希处理
清单、选定的运行时文件和系统映像清单。它还记录了
准确的构建配置文件、资格配置文件、`libkrun-kvm` 驱动程序，以及
`dedicated-vm`隔离等级。其他 KVM 门重复使用相同的合约，因此
来自不同源或运行时字节的绿色报告无法满足
晋升门。

KVM 门控生命周期条目重用与实用程序 VM 相同的实现
Apple Silicon 资格认证，而不是维持第二次仅限 Linux 的测试
线束：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-lifecycle.sh
```

单独的所有者死亡/重启条目练习，候选人通过
明确范围的 Unix 主机服务而不使其通常可注册：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-recovery.sh
```

创建操作阶段条目使用单独的限定范围和
替换所有四个主机和五个访客的真正 KVM VM/会话所有者
请求/响应转换：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-create-reopen.sh
```

状态在精确设置创建后使用相同的限定范围。它
在不同的替换来宾中重建创建的容器并重新发布
针对原始持久代的状态：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-state-reopen.sh
```

Start 保留与 Create 相同的设置和确切的 Start 标识。替代品
来宾要么调度准备好的 Start 一次，要么重建一个已经
主机重放持久响应之前已提交的运行状态：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-start-reopen.sh
```

Kill 保留确切的设置 Create、Start 和 signal-9 Kill 身份。一个
替换来宾重建正在运行的工作负载并调度
准备杀死一次或重建之前已经提交的停止的墓碑
主机重放持久响应：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-kill-reopen.sh
```

删除保留这三个设置标识以及确切的仅停止标识
删除身份。它的前八条路径重建了停止的墓碑并
发送 删除一次。最终提交的路径启动一个不同的空 KVM
所有者，不重建工作负载，并让主机重放已完成的日志
没有其他司机调度：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-delete-reopen.sh
```

等待使用相同的精确停止设置并将当前目标解析为其
持久的一代。前八条路重建了停止的客人墓碑，
调度原来的 15 秒 Wait 一次，并缓存其 signal-9 结果。的
提交的最终路径已经有该缓存，因此替换和稍后等待
无需其他司机或客人调度即可呼叫重放：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-wait-reopen.sh
```

Exec 保留确切的设置创建和启动身份以及一个随机数绑定，
长时间运行的终端进程请求。前八个路径仅恢复
运行 init 进程并在 API 重试后分派一次未更改的 Exec。
提交的最终路径在恢复期间重新创建 init 和 Exec，重新绑定
将它们的正 PID 放入持久响应中，并让主机重放 Exec
无需另一个 API 驱动的调度：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-exec-reopen.sh
```

SignalProcess 保留该提交的终端 Exec 并发送确切的信号 10。
前八个路径重建 init 和 Exec，但保留准备好的信号
API 重试调度一次。提交的最终路径等待重建
执行就绪标记，在恢复期间重新应用信号一次，并让
主机重放已完成的日志，无需另一个驱动程序调度：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-signal-process-reopen.sh
```

WaitProcess 使用信号 10 终止同一个已提交的非 init Exec，并且
等待最多 15 秒才能准确退出。前八条路径重建并
终止 Exec，然后在 API 上分派已解析的 WaitProcess 目标一次
重试并缓存`signal=10, oom_killed=false`。已经承诺的最终路径
具有持久的缓存，因此替换和稍后的 WaitProcess 调用不会执行
司机调度：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-wait-process-reopen.sh
```

暂停会保留创建和启动身份的准确设置并验证
在冻结生成之前绑定随机数初始化标记。前八条路
重建未暂停的 init 并在 API 重试时分派未更改的 Pause。
提交的最终路径在恢复期间重新应用暂停，重新绑定暂停的路径
记录到替换的PID，并让主机重放而无需另一个
API驱动的调度：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-pause-reopen.sh
```

恢复保留确切的设置创建、启动和暂停标识。每个
替换来宾在随机数绑定初始化后重建冷冻机历史记录
标记。前八个路径在 API 重试时调度一次未更改的 Resume；
提交的最终路径在恢复期间重新应用“恢复”并让主机
无需另一个 API 驱动的调度即可重放：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-resume-reopen.sh
```

进程保留了创建、启动和实时终端执行的精确设置
身份。每个替换的来宾都会使用新的正值重新创建 init 和 Exec
PID 和两个随机数绑定标记，然后接收只读进程查询
一次，因为不存在持久的查询响应日志。退回的库存
必须在保留代中准确包含这两个目标，包括
在第一个所有者写完完整的回复后：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-processes-reopen.sh
```

更新保留了确切的设置创建和启动身份以及完整的
Linux 资源配置文件。前八名替换客人将获得
重建正在运行的 init 后一次未更改的请求。当第一任主人
已经提交了响应，恢复将资源配置文件重新应用到
新鲜的 cgroup 和主机重放响应，无需另一个 API 驱动
派遣。 Direct Stats 验证 512 MiB 限制和实时计数器：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-update-reopen.sh
```

统计信息保留已提交的创建、启动和更新设置，同时处理
查询自身为只读。每位替换客人都会收到一份新的统计数据
请求，包括在第一个所有者写出完整的回复之后。决赛
路径要求替换快照更新且不同，同时两者
快照保留准确的生成和更新的资源配置文件：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-stats-reopen.sh
```

ReadOutput 保留提交的 Create、Start 和非终端捕获 Exec
设置。每一位替换的客人都会收到一个新的请求，内容完全相同
进程目标、游标、字节限制和超时，包括在第一个之后
所有者交付了完整的随机数绑定的标准输出块。恢复重新绑定两者
设置 PID、隔离陈旧的主机和来宾代，并删除两个标记
和所有临时所有者状态：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-read-output-reopen.sh
```

WriteStdin 保留提交的 Create、Start 和非终端管道支持
执行设置。前八个替换所有者分派未更改的字节
一次来自准备好的主机日志。 `guest-after-response-write`，恢复
将提交的写入重新水合到重建的 Exec 中，并且 API 重试返回
无需另一名司机派遣。每条路径都会验证确切的效果标记，
请求身份、陈旧的主机和来宾围栏以及完成清理：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-write-stdin-reopen.sh
```

CloseStdin 保留相同的设置和一个管道支持的 Exec，该 Exec 可以准确地写入
仅在观察到 EOF 后才进行效果标记。前八位更换业主
从准备好的主机日志中发送未更改的关闭一次。在
`guest-after-response-write`，recovery关闭之前重建的Exec输入
主机服务打开完成，因此 API 重试返回，无需其他驱动程序
派遣。每条路径都会验证确切的进程目标、EOF 标记、过时的主机
和访客围栏，并完成清理：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-close-stdin-reopen.sh
```

Resize 保留精确的终端尺寸和随机数绑定的 PTY Exec。的
前八个替换所有者将准备好的调整大小发送一次；决赛
路径在恢复期间重新应用提交的维度并重放主机
没有第二个司机调度的响应：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-resize-reopen.sh
```

文件通过相同的九个主机/来宾传输边界限定上传
使用私有可写 `/tmp` 挂载。恢复验证了确切的耐用性
请求和生成，幂等地重放已确认的上传，下载
来自替换访客的字节，拒绝更改的和过时的身份，以及
在强制删除之前删除文件：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-file-reopen.sh
```

文件系统使用相应的目录元数据和 Stat 来限定 mkdir
效果。它使用相同的耐用日志、替换所有者重放、更改和
过时生成栅栏、显式删除和零残留检查：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-filesystem-reopen.sh
```

有界浸泡使用其自己的限定范围和一项持久的主机服务：

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-soak.sh
```

当 KVM 可用时，生命周期条目会下载固定的 Alpine 夹具，
在私有运行时共享下准备两个包，并运行 17 个案例：一个完整的
生命周期、一个多容器生命周期、一个版本化的访客隔离条目、
三个不可删除清理边界，以及所有 11 个传输故障点。的
访客隔离条目包含十个捆绑的有序敌对路径案例，
rootfs、绑定源、文件和文件系统边界。需要输入
`permission-denied` 来自确切拥有操作的错误，未更改的金丝雀，
缺少容器状态，并完成固定装置/运行时清理。的
`a3s.oci.linux-kvm-lifecycle-matrix.v2`报告
保留每个嵌套的运行时报告以及端点、进程、运行时状态，
引导、令牌/恢复和标记清理检查。没有可用的KVM
跳过夹具下载并发出 `status: unavailable` 零案例。
这使得 CI 对跑步者的能力保持诚实；它不算是硬件
通过。 `a3s.oci.linux-kvm-recovery-matrix.v2` 条目同样跳过 Alpine
当KVM不可用时。使用 KVM，它会终止实时主机服务，需要
经过身份验证的 SIGKILL 恢复，
打开一个不同的替换套接字所有者，重放确切的停止状态并
等待，并证明仅停止删除加上瞬时清理。浸泡也
在不可用的主机上跳过 Alpine；其保留的聚合模式是
`a3s.oci.linux-kvm-soak-matrix.v2`。在 KVM 上运行 25 个新代，
需要每个进程、描述符、端点、切换、共享、恢复记录，
和访客标记在每次波后返回到基线。可用生命周期，
恢复和浸泡报告，包括集成的访客隔离条目
新的 x86_64 和 AArch64 KVM 主机仍然需要。其他实录
负面隔离特征仍然是单独的晋升证据。

`a3s.oci.linux-kvm-create-reopen-matrix.v1` 条目也会跳过 Alpine
KVM 不可用。在 KVM 上，它保留了确切的持久代和
创建跨九个真实主机/客户中断点的操作身份，
包括对已承诺的`guest-after-response-write`结果进行补液
一位独特的替代嘉宾。所有案例强制删除并恢复引导程序，
端点、进程、捆绑切换、运行时共享、恢复报告和标记
库存。 `a3s.oci.linux-kvm-state-reopen-matrix.v1`门应用
同样的九分给国家。它的前八个点保留了精确的 Created
记录而不返回响应； `guest-after-response-write` 提供
在断开探针证明所有者丢失之前的准确响应。更换
恢复必须重建 Created 状态，保留设置 Create 身份并
生成，返回恢复的持久记录，并恢复相同的清理
库存。然后`a3s.oci.linux-kvm-start-reopen-matrix.v1`门适用
同样点开始。它的前八个路径保留 Created 状态并且
通过替换驱动程序发送确切的启动一次。最终路径
保留运行状态；恢复重新创建并启动工作负载，重新绑定
替换 PID，重新生成准确的标记，并让主机重放
无需另一个 API 驱动的 Start 调度即可完成日志。的
`a3s.oci.linux-kvm-kill-reopen-matrix.v1`门同样适用九点
杀。其前八条路径保持运行状态；更换恢复
重新创建并启动工作负载、修复设置响应并调度
不变的 SIGKILL 一次。最终路径保留Stopped状态；恢复
重新创建、启动和终止替换工作负载以重建来宾
墓碑，然后主机重放已完成的杀戮日志而无需另一个
API驱动的调度。每条路径都会验证替换标记并使用
仅停止删除。然后`a3s.oci.linux-kvm-delete-reopen-matrix.v1`登机口
将所有九个点应用于删除。其前八个路径保留 Stopped 状态
和一份准备好的日记；替换恢复重新创建、启动和终止
在分派未更改的工作负载之前，使用原始设置身份的工作负载
删除一次。提交的最终路径保留空库存和
SucceededEmpty 日志，因此不同的空替换所有者不执行任何操作
工作负载恢复或驱动程序在主机重放之前删除。的
`a3s.oci.linux-kvm-wait-reopen-matrix.v1`门重建停止的墓碑
共九点。它的前八条路径发送精确解析的等待
定位一次并持久缓存`signal=9, oom_killed=false`；承诺的决赛
路径保留该缓存并重放替换调用和稍后的 Wait 调用
没有司机调度。每条路径都拒绝两个主机上的过时代
和来宾边界，使用仅停止删除，并恢复所有清单。
`a3s.oci.linux-kvm-exec-reopen-matrix.v1` 门将所有九个点应用到一个
终端执行者它的前八个路径保留一个Prepared日志，仅恢复
正在运行的 init 进程，并分派字节相同的进程、终端，
I/O、生成和操作标识一次。承诺的最终路径保留
成功的进程日志，以新的积极方式重新创建 init 和 Exec
PID，重新绑定设置和执行响应，并重放主机请求，而无需
另一位司机派遣。每条路径都会验证不同的随机数绑定 init 和 Exec
标记，拒绝更改的请求和过时的生成，强制删除
工作量，并恢复所有库存。的
`a3s.oci.linux-kvm-signal-process-reopen-matrix.v1` 门保留了这一点
终端 Exec 并在所有九个点应用信号 10。它的前八条路径
保留一个Prepared信号日志，重建init和Exec，并调度
API 重试时目标和信号保持不变。承诺的最终路径保留
SucceededEmpty 日志，重建 init 和 Exec，等待随机数绑定的 Exec
就绪标记，并在恢复期间重新应用信号一次；主持人
然后重放不执行额外的驱动程序调度。每条路径都会验证
单独的信号标记，拒绝信号漂移和过时的主机/客户生成，
强制删除工作负载，并恢复所有清单。等效覆盖范围
供 WaitProcess 使用
`a3s.oci.linux-kvm-wait-process-reopen-matrix.v1`。它的前八条路径有
没有主机退出缓存，因此恢复会重建并终止之前的确切 Exec
一个已解决的 WaitProcess 调度仍然存在 `signal=10, oom_killed=false`。在
`guest-after-response-write`，缓存已经持久；恢复仍在
重新创建并终止 Exec，但将其从实时清单中忽略，并且
替换和稍后等待重放都以零驱动程序调度。每一条路
重用所有设置身份，拒绝过时的主机和来宾生成，
强制删除工作负载，并恢复每个清单。等效覆盖范围
暂停使用`a3s.oci.linux-kvm-pause-reopen-matrix.v1`。它的前八个
路径保留运行状态和准备暂停日志，重建未暂停的日志
init，并调度未更改的 Pause 一次。承诺的最终路径保留
暂停状态和成功日志；恢复启动替换init，
等待其标记，重新应用暂停，并报告重新创建-暂停-运行
主持人重放之前的证据。每条路径都会隔离更改的请求和陈旧的主机
和来宾代，强制删除暂停的代，并恢复每个
库存。简历使用`a3s.oci.linux-kvm-resume-reopen-matrix.v1`。每个
替换所有者使用反弹 PID 重建创建、启动和暂停。其
前八个路径保留暂停状态，并且前一个路径保留准备恢复日志
派遣不变。提交的最终路径保留未暂停状态和
成功期刊；恢复重新应用恢复并且主机重放不执行
额外的 API 驱动调度。每条路径都会隔离更改的请求和陈旧的请求
主机和来宾代，强制删除恢复的代，然后恢复
每个库存。工艺用途
`a3s.oci.linux-kvm-processes-reopen-matrix.v1`。每一位更换车主
重建 Create、Start 和提交的终端 Exec，重新绑定两者
正进程 PID，并验证两个随机数绑定标记。因为
查询是只读的，所有九个路径仅在之后调度一次进程
重新打开，包括交付的最终响应路径。每个库存包含
只有 init 和原始 Exec 目标位于保留代
替换 PID。每条路径都拒绝陈旧的主机和来宾代，
强制删除工作负载，并恢复每个清单。更新用途
`a3s.oci.linux-kvm-update-reopen-matrix.v1`。它的前八条路径保留了
准备日志并分派未更改的完整 Linux 资源请求
恢复后一次。提交的最终路径保留了一个成功的日志；
recovery 将请求重新应用到新的 cgroup，并且主机重放执行 no
额外的 API 驱动调度。每条路径都会验证 512 MiB 限制并实时
通过直接访客统计进行计数器，拒绝更改的请求和过时的请求
主机/来宾生成，强制删除工作负载，并恢复每个
库存。统计使用`a3s.oci.linux-kvm-stats-reopen-matrix.v1`。每个
替换所有者重建创建、启动和之前提交的更新
分派一个新的只读查询。在`guest-after-response-write`，
第一个交付的快照和较新的替换快照都保留
准确的生成和更新的资源配置文件。每条路径都拒绝陈旧的主机
和来宾代，强制删除工作负载，并恢复每个
库存。读取输出用途
`a3s.oci.linux-kvm-read-output-reopen-matrix.v1`。每一位更换车主
使用反弹 PID 重建 Create、Start 和实时非终端 Exec，
然后调度一个新的查询，其中包含确切的进程目标、游标、字节
限制和超时。 `guest-after-response-write`，双方均先交付
块和替换块等于随机数绑定的标准输出。每一条路
拒绝过时的主机和来宾代，强制删除工作负载，以及
恢复所有库存。 WriteStdin 使用
`a3s.oci.linux-kvm-write-stdin-reopen-matrix.v1`。它的前八条路径保留
准备好的主机日志并在恢复后分派准确的字节一次。在
`guest-after-response-write`，恢复将提交的字节写入
重建管道支持的 Exec 并且 API 重试不执行额外的调度。
每条路径都拒绝更改的字节和陈旧的主机和访客生成，验证
随机数绑定效果标记，强制删除工作负载，并恢复每个
库存。 CloseStdin 使用
`a3s.oci.linux-kvm-close-stdin-reopen-matrix.v1`。它的前八条路径保留
准备好的主机日志并在恢复后发送准确的 EOF。在
`guest-after-response-write`，恢复关闭重建的管道支持的 Exec
并且 API 重试不执行额外的调度。每条路径都拒绝
更改了进程目标和过时的主机和来宾代，验证
随机数绑定的 EOF 标记，强制删除工作负载，并恢复每个
库存。 Resize、File 和 Filesystem 使用相同的九级门；当前
x86_64 证据现在涵盖所有 20 个工作负载操作。主机关闭依然存在
明确的准备门。

|业主|保持|一定不能吸收|
| --- | --- | --- |
| A3S Box产品专机|所需状态、映像/构建、命名卷、产品网络、Compose、运行状况/重启策略、日志保留和秘密授权 |实际 PID/VM 身份或运行时操作日志 |
| OCI 运行时控制平面 |精确的 OCI 验证、实际状态、生成、重放、退出状态、驱动程序选择、恢复和清理 |注册表拉取、映像构建、Compose 或静默隔离后备 |
|平台执行面| Linux 实施、utility VM、传输、过程控制和运行时附件 |产品编排或第二个持久生命周期|

## 运行真实门禁

便携式工作区门是：

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

当前发布工作流程生成的完整运行时标签包括签名的 SLSA
为所有五个档案和`SHA256SUMS`以及便携式
Sigstore 捆绑包。关注
[Release verification](docs/release-verification.md) 强制执行存储库，
工作流程、标签和摘要身份。验证成功不推广
所选驱动程序的广告准备就绪或更换其真实主机门。
每个 Linux 主机运行时存档还带有摘要和模式绑定
`package-manifest.json` 连接其确切的运行时、Agent、containerd shim、
资格验证报告、containerd兼容性契约；包装好的
验证者可以在安装前离线验证它。

真正的执行门需要准备好的主机和隔离的运行时根。

|主持人|切入点|指南|
| ---| ---| ---|
| Linux x86_64/aarch64 | `bash .github/scripts/native-linux-smoke.sh`、`bash .github/scripts/native-linux-checkpoint.sh` 具有精确的 CRIU 二进制文件，以及 `bash .github/scripts/linux-kvm-lifecycle.sh` 具有固定的 KVM 清单 | [Native Linux development](docs/linux-native.md) |
|苹果芯片 | `cargo run -p a3s-oci-cli -- hvf-smoke` 后跟已签名的实用程序虚拟机配置文件 | [macOS HVF development](docs/macos-hvf.md) |
| Windows x86_64 | `scripts/windows-whpx-driver-smoke.ps1` 和 `scripts/windows-whpx-recovery-smoke.ps1` 以及经过验证的容器根文件系统存档和 `windows-system-image` 清单 | [Windows WHPX development](docs/windows-whpx.md) |

Linux Smoke 为以下对象准备了一个明确的用户拥有的 cgroup-v2 子树：
无根 v4 门。在 Tokio 启动之前，CLI 保留该确切的委派，
启动父级绑定的有效根助手，并永久删除运行时
所有者的真实身份。普通无根启动使用helper提供
六个 OCI 默认设备节点并安装相同的不可变清单
边界作为根执行；它没有发明`linux.resources.devices`
政策。单独的 A3S Box 配置文件还执行有界设备访问 BPF
替换和回滚。运行时提交`bed43d2`
在 CI 运行 `31714178349` 中通过了 x86_64 和 aarch64 上的完整策略配置文件。
v4 门验证创建、实时更新/统计、经过工作负载验证的暂停/恢复、
持久事件、所有六个节点、根据要求进行的精确策略更新，以及
完成 cgroup、运行时、会话和标记清理。更广泛的授权
简介仍然是未做广告的推广工作。

rootful 设备边界配置文件有意省略 `linux.cgroupsPath`，
授予`CAP_MKNOD`，并证明仅保留声明/默认身份
可用。它还会在工作负载内重新安装 `nodev` 与 `dev` 绑定源
并验证后期设备访问仍然失败，并显示`EPERM`。运行
聚焦门与
`A3S_OCI_NATIVE_FOCUS=device-boundary bash .github/scripts/native-linux-smoke.sh`。

可写 OCI cgroup 挂载现在遵循 OCI 1.3 委派边界。的
执行者仅更改确切的`source: "cgroup"`挂载的所有权
`/sys/fs/cgroup`，没有 `ro` 选项和新创建的 cgroup 命名空间。它
将 `process.user.uid` 映射到主机 UID，保留组，并且仅更改
容器 cgroup 目录以及列出的现有文件
`/sys/kernel/cgroup/delegate`;如果该库存不存在，则会使用这三个
规范后备文件。重点关注的 Native Linux Gate 也证明了
只读 cgroup 挂载和未列出的控制器文件保留其所有权：
`A3S_OCI_NATIVE_FOCUS=cgroup-ownership bash .github/scripts/native-linux-smoke.sh`。

rootful 终端初始化配置文件从 `process.terminal` 派生 init I/O，
在启动前应用配置的 120x40 大小，并绑定确切的 PTY 从属
到`/dev/console`。它还在 `/dev` 外部创建一个已配置的 FIFO，并映射
模式和所有权。该门使用新的控制台目标运行一次，并使用
调用者拥有的占位符；删除仅删除运行时创建的目标，并且
恢复预先存在的文件不变。

当容器创建私有挂载命名空间但加入现有用户时
命名空间，执行器固定并类型检查该命名空间，观察其真实的
UID/GID 通过短暂的命名空间助手进行映射，并重新检查命名空间
入境前的身份。然后，相同的分离式安装路径为六个
具有命名空间根所有权的默认设备。本机 Linux 多容器
v20 和真正的 Apple Silicon 实用程序-VM 多容器 v11 都验证了
设备类型、主/次编号、模式、所有权、工作负载访问和清理。
相同的报告使用新的 tmpfs 覆盖图像的 `/dev` 并要求
四个 OCI Linux 链接解析到其确切的 `/proc/self/fd` 目标
每个配置的安装都已就位。

挂载选项发现和执行现在共享 SDK 的固定 61 条目 OCI
1.3 注册表。执行器消耗所有必需和推荐的控制
选项而不将它们泄漏到文件系统数据中，将未知字符串视为
文件系统特定的数据，并返回一个类型化的`Unsupported`错误
可选的 `tmpcopyup` 行为。功能发现报告了 60 个已实施的功能
OCI 名称加上 `rnodev` 扩展名，按排序顺序排列，并且不做广告
`tmpcopyup`。

所有剩余的 OCI Linux 功能报告都遵循相同的规则。每个
`RuntimeDriver` 当主机
服务开启。注册表冻结该值，拒绝多驱动程序集，如果
任何配置文件都不同，并从中构建`Features`。创建、执行和更新
在持久突变之前检查相同的值； Linux代理重用共享的
init、进程和 cgroup 规划中的配置文件。 AppArmor、SELinux、挂载标签、
因此，无法通告未通告的 Seccomp 控制以及仅限 cgroup-v1 的资源
报道一种方式，承认另一种方式。

配置的主机服务还报告每个可以改变的内置注释
运行时行为，以及由注释支持的扩展
他们的活跃司机。仅探针发现保持空白，并且特定于驱动程序
诸如捆绑切换之类的扩展仅在选定的驱动程序集时出现
实际上是在给他们做广告。

`RuntimeInfo::extensions` 是版本化的 `a3s.oci.extensions.v1` 源
选择特定于驾驶员的表面的真相。它将目录绑定到
运行主机可执行文件的 SHA-256 并发布规范的操作合约
每个可启动驱动程序的附件版本及其独特的隔离
类。 `RuntimeNegotiationRequest` 通过类型化 `IsolationClass` 选择并
如果缺少任何请求的版本，则在工作负载准备之前失败。的
传统平面 `operations` 和 `attachments` 字段仅公开交集
对每位注册司机来说都是安全的；来自较旧对等方的响应默认为
目录空空如也，无法默默满足谈判。

`a3s.oci.attachments.v2` 将已授权的存储绑定到确切的 OCI
mount，不可变的调用者发布的分配身份，匹配只读或
读写访问、调用者所有权和仅分离清理。运行时从不
解析命名卷或快照，并且永远不会删除调用者拥有的备份
资源。存储创建需要 SDK 协议 5，而 v1 创建清单
保留协议 3 兼容性。每次恢复都需要不可变的
协议 8 检查点参考如下所述。

`a3s.oci.attachments.v3` 将已经授权的Linux接口绑定到
确切的 OCI 网络命名空间和 `linux.netDevices` 条目，以及
不可变的命名空间、接口和清理身份。运行时创建
命名空间随容器一起释放；加入的调用者命名空间是
保存下来。 IPAM、DNS、路由、别名、策略和支持网络清理保持不变
在A3S盒子里。网络创建需要SDK协议6；恢复需要协议
8. Rootful Native Linux 通告累积 v1-v3；无根的原住民住宿
v1-v2，因为它没有主机网络设备权限。现在专用 Linux KVM
具有内部失败即关闭 v2/v3 传输。调用者拥有的非绑定 `ext4` raw
图像仍然存在
在运行时共享之外，并被描述符固定为只读或
读写 virtio-blk 设备；访客与他们的 libkrun 序列、大小相匹配，
仅重写授权的 OCI 安装源之前处于只读状态。安
精确生成的私有清单还绑定授权网络 JSON 指针
以及确定性访客 MAC 的附件证据；访客仅重命名
唯一匹配的 VMM NIC。加入调用者命名空间和可重用的来宾
会话被拒绝。尽管如此，KVM 仍继续宣传 v1，直到其发布为止。
累积 v2/v3 破坏性真实主机重启、清理、重放和浸泡
资格通过。 HVF 保持 v1，直到获得同等独立性
运输和证据。

`dev.a3s.network.enforcement@1` 是独立协商的要求
v3 上的扩展。它绑定一个不透明的调用者编译的执行化身
以及可选的不透明本地重定向化身到确切的连接，
调用者拥有的命名空间，仅使用正代和小写 SHA-256
消化。运行时既不接收策略内容也不获得机制清理
权威。准确的解码绑定保留在
`ContainerRecord::network_enforcement` 并对照耐用舱单进行检查
以及重新打开后的配置快照。 SDK/Host 合约和 rootful
原生 Linux 实现是合格的；无根本机和虚拟机驱动程序
继续忽略此功能，等待他们自己的权威模型，并且
驾驶员特定的真实主持人资格。

`a3s.oci.attachments.v4` 将 SharedGuestKernel 请求绑定到一个可重用的
访客会话 ID 和积极化身，请求的不可变信任
域、限制为 64 个成员的容量、运行时所有权以及显式的
空会话重置模式。创建需要SDK协议7，而恢复则需要
需要协议 8。确切的绑定保留在 `ContainerRecord` 中并且
重新打开后根据持久清单重新验证。常见的HVF/KVM
实施强制准入、容量、重置、发电轮换、
成员清理和共享所有者回收，但没有生产实用程序-VM
驱动程序通告 v4，直到其必备的存储/网络传输和
真机重启/泄漏资格通过。请参阅
[attachment contract](docs/attachment-contracts.md) 用于失败即关闭
组成规则。

SDK 协议 8 冻结 `a3s.oci.checkpoint-reference.v1`：一个确切的暂停
源代码生成、配置和附件摘要、驱动程序/隔离、
平台和架构、主机可执行文件和驱动程序构建证据、
驱动程序定义的格式以及准确的工件摘要和大小。检查站接受
仅一个已经暂停的正在运行的生成并将其保留为暂停状态；恢复回报
一个新的暂停运行的生成，需要一个显式的稍后`resume`。
工件存储、沿袭、保留和对象策略仍然由调用者拥有。
主机现在拥有持久检查点和恢复编排。检查站
隔离确切的暂停源和所有进程 I/O。恢复第一个重放任何
提交 v5 或 v6 结果而不重新打开调用者数据；否则它
之前验证不可变的工件和确切的运行时/驱动程序兼容性
分配一代，调度幂等驱动程序恢复，并提交
暂停的运行记录。终端恢复失败仅隔离其
分配的一代，以便 ID 可以单调地重用。注册表
仅接受来自明确广告的当前平台的`Checkpoint`
司机并仅接受 `Restore` 和 `Checkpoint`。默认
原生Linux清单和普通实验构造函数广告
都没有操作。单独的根`open_experimental_with_criu`
构造函数绑定一个确切的 CRIU 可执行文件并通告 Checkpoint 和
恢复。
它的 `native-linux-criu` v1 后端以原子方式通告这两个操作
发布一个流式摘要绑定工件，重新创建一个更新的精确暂停
通过 CRIU 生成，通过重放检查点/恢复响应丢失
主机边界，使源暂停，并具有有限的实内核正数
门加上私有 PID 和配置的网络命名空间负门。它的v3
在 Restore 驱动程序调用之后以及之后，gate 还会替换运行时所有者
完成主机操作目录同步；重新开放新的服务和司机
相同的根，从保留的不可变中重新创建实时暂停的一代
图像、重放准确的响应、保留工件并清理每个
恢复日志、暂存、执行器和会话路径。包资格 v6
使用分阶段静态 CLI 和代理运行相同的三报告门，绑定
运行时和主机提供的 CRIU 摘要，并将报告保留在存档中。
2026 年 9 月 8 日来自干净修订版的裸机 x86_64 观察结果
`a35703c` 保留了针对固定 CRIU 4.2.1 的相同三报告门；是的
源构建的观察证据，并且不关闭标记的多架构
或生产准备情况。更广泛的命名空间和描述符配置文件、跨驱动程序
并保留标记的多架构资格和生产准备情况
保持开放。请参阅[immutable checkpoint contract](docs/checkpoint-contract.md)。

containerd runtime-v2 shim 现在公开了这个可选合约，而无需
使其成为端点的 18 操作基本准入集的一部分。停顿了一下
任务检查点写入`a3s-oci-checkpoint-v1.bin`加上原子提交
`a3s-oci-checkpoint-v1.json` 将清单引用到containerd的请求中
目录。使用该目录创建会验证不可变包并
调用 SDK 恢复。虽然 SDK 恢复返回暂停运行的生成，
填充程序报告 CREATED 直到第一个 Start 执行一次重放稳定
简历； schema-v10 元数据和 schema-v2 创建意图恢复双方
垫片崩溃后的障碍。不受支持的选定驱动程序返回
仅针对可选请求未实现。增量检查点和
非中性 runc 检查点选项仍被拒绝。

SDK协议9增加了策略中立的TEE机制边界。专用虚拟机
创建或恢复可能只需要一个 `dev.a3s.tee.amd-sev-snp@1` 或
`dev.a3s.tee.intel-tdx@1` 显式启动扩展 `hardware` 或
`simulated`模式。独立耐用的`attest`操作具有精确的
64 字节报告数据绑定并返回有界不透明提供者证据以及
启动测量、配置和附件摘要、驱动程序和
驱动程序构建身份和确切的主机工件。运行时验证和重放
这些绑定但不验证提供者声明或进行授权
决定； Box 或 Cloud 拥有评估和政策。司机可能会做广告
`Attest` 仅与至少一个精确的 TEE 扩展和专用 VM 一起使用
隔离。没有生产驱动程序宣传 TEE 扩展或 `Attest`
直到硬件执行、取证、重启、升级、
破坏性真主资格通行证。请参阅[TEE launch and attestation
contract](docs/tee-attestation-contract.md)。

这些命令可能需要 root 权限、虚拟机管理程序访问权限、签名
工件，或显式提供的测试根中的破坏性清理。
在运行它们之前请阅读链接的主机指南。

## 证据，而非口号

存储库将发布声明转换为检查清单：

|证据|当前锁|
| ---| ---: |
|命名 OCI 架构属性和枚举值分类 | 423 | 423
| OCI 架构配置 | 257 个强制执行 · 2 个已验证 · 75 个被拒绝 不受支持 · 89 个被拒绝 不适用 · 0 个待定 · 0 个符合 |
|审查架构证据 | 31 个绑定中的 334 个适用项目 · 132 条规则 · 103 项测试 |
| OCI Linux 配置和功能简介 | 190 / 190 架构项：145 强制执行 · 45 拒绝不受支持； 218 / 218 `config-linux.md`：206 个强制执行 · 9 个已验证 · 3 个一致； 41 / 41 `features-linux.md` 强制执行 |
| OCI 虚拟机配置文件 | 26 / 26 模式项 · 24 / 24 规范要求 · 4 个经过验证的绝对路径 · 20 个失败即关闭运行时拥有的控件 |
|固定 OCI JSON 架构套件 | 19 / 19 上游装置​​ · 4 / 4 启动配置文件，包括配置、功能和创建/运行/停止状态文档 |
|官方 OCI 运行时工具捆绑包 |运行时工具 0.9.0，`8a4db579f5c88af5a0d036fad34bddc9c1f703f3` · OCI 1.3.0 本机 Linux 和实用程序 VM 捆绑包 · 必须级别 · 转义 rootfs 负面 |
| RFC 2119 在 15 个固定规范 OCI 1.3 文档中出现 | 764 | 764
|类型化语义验证规则 | 95 | 95
|所有者绑定的非语义规则 | 156 | 156
| OCI 规范处置 | 578 项已强制执行 · 51 项已验证 · 12 项符合 · 14 项经过外部审核 · 0 项待审核 |
|已注册的持久提交错误阶段 | 877 | 877
|耐用状态更换资格验证 | macOS/Linux/Windows 完整，包括真正的 Linux 绑定安装和 Windows 重解析点矩阵 |
|直播containerd终端init-Kill补水| 2026 年 8 月 24 日 3 / 3 个连续的同主机 Ubuntu arm64/containerd 2.2.2 矩阵 |
|实时containerd `DeleteProcess`响应重放 | 2026 年 8 月 24 日 3 / 3 个连续的同主机 Ubuntu arm64/containerd 2.2.2 矩阵 |
|实时containerd任务删除响应重放| 2026 年 8 月 24 日的 3 / 3 个连续同一主机 Ubuntu x86_64/containerd 2.2.3 矩阵 |
|提交后containerd `WriteStdin` 强制清理 | 2026 年 8 月 24 日的 3 / 3 个连续同一主机 Ubuntu x86_64/containerd 2.2.3 矩阵 |
|提交后containerd `CloseStdin` 强制清理 | 2026 年 8 月 24 日的 3 / 3 个连续同一主机 Ubuntu x86_64/containerd 2.2.3 矩阵 |
|提交后containerd `ResizePty` 强制清理 | 2026 年 8 月 28 日的 3 / 3 个连续同一主机 Ubuntu 24.04.3 LTS/WSL2 x86_64 观察结果 |
| `RuntimeDriver` 断层边界之前/之后 | 52 | 52
|已验证的代理操作阶段故障对 | 180 | 180
|便携式创建/状态/启动/终止/删除/等待/执行/SignalProcess/WaitProcess/暂停/恢复/进程/更新/统计/ReadOutput/WriteStdin/CloseStdin/调整大小/文件/文件系统主机服务重新打开对| 180 | 180
|真正的 HVF 创建主机/访客加上主机关闭中断和清理阶段 | 11 | 11
|真正的 HVF 持久创建重新打开以及虚拟机/会话所有者替换路径 | 9 |
|真正的 HVF 持久状态重新打开以及虚拟机/会话所有者替换路径 | 9 |
|真正的 HVF 持久启动重新打开以及虚拟机/会话所有者替换路径 | 9 |
|真正的 HVF 持久终止重新打开以及虚拟机/会话所有者替换路径 | 9 |
|真正的 HVF 持久删除重新打开以及虚拟机/会话所有者替换路径 | 9 |
|真正的 HVF 持久等待重新打开以及虚拟机/会话所有者替换路径 | 9 |
|真正的 HVF 持久 Exec 重新打开以及 VM/会话所有者替换路径 | 9 |
|真正的 HVF 持久 SignalProcess 重新打开以及 VM/会话所有者替换路径 | 9 |
|真正的 HVF 持久 WaitProcess 重新打开以及 VM/会话所有者替换路径 | 9 |
|真正的 HVF 持久暂停重新打开以及虚拟机/会话所有者替换路径 | 9 |
|真正的 HVF 持久恢复重新打开以及虚拟机/会话所有者替换路径 | 9 |
|真正的 HVF 持久进程重新打开以及虚拟机/会话所有者替换路径 | 9 |
|真正的 HVF 持久更新重新打开以及虚拟机/会话所有者替换路径 | 9 |
|真正的 HVF 持久统计数据重新打开以及虚拟机/会话所有者替换路径 | 9 |
|真正的 HVF 持久 ReadOutput 重新打开以及 VM/会话所有者替换路径 | 9 |
|真正的 HVF 持久 WriteStdin 重新打开以及 VM/会话所有者替换路径 | 9 |
|真正的 HVF 持久 CloseStdin 重新打开以及 VM/会话所有者替换路径 | 9 |
|真正的 HVF 持久调整大小重新打开以及虚拟机/会话所有者替换路径 | 9 |
|真正的 HVF 持久文件重新打开以及虚拟机/会话所有者替换路径 | 9 |
|真正的 HVF 持久文件系统重新打开以及虚拟机/会话所有者替换路径 | 9 |
|真正的HVF操作更换覆盖| 180 / 180 条路径（20 / 20 次操作）|
|真实 HVF 记录响应后确认重放 | 2026 年 8 月 15 日 14 / 14 突变 |
|真正的 HVF 生命周期/运输清理故障点 | 14 / 14 | 14
|真正的 HVF 不可变系统图像浸泡 | 25 / 25 个新虚拟机（75 个主要代）|
| macOS HVF R2M 实施门 | 15 / 15 | 15 / 15
|公共 macOS HVF 主机服务实施 |完全的;修订版 `a5a6b53` 通过了 23/23 操作、所有者更换和 25/25 新虚拟机 |
| Linux KVM 17个案例生命周期入门 |针对 x86_64 和 AArch64 实现；干净的修订版`e7567f9`保留了x86_64上的`available`证据，因此新鲜主机证据是1 / 2架构|
| Linux KVM属主-死亡/重启入门 |针对 x86_64 和 AArch64 实现；干净的修订版 `e7567f9` 保留了 `available` x86_64 上的证据，因此新主机证据是 1 / 2 架构 |
| Linux KVM 有界浸泡入门 |在 x86_64 和 AArch64 的第 25 代中实现；干净的修订版 `e7567f9` 在 x86_64 上保留了 25 / 25，因此新鲜主机证据是 1 / 2 架构 |
| Linux KVM创建操作阶段所有者更换|两种架构均已实施并通过 CI 连接；干净的修订版 `c435e26` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构和 9 / 180 工作负载操作路径 |
| Linux KVM状态运行-阶段所有者更换|两种架构均已实施并通过 CI 连接；干净的修订版 `d0c29e2` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 18 / 180 个路径 |
| Linux KVM启动运营阶段业主更换|两种架构均已实施并通过 CI 连接；干净的修订版 `3bbdeda` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 27 / 180 个路径 |
| Linux KVM Kill运行阶段所有者更换|两种架构均已实施并通过 CI 连接；干净的修订版 `336bd5e` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 36 / 180 个路径 |
| Linux KVM删除操作-阶段所有者更换|两种架构均已实施并通过 CI 连接；干净的修订版 `3227ace` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 45 / 180 个路径 |
| Linux KVM等待运行阶段业主更换|两种架构均已实施并通过 CI 连接；干净的修订版 `b491195` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 54 / 180 个路径 |
| Linux KVM Exec运行阶段所有者更换|两种架构均已实施并通过 CI 连接；干净的修订版 `18ecaf1` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 63 / 180 个路径 |
| Linux KVM SignalProcess 操作阶段所有者更换 |两种架构均已实施并通过 CI 连接；干净的修订版 `2f5456c` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 72 / 180 个路径 |
| Linux KVM WaitProcess运行阶段所有者更换|两种架构均已实施并通过 CI 连接；干净的修订版 `4338d37` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 81 / 180 个路径 |
| Linux KVM暂停运行-阶段所有者更换|两种架构均已实施并通过 CI 连接；干净的修订版 `3e9fc4b` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 90 / 180 个路径（10 / 20 个操作） |
| Linux KVM恢复运行阶段所有者更换|两种架构均已实施并通过 CI 连接；干净的修订版 `b4c3a85` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 99 / 180 个路径（11 / 20 个操作） |
| Linux KVM进程操作阶段所有者更换|两种架构均已实施并通过 CI 连接；干净的修订版 `9a1a37c` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 108 / 180 个路径（12 / 20 个操作） |
| Linux KVM更新操作-阶段所有者更换|两种架构均已实施并通过 CI 连接；干净的修订版 `aa0f56a` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 117 / 180 个路径（13 / 20 个操作） |
| Linux KVM Stats 运行阶段所有者更换 |两种架构均已实施并通过 CI 连接；干净的修订版 `09286d8` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 126 / 180 个路径（14 / 20 个操作） |
| Linux KVM ReadOutput操作阶段所有者更换|两种架构均已实施并通过 CI 连接；干净的修订版 `dd47146` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 135 / 180 个路径（15 / 20 个操作） |
| Linux KVM WriteStdin操作阶段所有者更换|两种架构均已实施并通过 CI 连接；干净的修订版 `17b307d` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 144 / 180 个路径（16 / 20 个操作） |
| Linux KVM CloseStdin运行阶段所有者更换|两种架构均已实施并通过 CI 连接；干净的修订版 `31d35c3` 在 x86_64 上保留了 9 / 9，因此新主机证据是 1 / 2 架构，保留的总工作负载操作覆盖范围是 153 / 180 个路径（17 / 20 个操作） |
| Linux KVM Resize操作阶段所有者更换|两种架构均已实施并通过 CI 连接； clean x86_64 资格保留了 9 / 9 个阶段，完整的 Linux KVM 操作阶段实现集现在涵盖了 20 / 20 个操作 |
| Linux KVM文件操作-阶段所有者更换|两种架构均已实施并通过 CI 连接；干净的修订版 `fa4c593` 在 x86_64 上保留了 9 / 9 个阶段（报告 `8bd1bb731198c5a28659a47e85d146a5e8285483488a6540acda8d1596d51ec3`），新主机证据仍然是 1 / 2 架构 |
| Linux KVM 文件系统操作阶段所有者更换 |两种架构均已实施并通过 CI 连接；干净的修订版 `fa4c593` 在 x86_64 上保留了 9 / 9 个阶段（报告 `205e3b493e218a3fc3d8bc50f4d4b3af14ccf0156846352dfa00bd1d84d67c19`），新主机证据仍然是 1 / 2 架构 |
| Linux KVM运营阶段业主更换覆盖|在 20 个操作中实施并连接了 180 / 180 条路径；可用的 x86_64 证据在保留的当前和之前的干净修订中已完成，而新的 AArch64 证据正在等待 |
|协议 v10 背后的来宾操作 | 21（20 个公共工作负载操作 + 1 个维护确认）|

锁证明库存和行使边界，但不完全符合
他们自己。 OCI 1.3 规范清单没有未分类条目，但是
上游生命周期套件、对抗性安全性、升级兼容性以及
在驱动程序成为之前，精确的发布工件资格必须全部通过
`supported`。

### 还是有意开放

- 支持 CAT/MBA 的 Linux 主机上的真实内核 Intel RDT 资格；
- 每个上的描述符限制文件系统会话的真实主机资格
  剩余实用程序-VM 驱动程序；
- 生产就绪的本机 Linux 和utility VM驱动程序；
- 实时本地 Linux 进程 - I/O 在所有者死亡和精确情况下重新连接
  当持久性经过身份验证的收割者可以保留它时，它是最终证据；
- 实施的不可变 WHPX 系统根的新主机资格，以及
  已实施的KVM系统根的真实进入资格；
-实用程序-VM钩子恢复和安全认证；
- 默认和跨平台的 A3S Box 切换，加上剩余的
  容器兼容性、包装和跨驱动程序门；
- Native Linux CRIU 更广泛的检查点源配置文件、跨驱动程序和
  保留标记的多架构真实主机资格和生产
  检查点/恢复准备状态；
- 生产 SEV-SNP/TDX 启动和认证驱动程序、硬件证据
  运行时之外的资格认证和验证者策略集成；
- 精确的已发布包资格、升级、回滚、安全性和
  长期释放门。

## 仓库地图

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

- [Roadmap and release gates](ROADMAP.md)
- [Release verification](docs/release-verification.md)
- [Durable lifecycle and recovery](docs/durable-state.md)
- [SDK transport](docs/sdk-transport.md)
- [Immutable checkpoint and restore contract](docs/checkpoint-contract.md)
- [TEE launch and attestation contract](docs/tee-attestation-contract.md)
- [Versioned attachment contracts](docs/attachment-contracts.md)
- [Guest-agent protocol](docs/agent-protocol.md)
- [OCI 1.3 conformance contract](docs/oci-conformance.md)
- [Normative coverage](docs/normative-coverage.md)
- [Semantic validation](docs/semantic-validation.md)
- [Native Linux development](docs/linux-native.md)
- [macOS HVF development](docs/macos-hvf.md)
- [Windows WHPX development](docs/windows-whpx.md)

## 开发

从存储库根运行检查：

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

交叉检查受支持的 Linux 编译目标，无需处理父级
monorepo 作为 Rust 工作区：

```bash
cargo clippy --target x86_64-unknown-linux-gnu \
  --workspace --all-targets -- -D warnings
cargo clippy --target aarch64-unknown-linux-gnu \
  --workspace --all-targets -- -D warnings
```

带标签的存档包含主机诊断和匹配的平台资产。
Linux x86_64 和 arm64 存档带有静态链接的 musl CLI、代理和
其释放门拒绝 ELF 解释器的 containerd shim 可执行文件
动态依赖。在归档 Linux 目录之前，其确切位置
CLI 和 Agent 运行完整的 Native Linux SDK，无根，所有者死亡，
Hook 恢复、OAR-01 网络强制、故障清除和有界浸泡
删除了`/dev/kvm`的矩阵。档案保留
`qualification/native-linux-package.json` 模式 v7 加上十三个摘要绑定，
常规的非符号链接从属报告标准化为模式`0644`。三个
这些报告运行 OAR-03 CRIU
检查点/恢复、替换进程恢复和 PID/网络命名空间
带有分阶段二进制文件的拒绝门。第四个运行官方 OCI 运行时
准确提交的工具 0.9.0
`8a4db579f5c88af5a0d036fad34bddc9c1f703f3` 对抗 Native Linux 和
utility-VM OCI 1.3.0 捆绑配置和 escaping-rootfs 否定。
在 x86_64 和 AArch64 上，第五个报告启动固定的上游生命周期
通过分阶段 CLI 和持久主机服务进行配置文件。兼容性锁
提供架构匹配的 Alpine 3.22.5 minirootfs，具有精确的 URL、大小、
和 SHA-256 出处，因为运行时工具本身仅携带 amd64
固定装置。构建器拒绝不安全的存档路径、缺少 BusyBox 身份、
和体系结构漂移之前将其安装在预期的文件名下
上游线束。所有九个选定的测试均执行：七个通过了最初的测试
TAP 断言，而 `start` 和 `pidfile` 在语义上保留
符合两个精确的、经过源审核的运行时工具线束缺陷。的
上游 AArch64 配置的本机和 32 位 ARM seccomp ABI 都是
使用体系结构范围的系统调用表进行编译。报告记录了
rootfs 源，都是缺陷标识符，全部已停用的 CLI
日志、干净的服务关闭以及限定固定核心生命周期
两种 Linux 架构上的配置文件，而不隐藏两个原始 TAP 故障。
该工作流程还在固定提交时构建上游 CRIU v4.2.1
`9539417f3e3cfa4eb84c319cd71f4d52f1f08645`。 CRIU 和运行时工具仍然存在
主机提供且在存档之外；他们的确切身份和可执行文件
摘要受包报告的约束。固定核心轮廓不
限定继承的 stdio 描述符传输、终端控制台套接字、
`LISTEN_FDS`，更广泛的上游套件，或非 Linux 平台。套餐
可用性永远不会凌驾于报告的准备状态
精确的二进制 `features` 结果。

## 许可证

A3S OCI Runtime在 [MIT License](LICENSE) 下可用。
