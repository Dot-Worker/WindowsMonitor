# WindowsMonitor

在本机记录 Windows 持久化入口、配置和文件的变化。浏览器快捷方式在首次扫描就显示目标、完整参数和待核对的原因。连续扫描保留修改前后的证据，可以追查隔一段时间才出现的启动项。工具只读采集，发现变化后由用户决定如何处理。

查看程序版本可运行 python monitor.py --version。

## 查看本机

需要 64 位 Windows、64 位 Python 3.11 或更高版本，以及系统自带的 Windows PowerShell。以下命令在项目目录运行。

~~~powershell
python monitor.py scan
python monitor.py processes
python monitor.py files
.\Watch.ps1 Start
.\Watch.ps1 Status
~~~

默认报告位于项目内的本机数据目录。打开 [.windowsmonitor/settings.html](.windowsmonitor/settings.html) 查看浏览器参数、服务、启动设置变化、两次扫描间隔内的事件和权限缺口。打开 [.windowsmonitor/files.html](.windowsmonitor/files.html) 查看文件差异。对应的 JSON 适合检索或再次分析。每个 HTML 都可以离线打开。

首次成功读取的状态是本机观测起点。如果某些项目第一次是在权限恢复后读到，报告会标为“首次可读”。后续轮次以各范围最近一次成功读取的内容为准。新增、删除、修改分开记录，服务或注册表键只展示发生变化的字段。Windows 更新、策略下发、用户操作也可能产生差异。报告保留本轮和上一轮的系统版本。

打开 [.windowsmonitor/processes.html](.windowsmonitor/processes.html) 查看系统进程中的第三方模块、签名未知的模块和可执行内存线索。设置、进程、文件在三个独立的循环中采集。设置和进程各自在一轮结束后等待 5 分钟，文件扫描间隔为 24 小时。整个 Windows 目录每轮重新计算 SHA-256，同一轮内的硬链接可共享哈希。运行时间取决于文件总量、磁盘速度和其他程序的占用。数据库事务和扫描锁保证多个实例不会同时推进同一类基线。

~~~powershell
.\Watch.ps1 Stop
# 在前台用自定义间隔运行，Ctrl+C 结束
python monitor.py watch --interval 120 --file-hours 12
~~~

普通后台模式持续到当前用户退出、重启或手动停止。如需每次登录自动运行，可执行以下命令。任务名为 WindowsMonitor 加当前用户 SID，使用当前用户的普通权限。系统的任务计划权限策略适用于这一步。

~~~powershell
.\Watch.ps1 EnableLogon
.\Watch.ps1 DisableLogon
~~~

如果本机执行策略限制直接调用项目脚本，可以通过单次 PowerShell 进程运行，例如

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Watch.ps1 Status
~~~

若需要扩大系统进程和固件的可读范围，可在管理员 PowerShell 中运行以下命令。它会接管当前项目的后台进程并沿用现有数据目录。watch.json 中的 elevated 字段记录新进程启动时实际取得的权限。

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Watch.ps1 AdminStart
~~~

## 查看历史和完整清单

HTML 和 JSON 总是展示最近一轮。SQLite 数据库保存完整的当前观测清单、每一轮的变化和覆盖缺口。即使下一轮没有变化，旧的记录仍可导出。数据文件包含程序路径、命令行、网址、策略和可能含个人信息的事件 XML，默认通过 .gitignore 排除。

~~~powershell
python monitor.py history --limit 20
python monitor.py history --limit 100 --out .windowsmonitor/history.json
python monitor.py inventory
python monitor.py inventory --scope tasks --out .windowsmonitor/tasks.json
python monitor.py inventory --scope shortcuts --out .windowsmonitor/shortcuts.json
~~~

使用 --state 指定独立数据目录。每个目录绑定一台计算机。文件范围名称也绑定到固定目录，避免误用其他目录时产生大批虚假删除。inventory 列出最后成功观测到的记录，读取时应结合最近报告中的覆盖缺口。

## 采集范围

- **服务和驱动**。读取当前控制集中的服务配置，包括 ImagePath、账户、类型、Start、DelayedAutoStart、依赖、失败动作、Parameters、StartOverride 和 TriggerInfo。二进制注册表值记录长度及摘要。自动启动全局延迟单独采集。如果启动时间由计划任务指定，其触发器和操作在任务 XML 中。
- **启动项和计划任务**。覆盖系统和已加载用户的 Run、RunOnce、策略 Run、StartupApproved、32 位注册表视图、Winlogon、IFEO 等入口，记录可见的任务文件夹及其中的隐藏任务、启用状态、触发器和动作，另查 WMI 永久事件订阅。
- **浏览器快捷方式**。扫描用户和公用桌面、开始菜单、启动目录及用户固定项，处理已加载配置文件中能解析的重定向路径。启动目录内的其他文件也做哈希。静态解析 .lnk 的路径、相对路径和命令行，保存 .url 的网址和摘要。纯 Shell IDList 目标会标记路径未解析。网址、代理、扩展等参数值得核对，正常的配置文件选择和来源参数也会显示。--shortcuts 可重复指定其他目录。
- **注册表和系统设置**。跟踪启动、策略、会话管理、LSA、电源、时区、网络、Defender 等指定子树，以及已加载用户的控制面板、环境变量、代理和资源管理器配置。任意设置子树可以通过 --registry 增补，记录空键、值名称、类型和变化。普通设置的值以摘要记录，选定的启动和策略字段保留可读值。非活动用户配置单元需要等到加载才能比较。
- **组策略和安全设置**。记录本机组策略文件摘要、已应用策略注册表和可访问的 RSoP 信息，防火墙配置文件、规则源及有效规则的程序、端口、地址、方向和动作。读取 Defender 首选项、排除目录/进程/扩展和保护状态。第三方杀毒软件的私有配置可用 --registry 添加已知注册表路径。
- **UEFI**。读取平台开放的 Secure Boot 状态和密钥库摘要、固件 BCD、BootOrder、BootNext、BootCurrent、Timeout 和其引用的 Boot 项。厂商公开的运行时变量可通过 --uefi 增补。主板设置界面中的选项能否读取取决于固件是否导出对应变量。普通权限下通常会看到固件访问缺口。
- **事件日志**。对已启用且可读的 System、Security、TaskScheduler、Defender、防火墙通道保存 RecordId 游标。首次读取从当时的最新事件开始。后续补采相关服务安装/启动类型变更、任务注册/执行、注册表审计、安全软件变化等事件。日志清空或回卷时显示覆盖缺口。单通道每轮最多取 200 条匹配事件，余下的从上次游标继续读。未审计且在两次快照之间出现又消失的修改可能无法观察。

~~~powershell
python monitor.py scan --registry 'HKLM\Software\某个厂商' --shortcuts 'D:\浏览器快捷方式'
python monitor.py files --file-root 'ProgramFiles=C:\Program Files'
~~~

## 系统进程内的第三方代码

进程报告检查 Windows 目录内的可执行文件、常见系统进程名称以及部分 Windows 应用包进程。可以用 --process 额外指定进程名。每个宿主的标识包含名称、PID 和创建时间，避免 PID 重用时把两个进程混在一起。

~~~powershell
python monitor.py processes --process ExampleService.exe
python monitor.py inventory --scope loaded-modules --out .windowsmonitor/loaded-modules.json
~~~

报告按磁盘映像列出关联宿主，记录本次加载地址、SHA-256、Authenticode 嵌入或目录签名、签名者、证书指纹和 Windows 的 IsOSBinary 判定。加载地址保存在 loaded-modules 清单。签名有效的第三方扩展、无签名文件、签名未知和位于系统目录外的 Windows 签名文件分别展示。使用 --reference 可进一步核对 Windows 目录内模块的哈希和参考路径。磁盘签名说明的是当前文件，进程里已经映射的字节可能不同。

内存检查只查询映射元数据，记录私有可执行区域、可执行映射、模块清单外的可执行映像和可读工作集中变为私有的映像执行页。报告保留地址、保护属性、长度、可取得的映射路径以及页偏移，不保存进程内存字节。浏览器 JIT、热补丁、输入法和资源管理器扩展都可能留下线索，单个线索无法证明注入来源。

两次快照之间的短暂加载或注入可能漏过。若已有 Sysmon 日志，设置报告也会从保存的游标读取事件 7、8 和 25，分别对应映像加载、远程线程和进程映像篡改。可见性取决于现有日志配置和权限。受保护进程、无法读取的模块和未驻留的私有映像页限制了用户态扫描的覆盖范围。[Sysmon 事件说明](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)、[虚拟内存区域](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)、[工作集页属性](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-psapi_working_set_ex_block)、[Authenticode 检查](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature)。

## 原版文件和初始服务

没有干净来源时，本机基线能证明“从首次观测起内容变化”或“之前可读的文件已消失”。首次扫描前已存在的替换、缺失或新增服务属于未知。Windows 文件签名也无法证明一个特定路径在某个补丁、语言包或功能配置下应当存在。

在可信的、刚安装好的 Windows 上建立参考清单，再把清单复制到待监控机器。选择相同 Windows 版本、架构、安装语言、补丁、功能包和版本索引。命令会读取 Windows 目录和该安装中的服务/驱动；需要覆盖 Windows 目录外的随系统安装文件时，在两端使用相同范围名称补充相应目录。

~~~powershell
# 在干净系统上运行
python monitor.py reference --out D:\clean-windows.sqlite --file-root 'ProgramFiles=C:\Program Files'
# 在待检查系统上运行
python monitor.py scan --reference D:\clean-windows.sqlite
python monitor.py files --reference D:\clean-windows.sqlite --file-root 'ProgramFiles=C:\Program Files'
~~~

程序检查 EditionID、CurrentBuild、UBR、InstallationType、体系结构和安装语言。任一不匹配就跳过原版比较。已安装的可选组件、语言包、驱动和参考来源的可信度需另行核对。保存参考清单时请保留其来源，避免被待检查机器上的软件改写。

报告分别列出清单中的初始服务、清单以外的服务、缺失的服务/文件、内容不同的文件和配置不同的服务。SHA-256 覆盖可打开的普通文件主数据流，包括可能正常变化的日志和配置。不可读文件、重解析点以及扫描期间发生变化的文件列入缺口。文件差异反映与指定清单的差异，单凭差异无法判断来源或恶意程度。

## 验证

~~~powershell
python -m unittest -v
~~~

测试在临时目录中模拟快捷方式追加广告网址、同版本清单中的文件被替换或删除、服务启动类型变化以及读取受限。Windows 上还会通过正常采集入口读取一个临时 .lnk 文件。

## 改版并推送

在当前发布分支运行以下命令，把示例版本号换成目标版本。如果要发布新文件，先通过 git add 明确选入。脚本运行测试，更新 VERSION，提交已跟踪文件的修改及已选入的新文件，然后推送到当前上游分支。推送失败会保留本地提交，修复连接后可用相同版本号重试。

~~~powershell
.\Release.ps1 -Version 0.1.1
~~~

微软技术资料：[Shell Link 文件格式](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/)、[StringData 启动参数](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/17b69472-0f34-4bcf-b290-eccdb8de224b)、[Secure Boot 变量](https://learn.microsoft.com/powershell/module/secureboot/get-securebootuefi)、[读取固件变量](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariableexa)。
