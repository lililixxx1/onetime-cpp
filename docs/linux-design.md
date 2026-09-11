# Linux 版设计文档

状态：已审核（plan-code-reviewer，GO WITH CHANGES）→ 修订完成，实现中
审核修订记录：① 补运行时 SIGPIPE 处理（POSIX 对已关闭连接 send 默认终止进程，Windows 无此语义，须显式屏蔽）；② tests 清单补 GetTempPathA/MAX_PATH；③ GCM 向量编号修正为 TC13-16 组，AAD 向量因公开接口恒空 AAD 改为不引入；④ 采纳建议：SO_REUSEADDR、CNG 期望值生成流程、.desktop Exec 引号转义、`<spawn.h>`、Threads::Threads PUBLIC、pkg-config 与 fonts-noto-cjk 文档化。
日期：2026-09-10
前置：业务层 Windows 专属调用此前已评估为 4 文件；本次逐行复核（含审核修正）为 6 个源文件 + CMake + 测试。

## 目标

- `onetime`（GUI 全功能）与 `onetime_tests` 在主流 x64 Linux（Ubuntu 22.04/Debian 12 级 glibc）上构建并通过全部安全不变量测试。
- Windows 版零行为回归：现有 CNG/Winsock/注册表路径保持原样，仅做条件编译切分。
- 交付一键构建脚本与文档；本机（Windows）无法编译 Linux 目标，Linux 侧验证由用户执行，脚本须自检依赖并给出可读错误。

## 非目标

- macOS 支持（路径顺带留缝，不验证）。
- Wayland 原生剪贴板/托盘专项适配（GLFW X11 路径即可覆盖主流桌面；Wayland 兼容层下通常可用）。
- 交叉编译（不在 Windows 上产 Linux 二进制）。
- 连续集成流水线。

## 总体策略

1. **加密**：Windows 保留 CNG；Linux 新增自带实现（`crypto_posix.cpp`），零系统加密依赖。**加密是 Linux 版实现的最高风险点**，方案见下。
2. **平台差异内聚**：新增 header-only `src/platform.h`，集中封装文件/时间/环境/套接字的差异（约 100 行 inline）。三个业务文件（server.cpp / settings.h / main.cpp）共用，httplite.h 也走它，消除散点 `#ifdef`。
3. **框架层（3rd/EUI-NEO）不改**。CMake 已有 UNIX/X11 分支；托盘按平台开关（见 CMake 节）。

## 加密方案（Linux 分支）

### 决策：自带实现，不用 OpenSSL

理由：
- 项目哲学零第三方（服务端连 JSON 都是手写的）；OpenSSL 引入 libssl-dev 构建依赖与运行期 .so 依赖，交付脚本从"装个编译器"变成"装一堆库"。
- 接口面极小：SHA-256 一次性摘要、AES-256-GCM 单次 seal/open（≤1 MiB、无流式、无 AAD、固定 12 字节 nonce/16 字节 tag）。手写面可控。
- 正确性由测试向量锁定（见下），不靠"看起来对"。

### 实现：`src/crypto_posix.cpp`（新文件，约 330 行）

- `secureRandom`：`getrandom()`（`<sys/random.h>`，glibc ≥2.25），`ENOSYS` 时 fallback `/dev/urandom` 读满（循环读，短读即失败返回 false，与 CNG 语义一致）。
- `sha256`：FIPS 180-4 标准实现（64 轮压缩，一次性缓冲，消息长度上限按接口天然 ≤ 数 MB）。
- AES-256 + GCM：
  - AES：T 表不引入（省 4×256×4B 表与查表时序面），用 256 字节 S-box 的朴素 SubBytes 实现，14 轮，密钥扩展按 FIPS 197。性能预估：纯 C 每块 ~1-2 µs，1 MiB 加密 ~70-140 ms，本机一次性链接场景可接受（Windows CNG 对照 ~5 ms；不影响正确性，仅生成大密钥时略慢）。
  - GCM（NIST SP 800-38D）：96-bit nonce 时 J0 = IV‖0³¹‖1；加密 AES-CTR from inc32(J0)；认证 GHASH(AAD 空 ‖ CT ‖ len block)，tag = J0 加密块 ⊕ GHASH。GHASH 用逐位移移位乘法（GF(2^128) 无表实现，每 16B 块 ~128 步，对 ≤1 MiB 毫秒级）。
  - 解密先重算 tag 恒时比较（复用 util.cpp `constTimeEq`）再输出明文——与 CNG 分支"认证失败即整体失败"语义一致。
- 时序侧信道说明：S-box AES 非查表常时，但整体不做常时承诺；威胁模型是 127.0.0.1 回环本机服务（默认绑定），远程攻击者不可达，密钥只随一次性链接出现。此取舍写入代码头注释。

### 正确性锁定（test_main.cpp 增补）

1. NIST 向量：SHA-256("abc")；GCM-256 官方测试向量 McGrew-Viega **TC13（空明文）/TC14（16B 单块）/TC16（60B 多块）** 硬编码校验（TC15 含 AAD，公开接口 AAD 恒空，不引入；GHASH 的 len 块路径被所有向量覆盖；空明文向量在 Windows 上先实测 CNG 行为，一致才纳入共用测试）。
2. 跨实现一致性：用当前 Windows CNG 对固定 (key, nonce, pt) 生成的 ct/tag 期望值硬编码进测试——Linux 构建的自带实现必须逐字节复现；Windows 构建上该测试继续验证 CNG 不变。等价于双实现交叉验证。**生成流程**：实现期在 Windows 构建里加一次性打印用例，输出 (key, nonce, pt, ct, tag) 十六进制，人工粘贴硬编码进 test_main.cpp 后删除打印用例。
3. 既有往返/篡改/长度边界用例两平台共用。

## platform.h 接口清单（header-only，`onetime::plat` 命名空间）

| 接口 | Windows 实现 | POSIX 实现 |
|---|---|---|
| `moveReplace(from,to,replace)` | MoveFileExW | `::rename`（POSIX 原生原子替换；replace=false 时目标存在则失败，与 Win 语义对齐：先 stat 判存在） |
| `removeFile(path)` | DeleteFileW，ENOENT 视为成功 | `::unlink`，errno==ENOENT 视为成功 |
| `fileExists(path)` | GetFileAttributesW | `::stat` |
| `fopenRead/fopenWrite(path)` | `_wfopen_s` 宽字符 | `fopen` 字节路径 |
| `nowMs()` | GetTickCount64 | clock_gettime(CLOCK_MONOTONIC) |
| `monotonic`：连接预算/超时共用 | | |
| `localTime(t, tm&)` | localtime_s | localtime_r |
| `stderrIsConsole()` | GetConsoleMode | isatty(fileno(stderr)) |
| `debugLogLine(text)` | OutputDebugStringA | 空操作 |
| `homeDirUtf8()` | _wgetenv USERPROFILE+转换 | getenv("HOME")（缺省 "."） |
| 套接字：`SockHandle`(int)、`kInvalidSock`、`sockClose`、`sockSetTimeoutMs(fd,ms)`、`sendSock(fd,buf,len)`、`addrinfoResolve(...)`（窄字符统一） | winsock2 + DWORD 毫秒超时 + MSG_NOSIGNAL=0 | BSD socket + `timeval` 毫秒换算 + `MSG_NOSIGNAL` |
| `exePathUtf8()` | GetModuleFileNameW（main.cpp 用） | readlink("/proc/self/exe")（main.cpp 用） |

- **SIGPIPE（审核必改）**：POSIX 下对端已关闭的 socket 写入默认**终止进程**（Windows 无此语义）。服务端每连接主动 close，浏览器预取中途断开是常态。双重防线：`sendSock` 统一带 `MSG_NOSIGNAL`（结构性，不依赖初始化顺序）；`runServer` POSIX 分支开头 `signal(SIGPIPE, SIG_IGN)`（进程级兜底，覆盖未来遗漏点）。
- **SO_REUSEADDR（审核建议）**：服务端主动 close 产生 TIME_WAIT，Linux 默认 60s 内重启 bind 失败。`runServer` POSIX 分支 bind 前对监听 socket 设置（Windows 不设，保持现行为）。

- `SO_RCVTIMEO/SO_SNDTIMEO` 的类型差异（Windows DWORD 毫秒 vs POSIX timeval）是【新发现】的隐藏炸弹：不封装会在 Linux 上"设置成功但值错误"（把 15000ms 解释成 15µs 或相反）。集中到 `sockSetTimeoutMs` 一处换算。
- `getaddrinfo`：Windows 现走 GetAddrInfoW 宽字符；platform.h 提供窄字符包装 `addrinfoResolve(host, port, passive, &result)`，两平台签名一致（内部 Windows 转宽），`freeAddrinfo` 配对。server.cpp 与 httplite.h 各删掉自己的一份解析代码。
- WSAStartup：仅 Windows 需要且已在 server.cpp runServer 调用；httplite.h 的 httpCall 在 GUI/测试中都发生在 runServer 之后（服务探测成功才发业务请求），但测试里 httpCall 首连可能先于… 不会：startServer 先探测。保守起见 `addrinfoResolve` 的 Windows 分支内置一次性 lazy WSAStartup（std::call_once），彻底消除顺序假设。

## 各文件改动

### src/crypto.cpp → 拆分
- 现文件改名为 `crypto_win.cpp`（内容不动，仅头注释）。
- 新增 `crypto_posix.cpp`。
- `crypto.h` 不变。
- CMake 按平台二选一编入 onetime_core。

### src/server.cpp
- 删 windows.h/winsock2 头与 `#pragma comment`；改 include platform.h + POSIX 系统头（sys/socket.h、netinet/in.h、netinet/tcp.h、arpa/inet.h、netdb.h）。
- 逐点替换：日志时间戳（GetLocalTime→localTime + 手工拼月日时分秒）、`_vsnprintf_s`→`vsnprintf`、`_wfopen_s`/`DeleteFileW`/`MoveFileExW`→platform、`GetFileAttributesW` 判目录→`fs::is_regular_file`、`WSAStartup`→空（挪进 addrinfoResolve lazy init）、`GetAddrInfoW`→`addrinfoResolve`、SOCKET/closesocket/timeout→platform、`GetTickCount64`→`nowMs`、`_wgetenv`→`homeDirUtf8`、`isIpLiteral` 的 inet_pton 两平台通用（arpa/inet.h / ws2tcpip.h 都有）。
- `GetConsoleMode` 控制台检测→`stderrIsConsole()`。

### src/httplite.h
- winsock 头与 GetAddrInfoW 段→platform.h；`DWORD` 超时→`sockSetTimeoutMs`。函数主体逻辑不动。

### src/settings.h【新发现：原评估漏】
- `#include <windows.h>` → platform.h（文件头"须在 httplite 之后"的包含顺序约束随之删除，两平台都不再引 windows.h 级别的东西——settings.h 变纯跨平台头）。
- `onetimeHomeDir`（_wgetenv+WideCharToMultiByte）→ `plat::homeDirUtf8()`。
- `saveSettingsFile`（MoveFileExW/DeleteFileW）→ platform。

### src/main.cpp
- 头：windows.h/shellapi.h/`#pragma comment` → 条件；POSIX 加 `<sys/wait.h>`（posix_spawn 用）。
- `parseCli`：Windows 保持 CommandLineToArgvW；POSIX 读 `/proc/self/cmdline`（NUL 分段，首段为程序名对应 argv[0]，跳过逻辑与现有一致）。入口 main 在 EUI-NEO 框架（glfw_app_main.cpp）手里，应用拿不到 argc/argv，/proc 是最小侵入方案。
- `copyText`：Windows 保持 Win32 原实现（零回归）；POSIX 一行转调 `core::window::setClipboardText`（EUI-NEO 内置，include 根已在 PUBLIC 路径，GLFW 后端 X11 下写 CLIPBOARD selection）。调用点全部在 UI 点击回调，窗口必然存活，满足 GLFW 剪贴板前置条件。
- `hhmmNow`/`expireAtFrom`：`localtime_s`→`plat::localTime`。
- `setAutostart`：POSIX 写/删 `~/.config/autostart/onetime.desktop`（XDG 规范；Exec 路径按 desktop entry spec 转义：`\` `"` `` ` `` `$` 前加反斜杠并整体加双引号，空格路径安全；Type=Application，Terminal=false；关闭=删除文件）。语义与 HKCU Run 对齐（每次开启重写，路径纠正）。
- `openInBrowser`：POSIX `posix_spawn("xdg-open", url)`（`<spawn.h>` + `<sys/wait.h>`）后立刻 `waitpid` 收尸（xdg-open 自行 detach 拉起浏览器，父进程不悬挂）；失败静默（与现 ShellExecuteW 无反馈一致）。
- `writeTplFile`/`deleteTplFile`：MoveFileExW/DeleteFileW→platform。
- 托盘：`c.tray(true)` 与设置页"最小化到托盘"开关行均包 `#ifdef _WIN32`（Linux 默认无托盘后端，避免用户开了开关却直接退出进程的误导；Windows 行为不变）。
- Sleep 类：无（main.cpp 不用）。

### tests/test_main.cpp
- `#include <windows.h>` 删；`Sleep(50)`→`std::this_thread::sleep_for(milliseconds(50))`；【审核补】`GetTempPathA(MAX_PATH,…)`→`std::filesystem::temp_directory_path()`（两平台统一，行为等价，均取 TEMP/TMP 目录）。
- 增补加密向量测试（见加密节），两平台共跑。

### CMakeLists.txt
- `CMAKE_MSVC_RUNTIME_LIBRARY` 与 `/utf-8` `/O2` `/LTCG` 等全部套 `if(MSVC)`。
- `onetime_core`：源列表平台化（crypto_win.cpp / crypto_posix.cpp）；链接 `WIN32 → bcrypt ws2_32`，`ELSE → Threads::Threads`（PUBLIC，与现 bcrypt ws2_32 一致，保证 onetime_tests 的 std::thread 在老 glibc 也链接）。
- `EUI_ENABLE_TRAY`：现顶层 FORCE ON 会让无 glib/gtk 的 Linux 环境直接配置失败（EUI-NEO option 自述）。改：`if(WIN32) FORCE ON else() FORCE OFF`，注释说明 Linux 装好 glib/gio 或 GTK3+libappindicator 后可改回 ON。
- Release POSIX 加 `-O2`（GCC 无默认优化）+ `-fno-plt` 不搞花活。

### 交付物
- `scripts/build-linux.sh`：检测 cmake/g++/make → 提示 apt 依赖（build-essential cmake xorg-dev libgl1-mesa-dev libglu1-mesa-dev；可选路径：libglib2.0-dev + pkg-config 装齐后 `-DEUI_ENABLE_TRAY=ON` 才有托盘）→ 配置（build-linux/ 目录，与 Windows build/ 分离）→ 构建 onetime + onetime_tests → 自动跑测试 → 打印产物路径。幂等可重跑。
- `docs/linux-build.md`：依赖说明、构建步骤、功能差异表（托盘默认无、剪贴板依赖 X11 会话、路径 ~/.onetime 不变）、故障排查（DISPLAY 缺失、glib/pkg-config 未装等）、建议安装 fonts-noto-cjk（系统字体链兜底时 CJK 优先级低）、附 curl 冒烟命令（Linux 侧复刻 Windows 冒烟验证）。
- README 增 Linux 一节。

## 验证

1. **Windows 零回归（本机执行）**：全量构建三个目标 + `onetime_tests` 全绿 + onetime.exe 时间戳核对（构建管线防 SIGPIPE 教训照旧）+ curl 冒烟（创建/取用/金库）。
2. **Linux（用户执行）**：build-linux.sh 全自动跑通含测试；NIST 向量与 CNG 一致性向量是硬门槛（不过即失败）。
3. **审查**：设计文档过 plan-code-reviewer；实现后重点复审 crypto_posix.cpp 与 platform.h 的每处条件编译。

## 风险表

| 风险 | 缓解 |
|---|---|
| 手写 GCM/SHA 出错 | NIST 向量 + CNG 硬编码期望值交叉验证 + 现有全量业务测试（往返/篡改/并发） |
| /proc/self/cmdline 在容器/特殊环境差异 | 拿不到时静默回退默认参数（与 Windows CommandLineToArgvW 失败分支一致） |
| X11 剪贴板在 Wayland 纯会话不可用 | 文档注明；GLFW 在 XWayland 下通常可用 |
| EUI-NEO Linux 分支本机无法编译验证 | 不改框架；构建脚本自检依赖给可读错误；首建问题由用户反馈迭代 |
| rename 对跨文件系统失败（tmp 与目标不同盘） | tmp 与目标同目录生成（现有做法已保证），单文件金库布局不受影响 |
| 托盘缺失导致设置项误导 | Linux 隐藏开关 + 文档差异表 |
| getrandom 在老内核（<3.17）ENOSYS | /dev/urandom fallback |

## 工作量

代码约 ±900 行（新增 crypto_posix.cpp ~330、platform.h ~120、build-linux.sh ~80、文档；其余为条件编译改造）。Windows 侧一次回归构建即可。
