# onetime-cpp 设置功能设计方案

> 版本 v2（已按 plan-code-reviewer 审核意见修订）· 2026-09-10
> 目标：新增"设置"页签，覆盖四类设置（服务/链接、行为、界面、运维），UI 与现有链接页/金库页完全一致。
> v2 变更：修复 P1-1（Ctrl+Enter 三路分支）、P1-2（托盘为框架内建，并入一期）；补 P2-3/5/6/7/8、P3-9~15。

## 1. 背景与目标

当前可调参数只有 4 个命令行开关（`-addr/-base/-ttl/-vault`），普通桌面用户无法触达；行为与外观全部写死。本方案新增第三个页签"设置"，把高频参数与偏好收进去。

**非目标**：不改变一次性链接的安全语义（读后即焚不可配）；不做多配置档案；不改 EUI-NEO 框架源码（项目自有 CMakeLists 的 `EUI_ENABLE_TRAY` 开关除外）。

## 2. 设置项总表（13 项）

| # | 分类 | 名称 | 控件 | 默认 | 生效时机 | 存储键 |
|---|------|------|------|------|----------|--------|
| S1 | 服务/链接 | 默认有效期 | segmented 5 档（30m/1h/8h/24h/7d） | 1h | 立即（**仅 UI 预选**，服务端默认仍只由 `-ttl` 控制，curl 行为不变） | `default_ttl` |
| S2 | 服务/链接 | 公共链接前缀（publicBase） | 单行输入 + 保存 | 空（用 Host 推导） | **重启**（服务线程持有启动时的 cfg 副本，链接由服务端拼接） | `public_base` |
| S3 | 服务/链接 | 监听地址 | 单行输入 + 保存 | 127.0.0.1:8787 | **重启**；保存时校验 host:port 形态；启动失败在设置页给 warn 状态行 | `listen_addr` |
| S4 | 服务/链接 | 金库目录 | 单行输入 + 保存 | ~/.onetime/secrets | **重启** | `vault_dir` |
| B1 | 行为 | 生成后自动复制链接 | switch | 关 | 立即 | `auto_copy_link` |
| B2 | 行为 | 存入后清空名称框 | switch | 开 | 立即 | `clear_name_after_put` |
| B3 | 行为 | 显示本会话记录 | switch | 开 | 立即（守卫仅作用于链接页记录区，设置页不受影响） | `show_records` |
| B4 | 行为 | 清空本会话记录 | 危险 Ghost 按钮（两步确认） | — | 立即 | 不持久化 |
| I1 | 界面 | 主题 | segmented 浅色/深色 | 浅色 | **重启**（clearColor 与 tokens 在 DslAppConfig 静态初始化时烘焙，见 §6-R1） | `theme` |
| I2 | 界面 | 界面缩放 | segmented 100%/125%/150% | 125%（现值） | **重启**（映射 DslAppConfig.uiScale） | `ui_scale` |
| I3 | 界面 | 开机自启 | switch | 关 | 立即（HKCU Run 键，切换时始终重写为当前 exe 绝对路径） | `autostart` |
| I4 | 界面 | 关闭时最小化到托盘 | switch | 关 | **重启**（**框架内建能力**：`.tray()` 配置 + 关闭拦截在 glfw 主循环已实现，见 §6-R2） | `minimize_to_tray` |
| O1 | 运维 | 服务日志落盘 | switch | 关 | **重启**（开关为 ServerConfig 启动期常量） | `log_to_file` |
| O2 | 运维 | 查看服务日志 | Ghost 按钮 → 页内只读卡片 | — | 立即 | 不持久化 |

重启生效的项在标签后统一加注"（重启生效）"，并在服务类区块顶部放一行 dim 提示（`txt(wrap=true)`，不用 fieldHead）："本区修改保存后，下次启动应用时生效。"

## 3. UI 设计

### 3.1 入口与页面结构

**入口（v3 修订：应用户要求，"设置"不再是第三个页签）**：内容页签保持两项 `一次性链接 | 本机金库`（260px 不变）；页眉右侧状态文字后新增"设置"按钮（Ghost，64×24），点击进入设置页（`st.tab=2`，`st.lastTab` 记住来源），按钮变 Primary"返回"，再点回到原页签。设置页复用现有页面骨架：同宽度内容列（`w`）、同滚动容器、同页脚。

**渲染边界（P2-7）**：滚动区现为"当前页 + composeTplPanel + composeRecords"固定串联。tab 2 时**只渲染 composeSettingsPage**，模板面板与本会话记录均加 tab 守卫（否则设置页会显示金库模板编辑器——模板面板按 `st.tab==0?link:vault` 选目标，tab 2 会误落 vault 分支）。

**快捷键（P1-1）**：现 onKeyEvent 为 `if(tab==0) startCreate(); else vaultPut();`——tab 2 会误触 `vaultPut()`（无空值守卫，快捷键路径绕过按钮 disabled）。改为三路分支：`tab==0 → startCreate(); tab==1 → vaultPut(); tab==2 → 无动作`。

```
┌ 设置 ────────────────────────────────────────────┐
│ 服务与链接                                        │
│ ───────────────────────────────────────────────  │
│ 默认有效期      [30m | 1h | 8h | 24h | 7d]       │
│ 公共链接前缀（重启生效）  [ https://xx.example  ] 保存 │
│   ↑ hint: 留空则按请求 Host 推导；反代/对外分发时填  │
│ 监听地址（重启生效）      [ 127.0.0.1:8787     ] 保存 │
│ 金库目录（重启生效）      [ ~/.onetime/secrets ] 保存 │
│   dim 提示: 本区修改保存后，下次启动应用时生效。      │
│ 行为                                              │
│ ───────────────────────────────────────────────  │
│ 生成后自动复制链接        (switch)                 │
│ 存入后清空名称框          (switch)                 │
│ 显示本会话记录            (switch)                 │
│ 清空本会话记录            [清空]→[确认清空]         │
│ 外观                                              │
│ ───────────────────────────────────────────────  │
│ 主题（重启生效）           [浅色 | 深色]            │
│ 界面缩放（重启生效）       [100% | 125% | 150%]     │
│ 开机自启                 (switch)                 │
│ 关闭时最小化到托盘（重启生效） (switch)             │
│ 运维                                              │
│ ───────────────────────────────────────────────  │
│ 服务日志落盘（重启生效）    (switch)                │
│   hint: 日志零泄密：只记事件与字节数，绝不记密钥材料  │
│ 查看服务日志              [查看]                   │
└───────────────────────────────────────────────────┘
```

### 3.2 一致性规范（逐条对齐现有两页）

- **区块**：`fieldHead(ui, t, id, 标题, 右侧提示, w)` + `hairline`，与链接页"密钥内容"、金库页"金库条目"同款。需换行的 hint 走 `txt(wrap=true, maxWidth=w)`，fieldHead 的 hint 是 12.5px monospace 单行，不承载长文案。
- **控件**：选项用 `segmented()`（同有效期行）；开关用 EUI-NEO `components/switch.h`，工厂函数是 **`toggleSwitch(ui, id)`**（非 `switch()`，关键字），`SwitchStyle(t.tokens)`；文本设置用 `input()` 单行 + 右侧 `btn(Primary, "保存")`，同时挂 `onEnter` 保存（与金库存入的 Enter 语义一致）；"清空记录"复用两步确认模式（点一下变"确认清空"，3 秒未确认自动回退——复用 `armedDelete` 单槽机制 + `timer.arm` 回弹，键用哨兵 `"session-records"`，与条目名天然不撞）。
- **Switch 无 disabled/opacity 能力（P2-4）**：托盘探测不可用时**直接隐藏该行**（不置灰）。
- **反馈**：保存成功走现有 `st.tplNote` 通道（"已保存"2.4s 自动消失）；校验失败写区块内 warn 色 note（同 `st.vNote` 样式）。
- **排版**：标签 13.5px `t.ink2`，行高 38px 与金库行一致；卡片 `components::card` 1px `t.hair` 边框、16px 内边距，同 ok 卡片。
- **颜色**：全部走 `AppTheme` token，不新造颜色。

### 3.3 交互细节

- 文本类设置（S2-S4）"保存"按钮仅在有改动时可用（对比初值）；保存成功后回写初值。
- S3 校验：`host:port` 形态（host 非空、port 1-65535 数字），失败给 warn note。
- **服务启动失败可见性（P2-6）**：服务线程把启动结果写入全局 `std::atomic<int> g_serverState`（0 启动中/1 正常/2 失败）；设置页服务区块内显示状态行：正常显示"服务运行中 · 监听 <addr>"（dim），失败显示"服务启动失败：地址可能被占用，请修改监听地址后重启"（warn）。页眉维持现状（静态文案）。
- S4 保存后提示"新目录在重启后启用，旧目录文件不会移动"。
- B4 清空后 `st.records.clear()`；两步确认与金库删除共用单槽 armedDelete（跨页 3 秒互斥解除为可接受边界，无状态污染）。
- O2 查看日志：文件不存在显示"未启用日志落盘"；存在则展示最后 64 KB 等宽只读卡片。读取用 `std::ifstream`（MSVC 默认共享读，服务线程追加不阻塞读取）；文件恰等于/小于 64 KB 全量显示。

## 4. 数据模型与存储

### 4.1 文件格式（沿用模板的纯文本先例，零新依赖）

`~/.onetime/settings.txt`，UTF-8，每行 `key=value`，`#` 注释，未知键忽略（向前兼容）。**路径恒为 `~/.onetime/`，不随 S4 金库目录变化**（复用 `tplPath()` 同款推导）。

解析规格（P3-11）：
- 按**第一个 `=`** 切分（值可再含 `=`）；
- 容错 UTF-8 BOM（记事本编辑场景）与 CRLF；
- `public_base` 保存时**去尾部斜杠**（服务端 `base + "/s/"` 直拼，server.cpp:578）；
- 非法值一律回退默认（如 `ui_scale=abc` → 1.25）。

写入原子化：临时文件 + `moveReplace`（与金库条目同款）。

### 4.2 配置优先级与加载时机

启动顺序（`dslAppConfig()` 静态初始化内）：

```
parseCli()（记录显式键位标记，仅在值被接受时置位——非法 -ttl 静默忽略不置位）
→ loadSettings() 覆盖 g_cli.cfg 与 UI 设置
→ 对显式键重放命令行值（命令行优先级最高）
→ 拼页眉/页脚/金库显示路径（g_headerStatus/g_footerText/g_vaultDisplay，必须晚于合并，P3-10）
→ 启动服务线程
```

- **S1 仅 UI 预选（P2-5）**：`default_ttl` 只写 `st.ttlIdx` 初值，不进 `g_cli.cfg.defaultTtlNs`；服务端默认仍只由 `-ttl` 控制。
- 立即生效项进 `PageState` 新增 `st.settings`；重启生效项落 settings.txt，下次启动进 cfg/DslAppConfig/服务线程。

### 4.3 运行时联动点

| 项 | 联动代码位置 |
|----|--------------|
| S1 | `PageState::ttlIdx` 初始化从设置来（现在硬编码 1） |
| B1 | `startCreate()` 成功回调末尾：`if (st.settings.autoCopyLink) copyWithFeedback("copy.link", st.link);`（直接复用，票据"复制链接"按钮自然显示 1.6s"已复制"，timer.copy 现成） |
| B2 | `vaultPut()` 成功回调：按设置补 `st.vName.clear()` |
| B3 | 链接页"本会话记录"区块外层 `if (st.settings.showRecords)` |
| I1/I2 | `dslAppConfig()` 内按设置选 light/dark 主题表与 uiScale |
| I3 | `RegSetKeyValueW(HKCU, ..., Run, "onetime", exe绝对路径)` / 删除键；每次切换重写当前路径（防 exe 移动后陈旧） |
| I4 | `EUI_ENABLE_TRAY ON` + `.tray(true)` + 托盘图标**绝对路径**（自启场景 cwd 不定，相对路径图标会加载失败→托盘降级→关闭变真退出，与预期相反，P3-13） |
| O1 | `ServerConfig` 加 `bool logToFile`（启动期常量）；`logEvent` 内按开关写 `~/.onetime/service.log`（追加，启动时若超过 1 MiB 先轮转为 `.old`） |
| O2 | `readLogTail(path, 64KB)` 纯函数 + 只读卡片 |

## 5. 实现方案（预估 +560 行 / -12 行，全部在 src/ 与项目 CMakeLists）

### 5.1 新增

1. `src/settings.h`：`struct Settings` + `parseSettings(text)→Settings` + `serializeSettings()` + `loadSettings()/saveSettings()` + `applySettingsToCli()`（显式键重放）（纯函数可单测）。
2. `main.cpp` 内 `composeSettingsPage(ui, t, w)`：约 300 行，全部复用现有小件。
3. `appThemeDark()`：照抄 light 表构造法——`a.tokens = components::theme::dark()` 起步再逐字段覆写，**必须覆盖 AppTheme 全部 13 字段**（tokens.background/primary/surface/surfaceHover/surfaceActive/text/border、pageBg、accentDeep、accentWash、warn、warnWash、dim、ink2、hair、hairSoft、linkWell），且 **`tokens.dark = true`**（组件库十余处交互态混色按它分支，漏设会整页交互态反色，P2-3）。深色色板：底 #16201e、面板 #1d2927、文字 #d8e2df、主青绿提亮 #2f9e8f、砖红提亮 #cf6f66、分隔线 #2c3a37、洗底色 #223330/#3a2622，对比度按 dim/ink2 深化先例保证 ≥4.5:1。
4. 日志管线：`logEvent` 加文件 sink（互斥锁内追加，路径启动期定）；`readLogTail` 纯函数。

### 5.2 修改

- `PageState`：加 `Settings settings` + 设置页 UI 态（armedClear 哨兵复用 armedDelete、日志展开、三个文本框草稿/初值）。
- `onKeyEvent`：三路分支（P1-1）。
- 滚动区：`tab==2` 只渲染设置页；模板面板与记录区加 tab 守卫（P2-7）。
- 页签 segmented：items 加"设置"，宽度 260→330。
- `parseCli()`：显式键位标记（值被接受才置位）。
- `dslAppConfig()`：合并时序按 §4.2；`.tray(true).trayTitle("onetime").trayIcon(绝对路径)`（I4 开启时）；服务线程写 `g_serverState`。
- `startCreate()`/`vaultPut()` 成功回调、记录区块，按 §4.3。
- 项目 `CMakeLists.txt`：`EUI_ENABLE_TRAY OFF→ON`。

### 5.3 测试计划

自动（新增约 14 条断言，console 测试工程不链 EUI）：
- settings 往返：默认序列化→解析==默认；改各字段→往返相等。
- 解析容错：注释/未知键/缺行/CRLF/**BOM**/**值含 `=`**（`public_base=http://x/?a=b`）；非法值回退（`ui_scale=abc`→1.25）。
- `public_base` 尾斜杠剥离；`default_ttl` 五档字符串↔索引映射。
- 优先级：settings 值被显式命令行值覆盖；命令行缺省时 settings 生效；**非法 CLI 值不置位不覆盖**。
- `readLogTail` 边界：空文件/小于 64KB/恰 64KB/超 64KB。

手动验收清单（UI 行为进不了自动测试，P3-15）：
1. tab 2 按 Ctrl+Enter 无任何请求发出（对照服务日志）。
2. 每个 switch 切换后重启应用，状态保持。
3. S3 填非法地址保存被拦；填被占用端口重启后设置页出现 warn 状态行。
4. 深色主题重启后逐页检查（链接/金库/设置/弹层 hover/toast）。
5. B1 开启后生成链接，票据"复制链接"按钮自动变"已复制"1.6s。
6. I4 开启后关窗口→托盘图标，菜单 Show/Exit 可用（注：托盘菜单文案为框架内建英文 "Show"/"Exit"，接受现状）。
7. 现有 114 条自动回归全过。

## 6. 风险与开放问题

- **R1 主题/缩放重启生效**：`DslAppConfig` 为静态 const（clearColor、uiScale 启动即定），运行时切换需框架支持动态重配。**决策：接受重启生效**，与 S2-S4 同批标注。
- **R2 托盘（v2 重写）**：关闭拦截与托盘菜单是框架 runner 层内建（glfw_app_main close 回调 → hideToTrayRequested；tray_bridge 菜单 Show/Exit），**非框架改造**。真实工作 = 项目 CMake `EUI_ENABLE_TRAY ON` + `.tray()` 配置 + 图标绝对路径。残余风险：(a) 该开关现处 OFF，打开后 Windows 构建是否引入额外依赖/告警需编译验证，失败则回退 OFF 并将 I4 移出一期；(b) 图标资产 `assets/icon.png` 需存在且随包；(c) 菜单文案英文，接受。
- **R3 日志落盘（v2 简化）**：`bool logToFile` 进 ServerConfig（`maxEntries` 有同款先例），启动期常量，无 atomic、无运行时开关竞态。路径 `~/.onetime/service.log`，1 MiB 启动轮转。
- **R4 深色主题对比度**：手工色表，需人工 + vision-reader 逐页验收（见手动清单 4）。
- **R5 settings.txt 并发**：仅 UI 线程读写；服务线程不读该文件。
- **R6 服务启动失败反馈**：现状 `runServer` 结果被丢弃（本缺陷先于本方案存在，但 S3 把它放大）；本方案以 `g_serverState` + 设置页状态行做最小闭环，不改页眉静态文案设计。

## 7. 分期

单期交付全部 13 项；唯一条件项：I4 依赖 R2 编译验证，失败则仅 I4 顺延，其余不受影响。
