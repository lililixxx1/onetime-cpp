# Linux 构建与使用

设计文档见 [linux-design.md](linux-design.md)。本文只讲怎么构建、有什么差异、出问题查哪里。

## 一键构建（Ubuntu 22.04 / Debian 12 级）

```bash
sudo apt install build-essential cmake xorg-dev libgl1-mesa-dev libglu1-mesa-dev \
  libwayland-dev libwayland-bin
./scripts/build-linux.sh
```

脚本会自检工具与依赖、配置（`build-linux/` 目录，与 Windows 的 `build/` 互不干扰）、构建 `onetime` 与 `onetime_tests`，并自动跑完 154 项测试（含 NIST 加密向量与 Windows CNG 跨实现一致性向量——不通过即失败，不会带病交付）。建议同时安装中文字体：`sudo apt install fonts-noto-cjk`。

## 功能差异（相对 Windows 版）

| 项 | Windows | Linux |
|---|---|---|
| 托盘（关闭最小化到托盘） | 有 | 默认无（设置页开关隐藏）。装 `pkg-config` + `libglib2.0-dev` 后 `TRAY=1 ./scripts/build-linux.sh` 可开 |
| 开机自启 | HKCU Run 键 | `~/.config/autostart/onetime.desktop`（XDG 标准） |
| 剪贴板 | Win32 CF_UNICODETEXT | GLFW/X11 剪贴板；纯 Wayland 会话需 XWayland（主流桌面默认有） |
| 加密 | CNG（系统） | 自带实现（SHA-256 / AES-256-GCM，src/crypto_posix.cpp），测试向量与 CNG 逐字节对齐 |
| 字体 | 微软雅黑 | 探测 Noto CJK / 文泉驿 / arphic，未命中走框架默认链 |
| 数据目录 | `%USERPROFILE%\.onetime\` | `~/.onetime/`（settings.txt / service.log / secrets/ / agent-template.*.txt 同构） |

设置文件可跨平台拷贝：从 Windows 带来的 `minimize_to_tray=1` 在 Linux 上保留但不生效（无托盘后端），拷回 Windows 仍然有效；`autostart=1` 首次启动会自动写入本平台的自启机制。

## 运行

```bash
./build-linux/onetime              # GUI 窗口 + 127.0.0.1:8787 服务
./build-linux/onetime -addr 127.0.0.1:9000 -vault ~/my-secrets
```

命令行参数与 Windows 版一致（`-addr` / `-base` / `-ttl` / `-vault`）。

## 冒烟验证（与 Windows 相同的验收路径）

```bash
link=$(curl -s -d 'top-secret' http://127.0.0.1:8787/create)   # 出票
curl -s -o ~/.onetime/received.key -w '%{http_code}\n' "$link"  # 取用一次 → 200
cat ~/.onetime/received.key                                     # top-secret
curl -s -o /dev/null -w '%{http_code}\n' "$link"                # 二次取用 → 404
```

## 故障排查

- **配置阶段报 glib/gio/gtk 相关错误**：说明以 `-DEUI_ENABLE_TRAY=ON` 配置但缺依赖。默认脚本不会开托盘；要开就装 `pkg-config libglib2.0-dev`（或 `libgtk-3-dev libappindicator3-dev`）。
- **运行报无法打开显示 / DISPLAY 未设置**：GUI 需要图形会话（X11 或 XWayland）。SSH 无头环境请只跑 `onetime_tests`。
- **界面中文是方块**：`sudo apt install fonts-noto-cjk`。
- **重启服务报端口占用（bind 失败）**：Linux TIME_WAIT 窗口约 60s；代码已设 `SO_REUSEADDR`，若仍出现检查是否有残留进程 `pgrep onetime`。
- **剪贴板复制无效**：确认桌面会话可用（`echo $DISPLAY` 非空）；纯 Wayland 用户确认 XWayland 开启。

## 从源码结构看平台层

所有 OS 差异集中在 `src/platform.h`（文件/时间/套接字/环境），加密按平台编译 `crypto_win.cpp` / `crypto_posix.cpp`（CMake 自动选择）。业务代码（server.cpp / main.cpp 等）不含任何 `#ifdef` 之外的系统调用。
