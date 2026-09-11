#!/usr/bin/env bash
# build-linux.sh — onetime Linux 一键构建 + 测试
# 用法：./scripts/build-linux.sh          （构建 onetime + onetime_tests 并跑测试）
#       TRAY=1 ./scripts/build-linux.sh   （启用托盘，需先装 glib/gio + pkg-config，见 docs/linux-build.md）
set -euo pipefail
cd "$(dirname "$0")/.."

# ---------- 工具自检 ----------
miss=()
for t in cmake g++ make; do
    command -v "$t" >/dev/null 2>&1 || miss+=("$t")
done
if [ ${#miss[@]} -gt 0 ]; then
    echo "缺少构建工具: ${miss[*]}"
    echo "Ubuntu/Debian 安装: sudo apt install build-essential cmake"
    exit 1
fi

# ---------- 系统依赖探测（GLFW/X11/Wayland + OpenGL）----------
need_pkgs=()
pkg_installed() {  # 粗探测：头文件/库文件存在即认为可用
    case "$1" in
        xorg-dev) [ -d /usr/include/X11 ];;
        libgl1-mesa-dev) ls /usr/include/GL/gl.h >/dev/null 2>&1 || ls /usr/lib/*/libGL.so* >/dev/null 2>&1;;
        libglu1-mesa-dev) ls /usr/include/GL/glu.h >/dev/null 2>&1 || ls /usr/lib/*/libGLU.so* >/dev/null 2>&1;;
        libwayland-dev) ls /usr/include/wayland-client.h >/dev/null 2>&1;;
        libwayland-bin) command -v wayland-scanner >/dev/null 2>&1;;
        pkg-config) command -v pkg-config >/dev/null 2>&1;;
        libglib2.0-dev) pkg-config --exists gio-2.0 2>/dev/null;;
        *) false;;
    esac
}
# bundled GLFW 在 Linux 上默认启用 Wayland 后端，编译期需要 wayland 开发库 + wayland-scanner；
# 用户显式传 -DGLFW_BUILD_WAYLAND*（如 OFF 只要 X11）时由其自管依赖，不再检查
wayland_pkgs="libwayland-dev libwayland-bin"
for a in "$@"; do
    case "$a" in -DGLFW_BUILD_WAYLAND*) wayland_pkgs="";; esac
done
for p in xorg-dev libgl1-mesa-dev libglu1-mesa-dev $wayland_pkgs; do
    pkg_installed "$p" || need_pkgs+=("$p")
done
if [ ${#need_pkgs[@]} -gt 0 ]; then
    echo "缺少系统依赖: ${need_pkgs[*]}"
    echo "安装: sudo apt install ${need_pkgs[*]}"
    echo "（其他发行版对应：X11/Wayland 开发包 + OpenGL/GLU 开发包）"
    exit 1
fi

# ---------- 托盘（可选，默认关）----------
tray_flag=OFF
if [ "${TRAY:-0}" = "1" ]; then
    for p in pkg-config libglib2.0-dev; do
        if ! pkg_installed "$p"; then
            echo "TRAY=1 需要 pkg-config 与 glib/gio 开发包（sudo apt install pkg-config libglib2.0-dev）"
            exit 1
        fi
    done
    tray_flag=ON
fi

# ---------- 配置 + 构建 ----------
BUILD_DIR=build-linux
cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DEUI_ENABLE_TRAY="$tray_flag" "$@" .
cmake --build "$BUILD_DIR" -j"$(nproc)"

# ---------- 测试（NIST 向量 + CNG 跨实现一致性 + 全部安全不变量）----------
"$BUILD_DIR/onetime_tests"

BIN="$BUILD_DIR/onetime"
case "$BIN" in /*) ;; *) BIN="./$BIN";; esac
echo
echo "构建完成：$BIN"
echo "冒烟（另开终端运行 GUI 后执行）："
echo "  curl -s -d 'top-secret' http://127.0.0.1:8787/create"
echo "  curl -s -o ~/.onetime/received.key -w '%{http_code}\n' '<上面返回的链接>' && cat ~/.onetime/received.key"
