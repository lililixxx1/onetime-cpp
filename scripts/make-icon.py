#!/usr/bin/env python3
# 生成 onetime 应用图标（配色与 UI 强调色 #0e6e64 一致）：
#   assets/icon.png  — 256x256 RGBA，运行时窗口/托盘图标的源资产
#   assets/icon.ico  — 16~256 多尺寸，Windows exe 资源（app.rc 引用）
#   src/icon_png.h   — icon.png 的字节数组（单文件分发不携带 assets/，
#                      启动时由 main.cpp 写到临时目录交给 EUI 加载）
# 重新生成：python3 scripts/make-icon.py（需 Pillow）
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
BASE = 4  # 超采样倍数（抗锯齿）
GREEN = (14, 110, 100, 255)  # #0e6e64，见 src/main.cpp 界面配色注释
WHITE = (255, 255, 255, 255)


def draw() -> Image.Image:
    w = 512 * BASE
    img = Image.new("RGBA", (w, w), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([4 * BASE, 4 * BASE, w - 4 * BASE, w - 4 * BASE],
                        radius=int(w * 0.21), fill=GREEN)
    # 白色钥匙：圆环头 + 竖杆 + 双齿（齿朝右），略上移留出光学重心
    t = int(w * 0.075)  # 线宽
    cx = int(w * 0.465)
    ring_cy = int(w * 0.355)
    ring_r = int(w * 0.150)
    d.ellipse([cx - ring_r, ring_cy - ring_r, cx + ring_r, ring_cy + ring_r],
              outline=WHITE, width=t)
    shaft_x0, shaft_x1 = cx - t // 2, cx + t // 2
    shaft_top = ring_cy + ring_r - t // 3
    shaft_bot = int(w * 0.73)
    d.rectangle([shaft_x0, shaft_top, shaft_x1, shaft_bot], fill=WHITE)
    tooth_end = cx + int(w * 0.165)
    for y in (int(w * 0.545), int(w * 0.655)):  # 齿间隙 ≥0.035W，32px 小图也能分开
        d.rectangle([shaft_x1, y, tooth_end, y + t], fill=WHITE)
    return img.resize((512, 512), Image.LANCZOS)


master = draw()
(ROOT / "assets").mkdir(exist_ok=True)
icon = master.resize((256, 256), Image.LANCZOS)
icon.save(ROOT / "assets/icon.png", optimize=True)
master.resize((256, 256), Image.LANCZOS).save(
    ROOT / "assets/icon.ico",
    sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128),
           (256, 256)])

data = (ROOT / "assets/icon.png").read_bytes()
rows = ["    " + ", ".join(f"0x{b:02x}" for b in data[i:i + 16]) + ","
        for i in range(0, len(data), 16)]
(ROOT / "src/icon_png.h").write_text(
    "// 由 scripts/make-icon.py 生成（源资产 assets/icon.png），勿手改。\n"
    "// 单文件分发不携带 assets/：图标 PNG 内嵌进二进制，启动时写到临时\n"
    "// 目录再交给 EUI iconPath 加载（见 main.cpp writeIconTempFile）。\n"
    "#pragma once\n#include <cstddef>\n\n"
    "inline constexpr unsigned char kIconPng[] = {\n" + "\n".join(rows) +
    "\n};\ninline constexpr std::size_t kIconPngSize = sizeof(kIconPng);\n",
    encoding="utf-8")
print(f"assets/icon.png {len(data)} B, "
      f"assets/icon.ico {(ROOT / 'assets/icon.ico').stat().st_size} B, "
      f"src/icon_png.h written")
