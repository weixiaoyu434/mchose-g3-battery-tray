#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mouse_battery_tray.py — 迈从 G3 电量托盘图标（系统托盘 + 内置仪表盘）

适用型号: 仅初代迈从 G3（2.4G 接收器 258A:0138 / 有线 258A:0136，SINO WEALTH 方案）。
G3 V2 / 新版 G3（VID 0x3837 或 0x5253）使用不同协议族，本工具不支持。

用法:
    python mouse_battery_tray.py       # 建议用 pythonw mouse_battery_tray.py（无控制台窗口）

托盘图标状态（实测协议驱动）:
  * 接收器(258A:0138)在线: 被动监听 ~48s 周期广播 [09 0A 05 电量%]，
    图标 = 电池填充 + 按电量变色(≥50 绿 / 20-49 黄 / <20 红)，悬停显示百分比
  * 有线模式(258A:0136 出现，接收器消失): 判定为充电中，
    图标 = 电池 + 闪电，悬停显示"上次电量"
  * 广播电量到 100%: 图标 = 满格绿 + 对勾，"已充满"
  * 接收器/鼠标都不在: 灰色电池 + 红色斜杠

右键菜单: 状态、打开仪表盘(http://127.0.0.1:8765)、退出。
"""

import ctypes
import os
import sys
import threading
import time
import webbrowser

from ctypes import create_string_buffer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mouse_battery_probe as mbp  # noqa: E402
import mouse_battery_web as web    # noqa: E402

from http.server import ThreadingHTTPServer  # noqa: E402
from PIL import Image, ImageDraw             # noqa: E402
import pystray                               # noqa: E402
from pystray import Menu, MenuItem           # noqa: E402

G3_STATUS_PAGE, G3_STATUS_USAGE = mbp.G3_STATUS_PAGE, mbp.G3_STATUS_USAGE
WIRED_PID = 0x0136          # 有线模式 PID（实测: 插线后出现，接收器消失）
VENDOR_PAGE, VENDOR_USAGE = 0xFF01, 0x01

# 托盘状态
TRAY = {"mode": "offline", "level": None, "wired": False}
# mode: offline/wait/battery/charging/full
ICON = None
PORT = 8765
_ICON_CACHE = {}

# ------------------------------------------------------------ 图标绘制


def _level_color(p):
    if p is None:
        return (150, 155, 165, 255)
    if p >= 50:
        return (80, 220, 120, 255)
    if p >= 20:
        return (250, 190, 60, 255)
    return (245, 100, 100, 255)


GRAY = (150, 155, 165, 255)
GREEN = (80, 220, 120, 255)
BOLT = (255, 240, 90, 255)
DARK = (24, 26, 30, 255)
RED = (245, 100, 100, 255)


def make_icon(mode, level):
    key = (mode, level)
    if key in _ICON_CACHE:
        return _ICON_CACHE[key]
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    if mode == "offline":
        d.rounded_rectangle([4, 18, 46, 46], radius=6, outline=GRAY, width=4)
        d.rounded_rectangle([48, 25, 57, 39], radius=2, fill=GRAY)
        d.line([8, 52, 56, 12], fill=RED, width=5)
    else:
        col = GREEN if mode == "full" else (
            GRAY if mode in ("wait", "charging") else _level_color(level))
        d.rounded_rectangle([4, 18, 46, 46], radius=6, outline=col, width=4)
        d.rounded_rectangle([48, 25, 57, 39], radius=2, fill=col)
        if mode == "full":
            d.rounded_rectangle([8, 22, 42, 42], radius=3, fill=GREEN)
            d.line([(15, 32), (25, 41), (42, 22)], fill=DARK, width=5, joint="curve")
        elif mode == "charging":
            # 不显示电量（有线固件不提供），只画闪电
            d.polygon([(30, 10), (16, 34), (25, 34), (22, 54), (39, 28), (29, 28), (34, 10)],
                      fill=BOLT, outline=DARK)
        elif mode == "battery" and level:
            w = max(3, int(34 * level / 100))
            d.rounded_rectangle([8, 22, 8 + w, 42], radius=2, fill=col)
    _ICON_CACHE[key] = img
    return img


def status_tip():
    m, lv = TRAY["mode"], TRAY["level"]
    if m == "charging":
        return "迈从 G3 充电中"
    if m == "wait":
        return "迈从 G3 已连接，等待电量广播…"
    if m == "full":
        return "迈从 G3 已充满（100%）"
    if m == "battery":
        return "迈从 G3 电量 %d%%（使用电池）" % lv
    return "未找到 G3 接收器/鼠标"


# ------------------------------------------------------------ 托盘更新

def set_mode(mode, level=None):
    if level is not None:
        TRAY["level"] = level
    if TRAY["mode"] == mode:
        return
    TRAY["mode"] = mode
    try:
        with web.LOCK:
            web.STATE["charging"] = (mode == "charging")
    except Exception:
        pass
    refresh_tray()


def refresh_tray():
    if ICON is None:
        return
    try:
        ICON.icon = make_icon(TRAY["mode"], TRAY["level"])
        ICON.title = status_tip()
        ICON.update_menu()
    except Exception as e:
        web.log(f"托盘刷新异常: {e!r}")


_original_handle_frame = web.handle_frame  # 必须先捕获原函数，再替换（否则钩子递归调用自己）


def handle_frame_hook(data):
    _original_handle_frame(data)  # 仪表盘/日志照常
    if len(data) >= 4 and data[1] == 0x0A and data[2] in (0x05, 0x06):
        # 0x05=状态帧（实测）；0x06=疑似充电帧
        lv = data[3]
        if TRAY.get("wired"):
            set_mode("charging")  # 有线固件不提供电量，按要求只显示充电中
        elif lv >= 100:
            set_mode("full", lv)
        else:
            set_mode("battery", lv)


web.handle_frame = handle_frame_hook  # 帧入口统一走钩子


# ------------------------------------------------------------ 即时电量查询（旧版 M-HUB 同款协议，抓包逆向）

# 通道: 0xFF02/0x02 集合 Feature Report rid 0x09
# 命令: SET 521B = [0x09] + [09 0C 09 01 01 00 01 00] + 512 零
# 响应: GET 521B = [09 0C 09 01 01 00 01 00 电量% ...]
# 注意: 缓冲区必须 521 字节（1 rid + 520 载荷），520 会被设备 NAK；
#       且 SET/GET 必须用独立于输入监听的句柄（hidclass 按句柄串行，同句柄
#       挂着阻塞 ReadFile 时 SetFeature 会死锁）

def query_battery(cmd_handle):
    buf = create_string_buffer(521)
    buf[0] = 0x09
    buf[1:9] = bytes([0x09, 0x0C, 0x09, 0x01, 0x01, 0x00, 0x01, 0x00])
    if not mbp.hid.HidD_SetFeature(cmd_handle, buf, 521):
        return None
    time.sleep(0.05)
    buf2 = create_string_buffer(521)
    buf2[0] = 0x09
    if not mbp.hid.HidD_GetFeature(cmd_handle, buf2, 521):
        return None
    raw = buf2.raw[:9]
    if raw[:8] == bytes([0x09, 0x0C, 0x09, 0x01, 0x01, 0x00, 0x01, 0x00]) \
            and 0 <= raw[8] <= 100:
        return raw[8]
    return None


def battery_querier(hq, sid):
    """接收器连接期间的即时电量轮询线程（连接后快速重试，成功后 30 秒粒度）。"""
    attempts = 0
    while TRAY.get("qsession") == sid:
        res = {}

        def work():
            res["lv"] = query_battery(hq)

        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(4)
        if "lv" not in res:
            web.log("电量查询超时（鼠标休眠?），本轮查询线程退出，广播仍有效")
            break
        lv = res["lv"]
        attempts += 1
        if lv is not None:
            if attempts <= 5 or web.STATE.get("battery") != lv:
                web.log(f"即时查询: 电量 {lv}%")
            set_mode("full" if lv >= 100 else "battery", lv)
            with web.LOCK:
                web.STATE["battery"] = lv
                web.STATE["battery_ts"] = time.time()
                if not web.STATE["history"] or web.STATE["history"][-1][1] != lv:
                    web.STATE["history"].append((time.time(), lv))
        elif attempts == 1:
            web.log("首次即时查询未响应（设备初始化中），快速重试中…")
        # 失败且在前 5 次: 2s 快速重试；否则 30s 粒度；会话结束即退
        wait = 2 if (lv is None and attempts < 5) else 30
        for _ in range(wait):
            if TRAY.get("qsession") != sid:
                break
            time.sleep(1)
    try:
        mbp.kernel32.CloseHandle(hq)
        mbp._OPEN_HANDLES.remove(hq)
    except Exception:
        pass


# ------------------------------------------------------------ 后台监督

def tray_supervisor():
    while True:
        receiver = vendor_dev = wired = wired_status = None
        try:
            for d in mbp.enumerate_hid_devices():
                if d["vid"] != mbp.G3_VID:
                    continue
                c = d["caps"]
                if d["pid"] == mbp.G3_PID \
                        and (c.UsagePage, c.Usage) == (G3_STATUS_PAGE, G3_STATUS_USAGE) \
                        and c.InputReportByteLength == 8:
                    receiver = d
                elif d["pid"] == mbp.G3_PID \
                        and (c.UsagePage, c.Usage) == (VENDOR_PAGE, VENDOR_USAGE) \
                        and c.FeatureReportByteLength == 8:
                    vendor_dev = d
                elif d["pid"] == WIRED_PID or "g3 gaming" in (d["product"] or "").lower():
                    wired = d
                    if (c.UsagePage, c.Usage) == (G3_STATUS_PAGE, G3_STATUS_USAGE) \
                            and c.InputReportByteLength == 8:
                        wired_status = d
        except Exception as e:
            web.log(f"枚举异常: {e!r}")

        if receiver is not None:
            h = mbp.open_path(receiver["path"], mbp.GENERIC_READ | mbp.GENERIC_WRITE) \
                or mbp.open_path(receiver["path"], mbp.GENERIC_READ)
            if h is None:
                web.log("打开接收器状态集合失败，5s 后重试")
                set_mode("offline")
                time.sleep(5)
                continue
            mac = web.read_mac(vendor_dev) if vendor_dev else ""
            with web.LOCK:
                web.STATE["connected"] = True
                web.STATE["connected_since"] = time.time()
                web.STATE["mac"] = mac
                web.STATE["product"] = receiver["product"]
            web.log(f"接收器已连接（MAC={mac or '未知'}），监听广播…")
            set_mode("wait")
            # 即时电量查询线程（独立命令句柄，连接后 ~1s 出电量，30s 粒度刷新）
            TRAY["qsession"] = time.time()
            hq = mbp.open_path(receiver["path"], mbp.GENERIC_READ | mbp.GENERIC_WRITE)
            if hq is not None:
                threading.Thread(target=battery_querier, args=(hq, TRAY["qsession"]),
                                 daemon=True, name="querier").start()
            try:
                web.reader_loop(receiver, h, silence_timeout=180.0)  # 3 个广播周期
            except Exception as e:
                web.log(f"读取异常（监督线程已恢复）: {e!r}")
            TRAY["qsession"] = None
            mbp.kernel32.CloseHandle(h)
            try:
                mbp._OPEN_HANDLES.remove(h)
            except ValueError:
                pass
            with web.LOCK:
                web.STATE["connected"] = False
            set_mode("offline")   # 下一轮重新评估（可能转充电）
            time.sleep(2)
        elif wired is not None:
            with web.LOCK:
                web.STATE["connected"] = False
                web.STATE["product"] = wired.get("product") or "G3 Gaming Mouse"
            set_mode("charging")
            # 充电期间保持监听有线状态通道：抓里程碑/充满/插拔瞬间的帧
            h = None
            if wired_status is not None:
                h = mbp.open_path(wired_status["path"], mbp.GENERIC_READ | mbp.GENERIC_WRITE) \
                    or mbp.open_path(wired_status["path"], mbp.GENERIC_READ)
            if h is not None:
                web.log("有线模式：监听状态通道（等待充电相关帧）…")
                TRAY["wired"] = True
                try:
                    web.reader_loop(wired_status, h, silence_timeout=1800.0)  # 有线通道本就静默
                except Exception as e:
                    web.log(f"有线读取异常（监督线程已恢复）: {e!r}")
                TRAY["wired"] = False
                mbp.kernel32.CloseHandle(h)
                try:
                    mbp._OPEN_HANDLES.remove(h)
                except ValueError:
                    pass
                set_mode("offline")  # 有线断开（拔线）→ 下一轮回到接收器模式
                time.sleep(2)
            else:
                time.sleep(5)
        else:
            with web.LOCK:
                web.STATE["connected"] = False
                web.STATE["product"] = ""
            set_mode("offline")
            time.sleep(5)


# ------------------------------------------------------------ 托盘菜单

def on_dashboard(icon, item):
    webbrowser.open(f"http://127.0.0.1:{PORT}")


def on_exit(icon, item):
    web.log("退出")
    icon.stop()
    os._exit(0)


def build_menu():
    return Menu(
        MenuItem(lambda it: status_tip(), None, enabled=False),
        Menu.SEPARATOR,
        MenuItem("打开仪表盘", on_dashboard),
        MenuItem("退出", on_exit),
    )


# ------------------------------------------------------------ 主流程

def acquire_single_instance():
    """命名互斥体防止重复实例（开机自启后再手动启动时直接退出）。"""
    mbp.kernel32.CreateMutexW(None, False, "MCHOSE_G3_BATTERY_TRAY")
    return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS


def main():
    global ICON, PORT
    if not acquire_single_instance():
        web.log("已有托盘实例在运行，本次退出")
        os._exit(0)
    PORT = web.pick_port()
    try:
        ICON = pystray.Icon("g3battery", icon=make_icon("offline", None),
                            title="迈从 G3 电量监视", menu=Menu(build_menu))
        ICON.run_detached()
        refresh_tray()
    except Exception as e:
        web.log(f"托盘初始化失败（仅后台模式）: {e!r}")
        ICON = None

    threading.Thread(target=tray_supervisor, daemon=True, name="supervisor").start()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), web.Handler)
    web.log(f"托盘已启动 · 仪表盘 http://127.0.0.1:{PORT} · Ctrl+C 退出")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        web.log("退出")
    os._exit(0)  # 读线程阻塞在 HID IRP 上，直接终止进程


if __name__ == "__main__":
    main()
