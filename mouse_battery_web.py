#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mouse_battery_web.py — 迈从 G3 电量监视仪表盘（本地 Web 服务）

用法:
    python mouse_battery_web.py        # 浏览器打开 http://127.0.0.1:8765

后端复用 mouse_battery_probe.py 的 ctypes HID 读取（纯被动监听接收器广播，
不向设备写入任何数据），自动重连。dashboard.html 与本脚本同目录、可随时改。

协议（实测逆向）: 0xFF02/0x02 集合 Input Report rid=0x09 每 ~48s 上报
[09 0A 05 电量% 0x00×4]；[09 0A 02 X ...] 为事件帧。
"""

import json
import os
import socket
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import ctypes
from ctypes import byref, c_ulong, create_string_buffer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mouse_battery_probe as mbp  # noqa: E402

G3_STATUS_PAGE, G3_STATUS_USAGE = mbp.G3_STATUS_PAGE, mbp.G3_STATUS_USAGE
VENDOR_PAGE, VENDOR_USAGE = 0xFF01, 0x01  # MAC/序列所在的厂商集合

LOCK = threading.Lock()
STATE = {
    "connected": False,
    "battery": None,
    "battery_ts": None,
    "charging": False,     # 有线充电模式（托盘写入，仪表盘展示用）
    "mac": "",
    "product": "",
    "frame_count": 0,
    "connected_since": None,
    "history": deque(maxlen=240),   # (ts, battery%)，约 48s 一个点
    "frames": deque(maxlen=60),     # 原始帧日志，最新在前
}

DASH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")


LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tray.log")


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:  # pythonw 模式下 stdout 不可见，落盘一份便于排查
        if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 1024 * 1024:
            os.remove(LOG_PATH)
        with open(LOG_PATH, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
    except OSError:
        pass


def note_for(data):
    if len(data) >= 4 and data[1] == 0x0A:
        if data[2] == 0x05:
            return f"电量 {data[3]}%"
        if data[2] == 0x02:
            return "事件"
    return ""


def handle_frame(data):
    note = note_for(data)
    is_battery = len(data) >= 4 and data[1] == 0x0A and data[2] == 0x05
    with LOCK:
        STATE["frame_count"] += 1
        STATE["frames"].appendleft({
            "t": time.time(),
            "hex": data.hex(" ").upper(),
            "note": note,
        })
        if is_battery:
            STATE["battery"] = data[3]
            STATE["battery_ts"] = time.time()
            STATE["history"].append((time.time(), data[3]))
    if is_battery:
        log(f"电量帧: {data[3]}%")


def read_mac(vendor_dev):
    """从 0xFF01/0x01 集合 Feature rid=0x0A 读设备 MAC（只读）。"""
    h = mbp.open_path(vendor_dev["path"], mbp.GENERIC_READ | mbp.GENERIC_WRITE)
    if h is None:
        return ""
    try:
        size = vendor_dev["caps"].FeatureReportByteLength
        buf = create_string_buffer(size)
        buf[0] = 0x0A
        if mbp.hid.HidD_GetFeature(h, buf, size):
            raw = buf.raw[:size]
            # 实测响应: [06, MAC×6, 00] —— 首字节是响应标记 0x06，不回显报告 ID
            if len(raw) >= 7 and raw[0] == 0x06:
                return ":".join(f"{b:02X}" for b in raw[1:7])
    finally:
        mbp.kernel32.CloseHandle(h)
        try:
            mbp._OPEN_HANDLES.remove(h)
        except ValueError:
            pass
    return ""


def reader_loop(dev, handle, silence_timeout=180.0):
    size = dev["caps"].InputReportByteLength
    buf = create_string_buffer(size)
    n = c_ulong()
    state = {"last": time.time()}

    def watchdog():
        # 静默看门狗：句柄僵死（枚举窗口期打开的半死设备等）时强制关闭，
        # 让阻塞中的 ReadFile 失败返回，监督线程重连新句柄
        while True:
            if time.time() - state["last"] > silence_timeout:
                log(f"{dev.get('short', '')} 超过 {silence_timeout:.0f}s 无数据，重置监听句柄")
                mbp.kernel32.CloseHandle(handle)
                return
            time.sleep(1.0)

    threading.Thread(target=watchdog, daemon=True, name="watchdog").start()
    while True:
        if mbp.kernel32.ReadFile(handle, buf, size, byref(n), None):
            state["last"] = time.time()
            handle_frame(buf.raw[:n.value])
        else:
            err = ctypes.get_last_error()
            log(f"输入读取结束 err={err}（设备拔出/休眠/句柄被重置），准备重连")
            return


def supervisor():
    """常驻：找接收器 → 打开状态集合 → 阻塞读帧；断开后自动重连。"""
    while True:
        handle = None
        try:
            status_dev = vendor_dev = None
            for d in mbp.enumerate_hid_devices():
                if d["vid"] != mbp.G3_VID or d["pid"] != mbp.G3_PID:
                    continue
                c = d["caps"]
                if (c.UsagePage, c.Usage) == (G3_STATUS_PAGE, G3_STATUS_USAGE) \
                        and c.InputReportByteLength == 8:
                    status_dev = d
                elif (c.UsagePage, c.Usage) == (VENDOR_PAGE, VENDOR_USAGE) \
                        and c.FeatureReportByteLength == 8:
                    vendor_dev = d
            if status_dev is None:
                with LOCK:
                    STATE["connected"] = False
                    STATE["product"] = ""
                log("未找到 G3 接收器（258A:0138），5s 后重试")
                time.sleep(5)
                continue

            handle = mbp.open_path(status_dev["path"], mbp.GENERIC_READ | mbp.GENERIC_WRITE)
            if handle is None:
                handle = mbp.open_path(status_dev["path"], mbp.GENERIC_READ)
            if handle is None:
                log("打开状态集合失败（权限不足?），5s 后重试")
                time.sleep(5)
                continue

            mac = read_mac(vendor_dev) if vendor_dev else ""
            with LOCK:
                STATE["connected"] = True
                STATE["connected_since"] = time.time()
                STATE["mac"] = mac
                STATE["product"] = status_dev["product"]
            log(f"已连接接收器（MAC={mac or '未知'}），监听状态帧…")
            reader_loop(status_dev, handle)
        except Exception as e:  # 监督线程不允许死
            log(f"监督线程异常: {e!r}")
            time.sleep(3)
        finally:
            if handle is not None:
                mbp.kernel32.CloseHandle(handle)
                try:
                    mbp._OPEN_HANDLES.remove(handle)
                except ValueError:
                    pass
            with LOCK:
                STATE["connected"] = False
        time.sleep(3)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            try:
                with open(DASH_PATH, "rb") as f:
                    body = f.read()
                self._send(200, "text/html; charset=utf-8", body)
            except OSError:
                self._send(500, "text/plain; charset=utf-8", "dashboard.html 缺失".encode())
        elif path == "/api/state":
            with LOCK:
                snap = {
                    "connected": STATE["connected"],
                    "battery": STATE["battery"],
                    "battery_ts": STATE["battery_ts"],
                    "charging": STATE["charging"],
                    "mac": STATE["mac"],
                    "product": STATE["product"],
                    "frame_count": STATE["frame_count"],
                    "now": time.time(),
                    "history": [{"t": t, "b": b} for t, b in STATE["history"]],
                    "frames": list(STATE["frames"])[:40],
                }
            self._send(200, "application/json; charset=utf-8",
                       json.dumps(snap, ensure_ascii=False).encode("utf-8"))
        else:
            self._send(404, "text/plain; charset=utf-8", b"not found")

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # 静默逐请求日志
        pass


def pick_port():
    for p in range(8765, 8776):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return 8765


def main():
    port = pick_port()
    threading.Thread(target=supervisor, daemon=True, name="supervisor").start()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    log(f"仪表盘: http://127.0.0.1:{port}  (Ctrl+C 退出)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("退出")
    os._exit(0)  # 后台读线程阻塞在 HID IRP 上，正常 finalize 会挂死，直接终止


if __name__ == "__main__":
    main()
