#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mouse_battery_probe.py — 迈从(MCHOSE) G3 电量读取 / HID 原始探测工具

适用型号: 仅初代迈从 G3（2.4G 接收器 258A:0138 / 有线 258A:0136，SINO WEALTH 方案）。
G3 V2 / 新版 G3（VID 0x3837 或 0x5253）使用不同协议族，本工具不适用。

实测结论（G3 接收器 VID:PID = 258A:0138，SINO WEALTH 方案）:
  * 0xFF02/0x02 集合的 Input Report (rid=0x09) 每 ~48s 周期上报:
      [09 0A 05 电量% 00 00 00 00]  ← 电量帧（实测与鼠标实际电量吻合）
      [09 0A 02 X  00 00 00 00]     ← 事件帧（与按键等操作同步出现）
  * 0xFF01/0x01 集合 Feature rid=0x0A 返回 [06, MAC 地址 6 字节]
  * 0xFF00/0x01 rid=0x05 返回 UTF-16 片段("ALTH"); rid=0x06 (1032B) 为配置通道，
    需先 SetFeature 选择命令后才能读
  * 无标准 HID 电量 usage (Page 0x06/Usage 0x20)

流程（按用户约束）:
  1. ctypes 枚举 HID 设备接口（hid.dll + setupapi.dll，纯标准库，无第三方依赖）
  2. 优先尝试标准 HID 电量（Usage Page 0x06 Battery System / Usage 0x20 Battery Strength）
  3. 失败则进入探测模式: 从 Value Caps 枚举 Report ID + 暴力扫描，
     全零 payload GetFeature 试探，持续监听 Input Report，全部原始 hex 打印
  4. 交叉验证（可 --no-known 关闭）: 社区已逆向的迈从电量协议
     （dsh-mchose-battery: Feature/Output 0x11 触发 -> Input 0x13 电量帧, XOR 0xFF）

用法:
  python mouse_battery_probe.py --list            # 只枚举打印所有 HID 设备
  python mouse_battery_probe.py --battery         # 一键读电量（推荐）
  python mouse_battery_probe.py                   # 全流程（枚举→标准→探测→已知协议）
  python mouse_battery_probe.py --vid 0x258A --pid 0x0138 --feat 0xFF01/0x01:0A:
  python mouse_battery_probe.py --listen 5 --probe-out --no-known

仅支持 Windows。Python 3.8+（x64 下 detail data cbSize=8 自动处理）。
"""

import argparse
import atexit
import ctypes
import os
import sys
import threading
import time
from ctypes import (POINTER, Structure, byref, c_int, c_long, c_size_t, c_ubyte,
                    c_ulong, c_ushort, c_void_p, c_wchar, c_wchar_p,
                    create_string_buffer)

if sys.platform != "win32":
    print("本脚本仅支持 Windows。")
    sys.exit(1)

# ---------------------------------------------------------------- 常量

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = c_void_p(-1).value

DIGCF_PRESENT = 0x00000002
DIGCF_DEVICEINTERFACE = 0x00000010

HidP_Input, HidP_Output, HidP_Feature = 0, 1, 2
HIDP_STATUS_SUCCESS = 0x00110000  # NTSTATUS 0x0011xxxx

# 标准 HID 电量: Battery System 页(0x06) 的 Battery Strength(0x20)
USAGE_PAGE_BATTERY = 0x06
USAGE_BATTERY_STRENGTH = 0x20

# 实测确认: 迈从 G3 的 2.4G 接收器（SINO WEALTH 方案）
G3_VID = 0x258A
G3_PID = 0x0138
# G3 电量协议（实测逆向）: 0xFF02/0x02 集合的 Input Report rid=0x09，
# 每 ~48s 周期上报 [09 0A 05 电量% 00 00 00 00]；[09 0A 02 X ...] 为事件帧
G3_STATUS_PAGE = 0xFF02
G3_STATUS_USAGE = 0x02
G3_STATUS_RID = 0x09

# 社区逆向出的迈从(MCHOSE)协议参数（dsh-mchose-battery 项目）
KNOWN_VID = 0x3837
KNOWN_PID_24G = 0x100A   # 2.4G 接收器
KNOWN_PID_USB = 0x4018   # USB 有线
KNOWN_CMD_RID = 0x11     # 命令 Feature/Output Report ID
KNOWN_IN_RID = 0x13      # 状态 Input Report ID
KNOWN_VENDOR_PAGE = 0xFF01

NAME_KEYWORDS = ("g3", "mchose", "迈从")  # 名称兜底匹配

DETAIL_DATA_CBSIZE = 8 if ctypes.sizeof(c_void_p) == 8 else 6

# ---------------------------------------------------------------- ctypes 结构体


class GUID(Structure):
    _fields_ = [("Data1", c_ulong), ("Data2", c_ushort), ("Data3", c_ushort),
                ("Data4", c_ubyte * 8)]


class HIDD_ATTRIBUTES(Structure):
    _fields_ = [("Size", c_ulong), ("VendorID", c_ushort),
                ("ProductID", c_ushort), ("VersionNumber", c_ushort)]


class HIDP_CAPS(Structure):
    _fields_ = [
        ("Usage", c_ushort), ("UsagePage", c_ushort),
        ("InputReportByteLength", c_ushort),
        ("OutputReportByteLength", c_ushort),
        ("FeatureReportByteLength", c_ushort),
        ("Reserved", c_ushort * 17),
        ("NumberLinkCollectionNodes", c_ushort),
        ("NumberInputButtonCaps", c_ushort),
        ("NumberInputValueCaps", c_ushort),
        ("NumberInputDataIndices", c_ushort),
        ("NumberOutputButtonCaps", c_ushort),
        ("NumberOutputValueCaps", c_ushort),
        ("NumberOutputDataIndices", c_ushort),
        ("NumberFeatureButtonCaps", c_ushort),
        ("NumberFeatureValueCaps", c_ushort),
        ("NumberFeatureDataIndices", c_ushort),
    ]


class _VCRange(Structure):
    _fields_ = [("UsageMin", c_ushort), ("UsageMax", c_ushort),
                ("StringMin", c_ushort), ("StringMax", c_ushort),
                ("DesignatorMin", c_ushort), ("DesignatorMax", c_ushort),
                ("DataIndexMin", c_ushort), ("DataIndexMax", c_ushort)]


class _VCNotRange(Structure):
    _fields_ = [("Usage", c_ushort), ("Reserved1", c_ushort),
                ("StringIndex", c_ushort), ("Reserved2", c_ushort),
                ("DesignatorIndex", c_ushort), ("Reserved3", c_ushort),
                ("DataIndex", c_ushort), ("Reserved4", c_ushort)]


class _VCUnion(Structure):
    _anonymous_ = ("range", "notrange")
    _fields_ = [("range", _VCRange), ("notrange", _VCNotRange)]


class HIDP_VALUE_CAPS(Structure):
    """hidpi.h 原始布局（自然对齐，x86/x64 均为 72 字节）。"""
    _anonymous_ = ("u",)
    _fields_ = [
        ("UsagePage", c_ushort),
        ("ReportID", c_ubyte),
        ("IsAlias", c_ubyte),
        ("BitField", c_ushort),
        ("LinkCollection", c_ushort),
        ("LinkUsage", c_ushort),
        ("LinkUsagePage", c_ushort),
        ("IsRange", c_ubyte),
        ("IsStringRange", c_ubyte),
        ("IsDesignatorRange", c_ubyte),
        ("IsAbsolute", c_ubyte),
        ("HasNull", c_ubyte),
        ("Reserved", c_ubyte),
        ("BitSize", c_ushort),
        ("ReportCount", c_ushort),
        ("Reserved2", c_ushort * 5),
        ("UnitsExp", c_ulong),
        ("Units", c_ulong),
        ("LogicalMin", c_long),
        ("LogicalMax", c_long),
        ("PhysicalMin", c_long),
        ("PhysicalMax", c_long),
        ("u", _VCUnion),
    ]


class SP_DEVICE_INTERFACE_DATA(Structure):
    _fields_ = [("cbSize", c_ulong), ("InterfaceClassGuid", GUID),
                ("Flags", c_ulong), ("Reserved", c_size_t)]


class SP_DEVICE_INTERFACE_DETAIL_DATA_W(Structure):
    """分配用大缓冲；DevicePath 在 offset 4，与系统布局一致。"""
    _fields_ = [("cbSize", c_ulong), ("DevicePath", c_wchar * 1024)]


# ---------------------------------------------------------------- DLL 绑定

setupapi = ctypes.WinDLL("setupapi.dll", use_last_error=True)
hid = ctypes.WinDLL("hid.dll", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

setupapi.SetupDiGetClassDevsW.restype = c_void_p
setupapi.SetupDiGetClassDevsW.argtypes = (POINTER(GUID), c_wchar_p, c_void_p, c_ulong)
setupapi.SetupDiEnumDeviceInterfaces.restype = ctypes.c_bool
setupapi.SetupDiEnumDeviceInterfaces.argtypes = (c_void_p, c_void_p, POINTER(GUID), c_ulong, POINTER(SP_DEVICE_INTERFACE_DATA))
setupapi.SetupDiGetDeviceInterfaceDetailW.restype = ctypes.c_bool
setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = (c_void_p, POINTER(SP_DEVICE_INTERFACE_DATA), c_void_p, c_ulong, POINTER(c_ulong), c_void_p)
setupapi.SetupDiDestroyDeviceInfoList.restype = ctypes.c_bool
setupapi.SetupDiDestroyDeviceInfoList.argtypes = (c_void_p,)

hid.HidD_GetHidGuid.argtypes = (POINTER(GUID),)
for _fn in ("HidD_GetProductString", "HidD_GetManufacturerString", "HidD_GetSerialNumberString"):
    getattr(hid, _fn).restype = ctypes.c_bool
    getattr(hid, _fn).argtypes = (c_void_p, c_void_p, c_ulong)
hid.HidD_GetAttributes.restype = ctypes.c_bool
hid.HidD_GetAttributes.argtypes = (c_void_p, POINTER(HIDD_ATTRIBUTES))
hid.HidD_GetPreparsedData.restype = ctypes.c_bool
hid.HidD_GetPreparsedData.argtypes = (c_void_p, POINTER(c_void_p))
hid.HidD_FreePreparsedData.restype = ctypes.c_bool
hid.HidD_FreePreparsedData.argtypes = (c_void_p,)
hid.HidP_GetCaps.restype = c_long
hid.HidP_GetCaps.argtypes = (c_void_p, POINTER(HIDP_CAPS))
hid.HidP_GetValueCaps.restype = c_long
hid.HidP_GetValueCaps.argtypes = (c_int, POINTER(HIDP_VALUE_CAPS), POINTER(c_ushort), c_void_p)
hid.HidP_GetScaledUsageValue.restype = c_long
hid.HidP_GetScaledUsageValue.argtypes = (c_int, c_ushort, c_ushort, c_ushort, POINTER(c_long), c_void_p, c_void_p, c_ulong)
hid.HidD_GetFeature.restype = ctypes.c_bool
hid.HidD_GetFeature.argtypes = (c_void_p, c_void_p, c_ulong)
hid.HidD_SetFeature.restype = ctypes.c_bool
hid.HidD_SetFeature.argtypes = (c_void_p, c_void_p, c_ulong)

kernel32.CreateFileW.restype = c_void_p
kernel32.CreateFileW.argtypes = (c_wchar_p, c_ulong, c_ulong, c_void_p, c_ulong, c_ulong, c_void_p)
kernel32.CloseHandle.restype = ctypes.c_bool
kernel32.CloseHandle.argtypes = (c_void_p,)
kernel32.ReadFile.restype = ctypes.c_bool
kernel32.ReadFile.argtypes = (c_void_p, c_void_p, c_ulong, POINTER(c_ulong), c_void_p)
kernel32.WriteFile.restype = ctypes.c_bool
kernel32.WriteFile.argtypes = (c_void_p, c_void_p, c_ulong, POINTER(c_ulong), c_void_p)

# ---------------------------------------------------------------- 工具

_OPEN_HANDLES = []          # 进程退出时统一关闭（取消阻塞中的 ReadFile）
PHASE = {"tag": "监听"}      # 输入报告打印时的阶段标签（主线程写、读线程读）


def hx(data, limit=None):
    if limit is not None and len(data) > limit:
        return " ".join(f"{b:02X}" for b in data[:limit]) + f" ...({len(data)}B)"
    return " ".join(f"{b:02X}" for b in data)


def now():
    return time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"


def _get_string(h, fn):
    buf = (c_wchar * 256)()
    if fn(h, buf, ctypes.sizeof(buf)):
        s = str(buf.value or "")
        return s if s else ""
    return ""


def open_path(path, access):
    h = kernel32.CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             None, OPEN_EXISTING, 0, None)
    if not h or h == INVALID_HANDLE_VALUE:
        return None
    _OPEN_HANDLES.append(h)
    return h


@atexit.register
def _close_all():
    for h in list(_OPEN_HANDLES):
        kernel32.CloseHandle(h)
    _OPEN_HANDLES.clear()


def get_preparsed_caps(h):
    """返回 (preparsed_ptr 或 None, HIDP_CAPS 或 None)。"""
    pp = c_void_p()
    if not hid.HidD_GetPreparsedData(h, byref(pp)):
        return None, None
    caps = HIDP_CAPS()
    ok = hid.HidP_GetCaps(pp, byref(caps)) == HIDP_STATUS_SUCCESS
    if not ok:
        hid.HidD_FreePreparsedData(pp)
        return None, None
    return pp, caps


def get_value_caps(pp, report_type, count):
    if not pp or count <= 0:
        return []
    arr = (HIDP_VALUE_CAPS * count)()
    n = c_ushort(count)
    if hid.HidP_GetValueCaps(report_type, arr, byref(n), pp) != HIDP_STATUS_SUCCESS:
        return []
    return arr[:n.value]


def cap_usages(vc):
    """该 value cap 覆盖的 usage 列表（一般 1 个）。"""
    if vc.IsRange:
        return list(range(vc.UsageMin, vc.UsageMax + 1))
    return [vc.Usage]


# ---------------------------------------------------------------- 枚举

def enumerate_hid_devices():
    """枚举所有 HID top-level collection。每个 collection 一个接口实例。"""
    guid = GUID()
    hid.HidD_GetHidGuid(byref(guid))
    hdev = setupapi.SetupDiGetClassDevsW(byref(guid), None, None,
                                         DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
    if not hdev or hdev == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    devices = []
    try:
        idx = 0
        while True:
            iface = SP_DEVICE_INTERFACE_DATA()
            iface.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)
            if not setupapi.SetupDiEnumDeviceInterfaces(hdev, None, byref(guid), idx, byref(iface)):
                break
            idx += 1

            req = c_ulong(0)
            setupapi.SetupDiGetDeviceInterfaceDetailW(hdev, byref(iface), None, 0, byref(req), None)

            detail = SP_DEVICE_INTERFACE_DETAIL_DATA_W()
            detail.cbSize = DETAIL_DATA_CBSIZE
            if not setupapi.SetupDiGetDeviceInterfaceDetailW(hdev, byref(iface), byref(detail),
                                                             ctypes.sizeof(detail), byref(req), None):
                continue
            path = detail.DevicePath.split("\x00")[0]

            h = kernel32.CreateFileW(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     None, OPEN_EXISTING, 0, None)
            if not h or h == INVALID_HANDLE_VALUE:
                continue
            try:
                attr = HIDD_ATTRIBUTES()
                attr.Size = ctypes.sizeof(HIDD_ATTRIBUTES)
                if not hid.HidD_GetAttributes(h, byref(attr)):
                    continue
                pp, caps = get_preparsed_caps(h)
                devices.append({
                    "path": path,
                    "vid": attr.VendorID,
                    "pid": attr.ProductID,
                    "version": attr.VersionNumber,
                    "product": _get_string(h, hid.HidD_GetProductString),
                    "manufacturer": _get_string(h, hid.HidD_GetManufacturerString),
                    "pp": pp,
                    "caps": caps,
                })
            finally:
                kernel32.CloseHandle(h)  # preparsed 数据与句柄无关，关闭后仍有效
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(hdev)
    return devices


def print_device_table(devices):
    print(f"\n共 {len(devices)} 个 HID top-level collection:")
    print(f"{'#':>3}  {'VID:PID':>9}  {'ver':>4}  {'Usage':>11}  {'I/O/F':>9}  产品名 / 路径")
    for i, d in enumerate(devices):
        c = d["caps"]
        usage = f"0x{c.UsagePage:02X}/0x{c.Usage:02X}" if c else "n/a"
        iof = f"{c.InputReportByteLength}/{c.OutputReportByteLength}/{c.FeatureReportByteLength}" if c else "n/a"
        name = d["product"] or d["manufacturer"] or "?"
        tail = d["path"].split("\\")[-1][:44]
        print(f"{i:>3}  {d['vid']:04X}:{d['pid']:04X}  {d['version']:<4}  {usage:>11}  {iof:>9}  {name} | {tail}")


# ---------------------------------------------------------------- 目标筛选

def pick_targets(devices, args):
    if args.vid is not None or args.pid is not None:
        vid = args.vid if args.vid is not None else KNOWN_VID
        pid = args.pid
        return [d for d in devices if d["vid"] == vid and (pid is None or d["pid"] == pid)]
    # 自动模式: 优先实测确认的 G3 接收器，再试社区记录的迈从 VID，最后按名称关键词
    hits = [d for d in devices if d["vid"] == G3_VID and d["pid"] == G3_PID]
    if hits:
        return hits
    hits = [d for d in devices if d["vid"] == KNOWN_VID]
    if hits:
        return hits
    hits = []
    for d in devices:
        haystack = f"{d['product']} {d['manufacturer']}".lower()
        if any(k in haystack for k in NAME_KEYWORDS):
            hits.append(d)
    return hits


# ---------------------------------------------------------------- 输入报告监听

def decode_g3_status(dev, data):
    """G3 状态帧: [09 0A 05 电量% 0...] 周期上报; [09 0A 02 X ...] 为事件帧。"""
    if len(data) >= 4 and data[1] == 0x0A and data[2] == 0x05:
        dev["battery"] = data[3]
        print(f"    >>> G3 电量帧解析: 电量={data[3]}%")


def decode_vendor_e2(dev, data):
    """Input Report 0x13: 逐字节 XOR 0xFF 后为 E2 电量帧。"""
    payload = bytes(b ^ 0xFF for b in data[1:])
    if len(payload) < 17 or payload[0] != 0xE2:
        return
    battery = payload[4]
    charging = payload[3] != 0
    name_raw = payload[9:].split(b"\x00")[0]
    try:
        name = name_raw.decode("ascii", "replace")
    except Exception:
        name = repr(name_raw)
    print(f"    >>> 已知协议解析: 电量={battery}%  充电中={charging}  设备名={name!r}")
    dev["battery"] = battery
    dev["charging"] = charging
    dev["got_e2"] = True


def on_input_report(dev, data):
    rid = data[0] if data else 0
    line = f"[{now()}][{PHASE['tag']}] {dev['short']} 输入报告 rid=0x{rid:02X} len={len(data)}: {hx(data, 64)}"
    print(line)
    if rid == G3_STATUS_RID:
        decode_g3_status(dev, data)
    if rid == KNOWN_IN_RID:
        decode_vendor_e2(dev, data)
    caps = dev.get("caps")
    pp = dev.get("pp")
    if caps and pp and dev.get("battery_input_caps"):
        vc = dev["battery_input_caps"]
        if rid == vc.ReportID:
            val = c_long()
            st = hid.HidP_GetScaledUsageValue(HidP_Input, USAGE_PAGE_BATTERY, 0,
                                              USAGE_BATTERY_STRENGTH, byref(val),
                                              pp, data, len(data))
            if st == HIDP_STATUS_SUCCESS:
                print(f"    >>> 标准电量(Input) 解码: {val.value}")


def start_reader(dev):
    size = dev["caps"].InputReportByteLength if dev.get("caps") else 0
    if not size or dev.get("access") is None:
        return
    buf = create_string_buffer(size)
    n = c_ulong()

    def loop():
        while True:
            if kernel32.ReadFile(dev["handle"], buf, size, byref(n), None):
                on_input_report(dev, buf.raw[:n.value])
            else:
                err = ctypes.get_last_error()
                print(f"[{now()}] {dev['short']} 输入监听结束 (err={err})")
                return

    t = threading.Thread(target=loop, daemon=True, name=f"reader-{dev['short']}")
    t.start()


# ---------------------------------------------------------------- 目标打开

def open_target(dev):
    for access, mode in ((GENERIC_READ | GENERIC_WRITE, "RW"), (GENERIC_READ, "RO")):
        h = open_path(dev["path"], access)
        if h is not None:
            dev["handle"] = h
            dev["access"] = mode
            return True
    dev["handle"] = None
    dev["access"] = None
    return False


# ---------------------------------------------------------------- 标准电量

def try_standard_battery(dev):
    """扫描 Value Caps 找 Battery Strength (Page 0x06 / Usage 0x20)，能读则读。"""
    caps, pp = dev["caps"], dev["pp"]
    result = {"feature_cap": None, "input_cap": None, "read": None}
    if not caps or not pp:
        return result
    for vc in get_value_caps(pp, HidP_Feature, caps.NumberFeatureValueCaps):
        if vc.UsagePage == USAGE_PAGE_BATTERY and USAGE_BATTERY_STRENGTH in cap_usages(vc):
            result["feature_cap"] = vc
    for vc in get_value_caps(pp, HidP_Input, caps.NumberInputValueCaps):
        if vc.UsagePage == USAGE_PAGE_BATTERY and USAGE_BATTERY_STRENGTH in cap_usages(vc):
            result["input_cap"] = vc
            dev["battery_input_caps"] = vc  # 供监听线程实时解码

    vc = result["feature_cap"]
    if vc and caps.FeatureReportByteLength > 0 and dev.get("handle"):
        rid = vc.ReportID
        size = caps.FeatureReportByteLength
        buf = create_string_buffer(size)
        buf[0] = rid
        if hid.HidD_GetFeature(dev["handle"], buf, size):
            raw = buf.raw[:size]
            print(f"  [标准电量] Feature rid=0x{rid:02X} 原始 {size}B: {hx(raw)}")
            print(f"             (Logical [{vc.LogicalMin}, {vc.LogicalMax}], "
                  f"Physical [{vc.PhysicalMin}, {vc.PhysicalMax}], BitSize={vc.BitSize})")
            val = c_long()
            st = hid.HidP_GetScaledUsageValue(HidP_Feature, USAGE_PAGE_BATTERY, 0,
                                              USAGE_BATTERY_STRENGTH, byref(val),
                                              pp, raw, size)
            if st == HIDP_STATUS_SUCCESS:
                print(f"  [标准电量] HidP_GetScaledUsageValue 解码: {val.value}")
                result["read"] = val.value
            else:
                print(f"  [标准电量] 解码失败 NTSTATUS=0x{st & 0xFFFFFFFF:08X}")
        else:
            print(f"  [标准电量] Feature rid=0x{rid:02X} 读取失败 err={ctypes.get_last_error()}")
    return result


# ---------------------------------------------------------------- 探测模式

def get_feature_watchdog(handle, rid, size, timeout):
    """带看护超时的 GetFeature（个别 ID 可能无响应）。"""
    res = {}

    def work():
        buf = create_string_buffer(size)
        buf[0] = rid
        ok = hid.HidD_GetFeature(handle, buf, size)
        res["ok"] = bool(ok)
        if ok:
            res["data"] = buf.raw[:size]
        else:
            res["err"] = ctypes.get_last_error()

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if "ok" not in res:
        return {"timeout": True}
    return res


def probe_features(dev, args):
    caps, handle = dev["caps"], dev.get("handle")
    print(f"\n---- Feature Report 探测: {dev['short']} (UsagePage 0x{caps.UsagePage:02X}/Usage 0x{caps.Usage:02X}) ----")
    if caps.FeatureReportByteLength == 0:
        print("  该集合未声明 Feature Report (FeatureReportByteLength=0)，跳过")
        return
    if handle is None:
        print("  句柄不可用，跳过")
        return
    size = caps.FeatureReportByteLength
    declared = set()
    if dev["pp"]:
        declared = {vc.ReportID for vc in get_value_caps(dev["pp"], HidP_Feature,
                                                         caps.NumberFeatureValueCaps)}
    rids = sorted(declared | {0})
    if args.sweep:
        rids = sorted(set(rids) | set(range(1, 0x40)))
    print(f"  缓冲区 {size}B; 声明的 Feature RID: "
          f"{[f'0x{r:02X}' for r in sorted(declared)] or ['0x00(默认)']}; 待试 {len(rids)} 个")
    for rid in rids:
        tag = "声明" if rid in declared else "扫描"
        res = get_feature_watchdog(handle, rid, size, args.timeout)
        if res.get("timeout"):
            print(f"  rid=0x{rid:02X} [{tag}] 超时(>{args.timeout:.1f}s)，放弃")
        elif res["ok"]:
            print(f"  rid=0x{rid:02X} [{tag}] OK {size}B: {hx(res['data'])}")
        else:
            print(f"  rid=0x{rid:02X} [{tag}] 失败 err={res['err']}")


def probe_outputs(dev):
    """可选: 对声明的 Output Report ID 写全零报告。"""
    caps, handle = dev["caps"], dev.get("handle")
    print(f"\n---- Output Report 探测(零 payload): {dev['short']} ----")
    if caps.OutputReportByteLength == 0:
        print("  该集合未声明 Output Report，跳过")
        return
    if handle is None or dev["access"] != "RW":
        print("  无写权限，跳过")
        return
    size = caps.OutputReportByteLength
    declared = set()
    if dev["pp"]:
        declared = {vc.ReportID for vc in get_value_caps(dev["pp"], HidP_Output,
                                                         caps.NumberOutputValueCaps)}
    rids = sorted(declared | {0})
    print(f"  缓冲区 {size}B; 声明的 Output RID: {[f'0x{r:02X}' for r in sorted(declared)] or ['0x00(默认)']}")
    for rid in rids:
        buf = create_string_buffer(size)
        buf[0] = rid
        written = c_ulong()
        if kernel32.WriteFile(handle, buf, size, byref(written), None):
            print(f"  rid=0x{rid:02X} 写入成功 {written.value}B")
        else:
            print(f"  rid=0x{rid:02X} 写入失败 err={ctypes.get_last_error()}")


# ---------------------------------------------------------------- 已知协议

def set_feature_watchdog(handle, rid, payload, timeout):
    """带看护超时的 SetFeature。payload 为完整缓冲（含 rid）。"""
    res = {}

    def work():
        buf = create_string_buffer(payload, len(payload))
        ok = hid.HidD_SetFeature(handle, buf, len(payload))
        res["ok"] = bool(ok)
        if not ok:
            res["err"] = ctypes.get_last_error()

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if "ok" not in res:
        return {"timeout": True}
    return res


def _parse_feat_spec(spec):
    """SPEC: 0x页面/0x用法:RID[:payload十六进制[:填充十六进制]]"""
    head, rid_s, *rest = spec.split(":")
    page_s, usage_s = head.split("/")
    page, usage, rid = int(page_s, 0x10), int(usage_s, 0x10), int(rid_s, 0x10)
    payload = rest[0] if rest and rest[0] else ""
    fill = rest[1] if len(rest) > 1 and rest[1] else ""
    return page, usage, rid, payload, fill


def _build_report(size, rid, payload, fill):
    buf = bytearray(size)
    buf[0] = rid
    body = bytes.fromhex(payload) if payload else b""
    buf[1:1 + len(body)] = body[:size - 1]
    if fill:
        tail = bytes.fromhex(fill)
        for i in range(1 + len(body), size):
            buf[i] = tail[(i - 1 - len(body)) % len(tail)]
    return bytes(buf)


def probe_custom(dev, page, usage, rid, payload, fill, timeout, mode="get"):
    """--feat/--setfeat 模式: 对指定集合/ReportID 发送带 payload 的 Get/SetFeature。"""
    caps, handle = dev["caps"], dev.get("handle")
    if (caps.UsagePage, caps.Usage) != (page, usage) or handle is None:
        return
    size = caps.FeatureReportByteLength
    if size == 0:
        print(f"  {dev['short']}: 该集合无 Feature Report，跳过 rid=0x{rid:02X}")
        return
    rpt = _build_report(size, rid, payload, fill)
    tag = f"payload[{payload or '-'}" + (f"|填充{fill}]" if fill else "]")
    if mode == "get":
        res = get_feature_watchdog(handle, rid, size, timeout)
    else:
        res = set_feature_watchdog(handle, rid, rpt, timeout)
    if res.get("timeout"):
        print(f"  rid=0x{rid:02X} {mode.upper()} {tag} 超时(>{timeout:.1f}s)")
    elif res["ok"]:
        print(f"  rid=0x{rid:02X} {mode.upper()} {tag} OK: {hx(res.get('data', rpt))}")
    else:
        print(f"  rid=0x{rid:02X} {mode.upper()} {tag} 失败 err={res['err']}")


def known_protocol(dev):
    """迈从已知协议: SetFeature(或 Output) 0x11 命令 -> Input 0x13 电量帧。"""
    caps = dev["caps"]
    handle = dev.get("handle")
    print(f"\n---- 已知协议交叉验证: {dev['short']} ----")
    if handle is None or dev["access"] != "RW":
        print("  无读写权限，跳过")
        return
    if caps.FeatureReportByteLength > 0:
        channel, size = "SetFeature", caps.FeatureReportByteLength
    elif caps.OutputReportByteLength > 0:
        channel, size = "Output", caps.OutputReportByteLength
    else:
        print("  该集合无 Feature/Output Report，跳过")
        return

    if size < 3:
        print(f"  报告太短({size}B)，跳过")
        return

    def build_cmd(rid, report_size):
        # 逻辑命令 [0x0B, 0xAA, 0x00...]，逐字节 XOR 0xFF -> [0xF4, 0x55, 0xFF...]
        return bytes([rid, 0x0B ^ 0xFF, 0xAA ^ 0xFF] + [0xFF] * (report_size - 3))

    cmd = build_cmd(KNOWN_CMD_RID, size)
    print(f"  发送 {channel} rid=0x{KNOWN_CMD_RID:02X} ({size}B): {hx(cmd, 16)}")
    for attempt in (1, 2):
        buf = create_string_buffer(cmd, size)
        if channel == "SetFeature":
            ok = hid.HidD_SetFeature(handle, buf, size)
            err = ctypes.get_last_error()
            if not ok and caps.OutputReportByteLength >= 3:
                print(f"  SetFeature 失败 err={err}，回退 Output 写入")
                channel, size = "Output", caps.OutputReportByteLength
                cmd = build_cmd(KNOWN_CMD_RID, size)
                buf = create_string_buffer(cmd, size)
                ok = kernel32.WriteFile(handle, buf, size, byref(c_ulong()), None)
                err = ctypes.get_last_error()
        else:
            ok = kernel32.WriteFile(handle, buf, size, byref(c_ulong()), None)
            err = ctypes.get_last_error()
        if ok:
            print(f"  第 {attempt} 次发送成功，等待响应...")
        else:
            print(f"  第 {attempt} 次发送失败 err={err}")
        deadline = time.monotonic() + 2.5
        while time.monotonic() < deadline:
            if dev.get("got_e2"):
                b, c = dev.get("battery"), dev.get("charging")
                print(f"  ✔ 收到电量帧: 电量={b}%  充电中={c}")
                return
            time.sleep(0.1)
    print("  ✗ 未收到 0x13 电量帧（确认鼠标已开机且在 2.4G 模式；碰一下鼠标唤醒再试）")


# ---------------------------------------------------------------- 主流程

def main():
    parser = argparse.ArgumentParser(
        description="迈从 G3 无线鼠标电量读取 / HID 原始探测（纯标准库 ctypes）")
    parser.add_argument("--list", action="store_true", help="只枚举并打印所有 HID 设备")
    parser.add_argument("--battery", action="store_true",
                        help="一键读电量: G3 被动监听 ~48s 周期帧；0x3837 设备走已知协议主动查询")
    parser.add_argument("--vid", type=lambda s: int(s, 0), default=None, help="过滤 VID（如 0x3837）")
    parser.add_argument("--pid", type=lambda s: int(s, 0), default=None, help="过滤 PID（如 0x100a）")
    parser.add_argument("--probe", action="store_true", help="强制进入探测模式（默认标准电量失败才进入）")
    parser.add_argument("--probe-out", action="store_true", help="探测时向 Output Report 写全零报告（默认关闭）")
    parser.add_argument("--no-sweep", action="store_true", help="不暴力扫描 Report ID 1..0x3F")
    parser.add_argument("--no-known", action="store_true", help="跳过已知协议（0x11/0x13）交叉验证")
    parser.add_argument("--known-anyway", action="store_true",
                        help="目标不是 VID 0x3837 时也执行已知协议写探测（默认只在 0x3837 上执行）")
    parser.add_argument("--feat", action="append", default=[], metavar="SPEC",
                        help="试探性 GetFeature: 0x页面/0x用法:RID[:payload十六进制[:填充十六进制]]，可重复；"
                             "例如 --feat 0xFF00/0x01:5:0001")
    parser.add_argument("--setfeat", action="append", default=[], metavar="SPEC",
                        help="试探性 SetFeature（写探测）: 格式同 --feat，例如"
                             " --setfeat 0xFF02/0x02:09:F455:FF")
    parser.add_argument("--listen", type=float, default=3.0, help="结束前监听输入报告的秒数（默认 3）")
    parser.add_argument("--timeout", type=float, default=2.0, help="单个 GetFeature 的看护超时秒数（默认 2）")
    args = parser.parse_args()
    args.sweep = not args.no_sweep

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    print("枚举 HID 设备 ...")
    devices = enumerate_hid_devices()
    if args.list:
        print_device_table(devices)
        return 0

    targets = pick_targets(devices, args)
    if not targets:
        print("\n未自动识别到迈从 G3（既没有 VID 0x3837 的设备，名称也不含 G3/MCHOSE/迈从）。")
        print_device_table(devices)
        print("\n请插好接收器后重试，或用 --vid/--pid 显式指定（见上表）。")
        return 1

    print(f"\n匹配到 {len(targets)} 个目标集合:")
    for dev in targets:
        c = dev["caps"]
        dev["short"] = f"{dev['vid']:04X}:{dev['pid']:04X}@0x{c.UsagePage:02X}/0x{c.Usage:02X}"
        usable = open_target(dev)
        mode = dev["access"] or "仅查询"
        print(f"  {dev['short']}  权限={mode}  I/O/F={c.InputReportByteLength}/"
              f"{c.OutputReportByteLength}/{c.FeatureReportByteLength}  产品={dev['product']!r}"
              + ("" if usable else "  (系统独占，无法直接读写——鼠标本体集合属正常现象)"))
        dev.setdefault("got_e2", False)

    # 输入监听贯穿全程
    for dev in targets:
        start_reader(dev)
    time.sleep(0.3)

    if args.battery:
        print("\n==== 一键读电量 ====")
        if any(d["vid"] == G3_VID for d in targets):
            status = [d for d in targets
                      if (d["caps"].UsagePage, d["caps"].Usage) == (G3_STATUS_PAGE, G3_STATUS_USAGE)
                      and d.get("access")]
            if not status:
                print("✗ 未找到可读写的状态集合 (0xFF02/0x02)")
                return 1
            print("被动监听 G3 电量帧（接收器每 ~48s 周期上报，最多等 75s）...")
            deadline = time.monotonic() + 75
            while time.monotonic() < deadline:
                for d in status:
                    if d.get("battery") is not None:
                        print(f"\n✔ 迈从 G3 电量: {d['battery']}%")
                        return 0
                time.sleep(0.2)
            print("✗ 75s 内未收到电量帧（确认鼠标开机、在 2.4G 模式且未休眠；动一动鼠标再试）")
            return 1
        pool = [d for d in targets if d["access"] == "RW"]
        pool = [d for d in pool if d["caps"].UsagePage == KNOWN_VENDOR_PAGE] or pool
        for d in pool:
            known_protocol(d)
            if d.get("got_e2"):
                return 0
        print("✗ 未能读到电量")
        return 1

    if args.feat or args.setfeat:
        print("\n==== 自定义 Get/SetFeature 试探 ====")

        # 按命令行出现顺序执行（支持 SET→GET 连招）
        ordered = []
        for i, a in enumerate(sys.argv[1:]):
            if a == "--feat" and i + 1 < len(sys.argv[1:]):
                ordered.append(("get", sys.argv[1:][i + 1]))
            elif a == "--setfeat" and i + 1 < len(sys.argv[1:]):
                ordered.append(("set", sys.argv[1:][i + 1]))
        if not ordered:
            ordered = [("get", s) for s in args.feat] + [("set", s) for s in args.setfeat]

        for mode, spec in ordered:
            try:
                page, usage, rid, payload, fill = _parse_feat_spec(spec)
            except (ValueError, IndexError):
                print(f"  ! 参数格式错误: {spec}（应为 0x页面/0x用法:RID[:hex[:填充hex]]）")
                continue
            print(f"-- {mode.upper()} 页面/用法 0x{page:02X}/0x{usage:02X} "
                  f"rid=0x{rid:02X} payload={payload or '-'}" + (f" 填充={fill}" if fill else ""))
            for dev in targets:
                probe_custom(dev, page, usage, rid, payload, fill, args.timeout, mode)
            time.sleep(0.03)  # 协议要求事务间隔 ≥25ms
        PHASE["tag"] = "收尾监听"
        print(f"\n监听输入报告 {args.listen:.0f}s ...")
        time.sleep(args.listen)
        return 0

    print("\n==== 第 1 步: 标准 HID 电量 (Page 0x06 / Usage 0x20) ====")
    any_std = False
    for dev in targets:
        r = try_standard_battery(dev)
        if r["feature_cap"] is None and r["input_cap"] is None:
            print(f"  {dev['short']}: 未发现标准电量 usage")
        elif r["read"] is not None:
            any_std = True
        dev["std"] = r

    if any_std:
        print("\n标准电量已读到，无需探测。（如仍想看原始数据，加 --probe）")
    else:
        print("\n==== 第 2 步: 探测模式（标准方式未成功）====")
        for dev in targets:
            probe_features(dev, args)
        if args.probe_out:
            for dev in targets:
                probe_outputs(dev)

    if not args.no_known:
        print("\n==== 第 3 步: 已知协议交叉验证（0x11 命令 -> 0x13 电量帧）====")
        writable = [d for d in targets if d["access"] == "RW"]
        if any(d["vid"] == KNOWN_VID for d in targets):
            pool = [d for d in writable if d["caps"].UsagePage == KNOWN_VENDOR_PAGE] or writable
        elif args.known_anyway:
            pool = [d for d in writable if d["caps"].UsagePage == KNOWN_VENDOR_PAGE] or writable
        else:
            pool = []
            print("  目标 VID 不是已知的迈从 VID 0x3837，跳过写探测（确认是迈从设备可加 --known-anyway）")
        for dev in pool:
            known_protocol(dev)

    PHASE["tag"] = "收尾监听"
    print(f"\n结束前监听输入报告 {args.listen:.0f}s（动一动鼠标/按键可触发上报）...")
    time.sleep(args.listen)
    PHASE["tag"] = "监听"

    print("\n==== 汇总 ====")
    for dev in targets:
        std = dev.get("std") or {}
        std_txt = (f"标准电量={std['read']}%" if std.get("read") is not None
                   else ("发现标准 usage 但未能解码" if std.get("feature_cap") or std.get("input_cap")
                         else "无标准电量 usage"))
        e2 = (f"  已知协议: 电量={dev.get('battery')}% 充电={dev.get('charging')}"
              if dev.get("got_e2") else "  已知协议: 无响应")
        print(f"  {dev['short']}  权限={dev['access'] or '仅查询'}  {std_txt}{e2}")
    print("\n原始数据以上全部打印；协议解析可基于 0x13 帧与 Feature 探测结果继续。")
    return 0


if __name__ == "__main__":
    _code = 0
    try:
        _code = main()
    except KeyboardInterrupt:
        print("\n(中断)")
        _code = 130
    finally:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        # 绕过解释器关停：被遗弃的看护线程可能仍阻塞在内核里（未决 HID IRP），
        # 正常 finalize 会与其死锁；直接终止进程，由内核强制清理句柄。
        os._exit(_code)
