"""Read runtime-accessible EFI variables, including boot order and referenced entries."""
from ctypes import (Structure, WinDLL, WinError, byref, create_string_buffer, get_last_error,
                    set_last_error, sizeof)
from ctypes.wintypes import BOOL, DWORD, HANDLE, LONG, LPCWSTR, LPVOID
from hashlib import sha256
import re
from uuid import UUID
from inventory import Inventory


class Luid(Structure):
    _fields_ = [("low", DWORD), ("high", LONG)]


class Privileges(Structure):
    _fields_ = [("count", DWORD), ("luid", Luid), ("attributes", DWORD)]


GLOBAL_GUID = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}"
SHIM_GUID = "{605dab50-e046-4300-abb6-3dd810dd8b23}"
MIRRORS = ("MokListRT", "MokListXRT")


def load_option(data):
    """Decode description and file path nodes; optional data stays opaque."""
    if len(data) < 8:
        raise ValueError("启动项头部不完整")
    end = next((p for p in range(6, len(data)-1, 2) if data[p:p+2] == b"\0\0"), None)
    if end is None:
        raise ValueError("启动项描述缺少结束符")
    desc = data[6:end].decode("utf-16le")
    pos = end + 2
    limit = pos + int.from_bytes(data[4:6], "little")
    if limit > len(data):
        raise ValueError("设备路径长度越界")
    paths = []
    while pos < limit:
        length = int.from_bytes(data[pos+2:pos+4], "little")
        if length < 4 or pos + length > limit:
            raise ValueError("设备路径节点无效")
        if data[pos:pos+2] == b"\x04\x04":
            payload = data[pos+4:pos+length]
            if len(payload) < 2 or len(payload) % 2 or not payload.endswith(b"\0\0"):
                raise ValueError("文件路径节点无效")
            paths.append(payload[:-2].decode("utf-16le"))
        pos += length
    return {"description": desc, "filePaths": paths, "loadAttributes": int.from_bytes(data[:4], "little"),
            "optionalDataBytes": len(data) - limit}


def vendor_key(spec):
    name, sep, guid = spec.partition("=")
    if not name or not sep:
        raise ValueError("--uefi 应为变量名=厂商GUID")
    return name + "=" + str(UUID(guid))


def observe_variables(inv, details, specs, previous, read_one):
    targets = {k: GLOBAL_GUID for k in ("BootOrder", "BootNext", "BootCurrent", "Timeout")}
    previous = tuple(previous)
    raw_keys = set(previous)
    for name in MIRRORS:
        targets[name + "=" + SHIM_GUID.strip("{}")] = SHIM_GUID
    for spec in specs:
        custom = vendor_key(spec)
        targets[custom] = "{" + custom.partition("=")[2] + "}"
        raw_keys.add(custom)
    for key in previous:
        if re.fullmatch(r"Boot[0-9a-fA-F]{4}", key):
            targets["Boot" + key[4:].upper()] = GLOBAL_GUID
        elif "=" in key and key not in targets:
            inv.fail(key, "本轮未请求此自定义变量")
            details.fail(key, "本轮未请求此自定义变量")
    pending = list(targets.items())
    for key, guid in pending:
        name = key.partition("=")[0]
        is_mirror = guid == SHIM_GUID and name in MIRRORS
        try:
            raw = read_one(name, guid)
        except OSError as exc:
            if not is_mirror or key in raw_keys:
                inv.fail(key, exc)
            details.fail(key, exc)
            continue
        if raw is None:
            if is_mirror:
                details.add(key, {"status": "运行时接口未找到此镜像"})
            continue
        data, attrs = raw
        value = {"sha256": sha256(data).hexdigest(), "attributes": attrs, "length": len(data)}
        if is_mirror:
            details.add(key, {"status": "运行时镜像可读", **value})
            # New default probes have their own baseline. Preserve compatibility
            # for callers who explicitly monitored the same vendor key before.
            if key not in raw_keys:
                continue
        if guid == GLOBAL_GUID:
            if name in ("BootOrder", "BootNext", "BootCurrent", "Timeout"):
                if len(data) % 2 or (name != "BootOrder" and len(data) != 2):
                    details.fail(key, "启动索引数据长度无效")
                else:
                    numbers = [int.from_bytes(data[i:i+2], "little") for i in range(0, len(data), 2)]
                    value["values"] = numbers
                    if name != "Timeout":
                        for number in numbers:
                            entry = f"Boot{number:04X}"
                            if entry not in targets:
                                targets[entry] = GLOBAL_GUID
                                pending.append((entry, GLOBAL_GUID))
            elif re.fullmatch(r"Boot[0-9a-fA-F]{4}", name):
                try:
                    details.add(key, load_option(data))
                except ValueError as exc:
                    details.fail(key, exc)
        inv.add(key, value)


def read_variables(inv, specs, previous=(), details=None):
    specs = tuple(vendor_key(spec) for spec in specs)
    if details is None:
        details = Inventory()

    kernel = WinDLL("kernel32", use_last_error=True)
    adv = WinDLL("advapi32", use_last_error=True)

    def bind(lib, name, result, args):
        f = getattr(lib, name)
        f.restype, f.argtypes = result, args
        return f

    get_process = bind(kernel, "GetCurrentProcess", HANDLE, [])
    open_token = bind(adv, "OpenProcessToken", BOOL, [HANDLE, DWORD, LPVOID])
    lookup = bind(adv, "LookupPrivilegeValueW", BOOL, [LPCWSTR, LPCWSTR, LPVOID])
    adjust = bind(adv, "AdjustTokenPrivileges", BOOL, [HANDLE, BOOL, LPVOID, DWORD, LPVOID, LPVOID])
    close = bind(kernel, "CloseHandle", BOOL, [HANDLE])
    read = bind(kernel, "GetFirmwareEnvironmentVariableExW", DWORD, [LPCWSTR, LPCWSTR, LPVOID, DWORD, LPVOID])
    token, requested, saved_privilege = HANDLE(), Privileges(), Privileges()
    changed = False
    try:
        if not open_token(get_process(), 0x28, byref(token)):
            raise WinError(get_last_error())
        requested.count, requested.attributes = 1, 2
        if not lookup(None, "SeSystemEnvironmentPrivilege", byref(requested.luid)):
            raise WinError(get_last_error())
        size = DWORD()
        set_last_error(0)
        if not adjust(token, False, byref(requested), sizeof(saved_privilege), byref(saved_privilege), byref(size)) or get_last_error():
            raise WinError(get_last_error())
        changed = True

        def read_one(name, guid):
            capacity = 65536
            while capacity <= 2 << 20:
                buf, attrs = create_string_buffer(capacity), DWORD()
                n = read(name, guid, buf, capacity, byref(attrs))
                if n:
                    return buf.raw[:n], attrs.value
                code = get_last_error()
                if code == 203:
                    return None
                if code != 122:
                    raise WinError(code)
                capacity *= 2
            raise OSError("固件变量超过 2 MiB，未读取")

        observe_variables(inv, details, specs, previous, read_one)
    except OSError as exc:
        inv.fail("", exc)
        details.fail("", exc)
    finally:
        if changed and saved_privilege.count:
            adjust(token, False, byref(saved_privilege), 0, None, None)
        if token:
            close(token)
