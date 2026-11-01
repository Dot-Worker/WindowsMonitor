"""Read-only process, loader and virtual-memory metadata. No process memory bytes are read."""
import ctypes as C
from ctypes import wintypes as W
from contextlib import contextmanager
import mmap
import os
from pathlib import Path

from inventory import Inventory, ps_inventory

kernel = C.WinDLL("kernel32", use_last_error=True)


def api(name, result, *args):
    func = getattr(kernel, name)
    func.restype, func.argtypes = result, args
    return func


class Process(C.Structure):
    _fields_ = [("size", W.DWORD), ("usage", W.DWORD), ("pid", W.DWORD), ("heap", C.c_size_t),
                ("module", W.DWORD), ("threads", W.DWORD), ("parent", W.DWORD), ("priority", W.LONG),
                ("flags", W.DWORD), ("name", W.WCHAR * 260)]


class Module(C.Structure):
    _fields_ = [("size", W.DWORD), ("module", W.DWORD), ("pid", W.DWORD), ("globalRefs", W.DWORD),
                ("refs", W.DWORD), ("base", W.LPVOID), ("length", W.DWORD), ("handle", W.HANDLE),
                ("name", W.WCHAR * 256), ("path", W.WCHAR * 260)]


class Region(C.Structure):
    _fields_ = [("base", W.LPVOID), ("allocation", W.LPVOID), ("allocationProtect", W.DWORD),
                ("partition", W.WORD), ("size", C.c_size_t), ("state", W.DWORD), ("protect", W.DWORD), ("type", W.DWORD)]


class WorkingPage(C.Structure):
    _fields_ = [("address", W.LPVOID), ("flags", C.c_size_t)]


snapshot = api("CreateToolhelp32Snapshot", W.HANDLE, W.DWORD, W.DWORD)
close = api("CloseHandle", W.BOOL, W.HANDLE)
open_process = api("OpenProcess", W.HANDLE, W.DWORD, W.BOOL, W.DWORD)
image_name = api("QueryFullProcessImageNameW", W.BOOL, W.HANDLE, W.DWORD, W.LPWSTR, W.LPVOID)
proc_times = api("GetProcessTimes", W.BOOL, W.HANDLE, W.LPVOID, W.LPVOID, W.LPVOID, W.LPVOID)
query_region = api("VirtualQueryEx", C.c_size_t, W.HANDLE, W.LPVOID, W.LPVOID, C.c_size_t)
mapped_name = api("K32GetMappedFileNameW", W.DWORD, W.HANDLE, W.LPVOID, W.LPWSTR, W.DWORD)
working_set = api("K32QueryWorkingSetEx", W.BOOL, W.HANDLE, W.LPVOID, W.DWORD)
drive_type = api("GetDriveTypeW", W.UINT, W.LPCWSTR)
first_proc = api("Process32FirstW", W.BOOL, W.HANDLE, W.LPVOID)
next_proc = api("Process32NextW", W.BOOL, W.HANDLE, W.LPVOID)
first_mod = api("Module32FirstW", W.BOOL, W.HANDLE, W.LPVOID)
next_mod = api("Module32NextW", W.BOOL, W.HANDLE, W.LPVOID)


def entries(pid=None):
    is_proc = pid is None
    for _ in range(4):
        h = snapshot(0x2 if is_proc else 0x18, pid or 0)
        if h != W.HANDLE(-1).value:
            break
        if C.get_last_error() != 24:  # ERROR_BAD_LENGTH, module list is changing
            raise C.WinError(C.get_last_error())
    else:
        raise C.WinError(C.get_last_error())
    try:
        entry = Process() if is_proc else Module()
        entry.size = C.sizeof(entry)
        ok = (first_proc if is_proc else first_mod)(h, C.byref(entry))
        while ok:
            if is_proc:
                yield entry.pid, entry.name
            else:
                path = entry.path
                if len(path) >= 259:
                    raise OSError("模块快照路径可能截断")
                if path.startswith("\\\\?\\") and path[5:7] == ":\\":
                    path = path[4:]
                yield entry.base, path
            ok = (next_proc if is_proc else next_mod)(h, C.byref(entry))
        if C.get_last_error() != 18:  # ERROR_NO_MORE_FILES
            raise C.WinError(C.get_last_error())
    finally:
        close(h)


@contextmanager
def process_handle(pid, access):
    handle = open_process(access, False, pid)
    if not handle:
        raise C.WinError(C.get_last_error())
    try:
        yield handle
    finally:
        close(handle)


def identity(handle):
    buf = C.create_unicode_buffer(32768)
    length = W.DWORD(len(buf))
    if not image_name(handle, 0, buf, C.byref(length)):
        raise C.WinError(C.get_last_error())
    times = (C.c_ulonglong * 4)()
    if not proc_times(handle, *(C.byref(times, i * 8) for i in range(4))):
        raise C.WinError(C.get_last_error())
    return buf.value, times[0]


def unshared_pages(handle, region):
    """Only resident executable image pages whose working set is marked private."""
    offsets = []
    for start in range(region.base, region.base + region.size, 2048 * mmap.PAGESIZE):
        addresses = range(start, min(start + 2048 * mmap.PAGESIZE, region.base + region.size), mmap.PAGESIZE)
        batch = (WorkingPage * len(addresses))()
        for item, address in zip(batch, addresses):
            item.address = address
        if not working_set(handle, batch, C.sizeof(batch)):
            raise C.WinError(C.get_last_error())
        offsets.extend(hex(p.address - region.allocation) for p in batch if p.flags & 1 and not (p.flags & (1 << 15)))
    return offsets


def inspect_memory(handle, key, modules, inv):
    address = 0
    region = Region()
    while query_region(handle, address, C.byref(region), C.sizeof(region)):
        address = (region.base or 0) + region.size
        if region.state != 0x1000 or not region.protect & 0xF0:
            continue
        label = key + "\\" + hex(region.base)
        module = modules.get(region.allocation) if modules is not None else None
        value = {"address": hex(region.base), "allocation": hex(region.allocation), "bytes": region.size,
                 "protection": hex(region.protect)}
        if region.type == 0x1000000 and module:
            try:
                private = unshared_pages(handle, region)
            except OSError as exc:
                inv.fail(label, exc)
                continue
            if not private:
                continue
            value.update(kind="驻留映像私有执行页", path=module, pageOffsets=private)
        else:
            if region.type == 0x20000:
                value["kind"] = "私有可执行内存"
            else:
                value["kind"] = "加载器清单外的可执行映像" if region.type == 0x1000000 else "可执行映射"
                buf = C.create_unicode_buffer(32768)
                if mapped_name(handle, region.base, buf, len(buf)):
                    value["mappedFile"] = buf.value
                else:
                    value["mappedFileError"] = str(C.WinError(C.get_last_error()))
            if modules is None and region.type == 0x1000000:
                value["kind"] = "可执行映像（模块清单不可读）"
        inv.add(label, value)
    if C.get_last_error() != 87:  # end of address space
        raise C.WinError(C.get_last_error())


CORE = set("system registry smss.exe csrss.exe wininit.exe winlogon.exe services.exe lsass.exe svchost.exe "
           "explorer.exe dwm.exe dllhost.exe rundll32.exe spoolsv.exe sihost.exe taskhostw.exe "
           "shellexperiencehost.exe startmenuexperiencehost.exe searchhost.exe fontdrvhost.exe "
           "msmpeng.exe nissrv.exe mssense.exe securityhealthservice.exe".split())


def system_process(name, image, extras):
    return (name.casefold() in CORE | extras or Path(image).is_relative_to(Path(os.environ["SystemRoot"]))
            or any(s in image.casefold() for s in ("\\windowsapps\\microsoftwindows.", "\\windowsapps\\microsoft.windows.")))


def collect_processes(extra):
    extra = {name.casefold() for name in extra}
    hosts, loads, memory, files = Inventory(), Inventory(), Inventory(), Inventory()
    paths = set()
    try:
        for pid, name in entries():
            key = name + "\\" + str(pid)
            if pid == 0:
                continue
            try:
                with process_handle(pid, 0x1000) as limited:
                    path, birth = identity(limited)
                    if not system_process(name, path, extra):
                        continue
                    key += "\\" + str(birth)
                    hosts.add(key, {"name": name, "pid": pid, "createdFileTime": birth, "image": path})
                    paths.add(path)
                    modules = {}
                    try:
                        modules = dict(entries(pid))
                        for base, module in modules.items():
                            paths.add(module)
                            loads.add(key + "\\" + module, {"path": module, "base": hex(base)})
                    except OSError as exc:
                        loads.fail(key, exc)
                        modules = None
                    try:
                        with process_handle(pid, 0x400) as handle:
                            inspect_memory(handle, key, modules, memory)
                    except OSError as exc:
                        memory.fail(key, exc)
            except OSError as exc:
                # An unreadable image cannot be confidently ruled out of the monitored set.
                for inv in (hosts, loads, memory):
                    inv.fail(key, exc)
    except OSError as exc:
        for inv in (hosts, loads, memory):
            inv.fail("", exc)
    local = []
    for path in sorted(paths):
        root = Path(path).anchor
        if not root or root.startswith("\\\\") or drive_type(root) not in (2, 3, 6):
            files.fail(path, "非本地文件路径，未读取")
        else:
            local.append(path)
    signed = ps_inventory("signatures", input_data=local) if local else Inventory()
    files.errors.update(signed.errors)
    for path in local:
        row = signed.rows.get(path.casefold())
        value = dict(row[1]) if row else {}
        if not row:
            files.fail(path, "未取得签名验证结果")
        value["class"] = module_class(path, value)
        files.add(path, value)
    return {"system-processes": hosts, "loaded-modules": loads, "executable-memory": memory, "module-files": files}


def module_class(path, value):
    if value.get("status") == "Valid":
        if value.get("osBinary"):
            return "Windows 签名" if Path(path).is_relative_to(Path(os.environ["SystemRoot"])) else "Windows 签名，位于系统目录外"
        return "有效签名，非 Windows 系统签名"
    if value.get("status") == "NotSigned":
        return "无签名"
    return "签名无效或未知"
