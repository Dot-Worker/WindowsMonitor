"""Read runtime-accessible EFI variables, including boot order and referenced entries."""
from ctypes import (Structure, WinDLL, WinError, byref, create_string_buffer, get_last_error,
                    set_last_error, sizeof)
from ctypes.wintypes import BOOL, DWORD, HANDLE, LONG, LPCWSTR, LPVOID
from hashlib import sha256
from uuid import UUID


class Luid(Structure):
    _fields_ = [("low", DWORD), ("high", LONG)]


class Privileges(Structure):
    _fields_ = [("count", DWORD), ("luid", Luid), ("attributes", DWORD)]


def read_variables(inv, specs):
    global_guid = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}"
    targets = {k: global_guid for k in ("BootOrder", "BootNext", "BootCurrent", "Timeout")}
    for spec in specs:
        name, sep, guid = spec.partition("=")
        if not name or not sep:
            raise ValueError("--uefi 应为变量名=厂商GUID")
        targets[name + "=" + str(UUID(guid))] = "{" + str(UUID(guid)) + "}"

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
    token, requested, previous = HANDLE(), Privileges(), Privileges()
    changed = False
    try:
        if not open_token(get_process(), 0x28, byref(token)):
            raise WinError(get_last_error())
        requested.count, requested.attributes = 1, 2
        if not lookup(None, "SeSystemEnvironmentPrivilege", byref(requested.luid)):
            raise WinError(get_last_error())
        size = DWORD()
        set_last_error(0)
        if not adjust(token, False, byref(requested), sizeof(previous), byref(previous), byref(size)) or get_last_error():
            raise WinError(get_last_error())
        changed = True
        pending = list(targets.items())
        for key, guid in pending:
            name = key.partition("=")[0]
            buf, attrs = create_string_buffer(65536), DWORD()
            n = read(name, guid, buf, len(buf), byref(attrs))
            if n == 0:
                code = get_last_error()
                if code != 203:  # ERROR_ENVVAR_NOT_FOUND is a known absence.
                    inv.fail(key, WinError(code))
                continue
            data = buf.raw[:n]
            value = {"sha256": sha256(data).hexdigest(), "attributes": attrs.value, "length": n}
            if guid == global_guid and name in ("BootOrder", "BootNext", "BootCurrent", "Timeout") and n % 2 == 0:
                numbers = [int.from_bytes(data[i:i + 2], "little") for i in range(0, n, 2)]
                value["values"] = numbers
                if name != "Timeout":
                    for number in numbers:
                        entry = f"Boot{number:04X}"
                        if entry not in targets:
                            targets[entry] = global_guid
                            pending.append((entry, global_guid))
            inv.add(key, value)
    except OSError as exc:
        inv.fail("", exc)
    finally:
        if changed and previous.count:
            adjust(token, False, byref(previous), 0, None, None)
        if token:
            close(token)
