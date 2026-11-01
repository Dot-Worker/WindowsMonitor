"""Read-only Windows inventory. Collection errors travel with their affected paths."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
from shortcuts import parse_link

if os.name == "nt":
    import winreg


class Inventory:
    def __init__(self):
        self.rows = {}
        self.errors = {}

    def add(self, key, value):
        self.rows[key.casefold()] = (key, value)

    def fail(self, key, reason):
        self.errors[key.casefold()] = str(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def machine():
    if os.name != "nt" or sys.maxsize <= 2**32:
        raise ValueError("请在 Windows 中使用 64 位 Python 运行。")
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
        version = {k: winreg.QueryValueEx(key, k)[0] for k in ("EditionID", "CurrentBuild", "UBR", "InstallationType")}
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Nls\Language") as key:
        version["InstallLanguage"] = winreg.QueryValueEx(key, "InstallLanguage")[0]
    version["Architecture"] = os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE") or platform.machine()
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
        host = winreg.QueryValueEx(key, "MachineGuid")[0]
    return host, version


def subkeys(key):
    for i in range(winreg.QueryInfoKey(key)[0]):
        yield winreg.EnumKey(key, i)


def reg_values(key, readable):
    values = {}
    for i in range(winreg.QueryInfoKey(key)[1]):
        name, data, kind = winreg.EnumValue(key, i)
        if isinstance(data, bytes):
            data = {"bytes": len(data), "sha256": digest(data)}
        elif not readable or re.search(r"passw(?:or)?d|secret|credential|token", name, re.I):
            data = {"sha256": digest(json.dumps(data, ensure_ascii=True).encode())}
        values[name] = [kind, data]
    return values


def reg_walk(inv, hive, path, label, readable=False, recurse=True, depth=0):
    try:
        with winreg.OpenKey(hive, path) as key:
            values = reg_values(key, readable)
            children = list(subkeys(key)) if recurse else []
        inv.add(label, values)
        if depth >= 128:
            inv.fail(label, "registry depth limit")
            return
        for child in children:
            reg_walk(inv, hive, path + "\\" + child, label + "\\" + child, readable, depth=depth + 1)
    except FileNotFoundError as exc:
        if depth:
            inv.fail(label, exc)
    except OSError as exc:
        inv.fail(label, exc)


def services():
    inv = Inventory()
    path = r"SYSTEM\CurrentControlSet\Services"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as root:
        for name in subkeys(root):
            try:
                with winreg.OpenKey(root, name) as key:
                    config = reg_values(key, True)
                    # Only service/driver definitions have a Type.
                    if "type" not in {k.casefold() for k in config}:
                        continue
                    for child in ("Parameters", "TriggerInfo", "StartOverride"):
                        tree = Inventory()
                        reg_walk(tree, winreg.HKEY_LOCAL_MACHINE, path + "\\" + name + "\\" + child, child, True)
                        for missing, reason in tree.errors.items():
                            inv.fail(name + "\\" + missing, reason)
                        for label, value in tree.rows.values():
                            config[label] = value
                    inv.add(name, config)
            except OSError as exc:
                inv.fail(name, exc)
    return inv


# One identity per registry key, including empty keys. Preserve value names and types.
RUN = r"Software\Microsoft\Windows\CurrentVersion"
USER_POLICIES = [r"Software\Policies", RUN + r"\Policies"]
STARTUP = [RUN + "\\" + tail for tail in (
    "Run", "RunOnce", "RunOnceEx", "RunServices", "RunServicesOnce", r"Explorer\StartupApproved",
    r"Explorer\Shell Folders", r"Explorer\User Shell Folders", "Group Policy\\Scripts", "Policies\\Explorer\\Run")]
MACHINE_SETTINGS = [r"SYSTEM\CurrentControlSet\Control\Session Manager", r"SYSTEM\CurrentControlSet\Control\Lsa",
                    r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                    r"SYSTEM\CurrentControlSet\Control\Power", r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", r"SOFTWARE\Microsoft\Windows Defender",
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"]
MACHINE_START = [r"Software\Microsoft\Windows NT\CurrentVersion" + "\\" + p for p in (
    "Winlogon", "Windows", "Image File Execution Options", "SilentProcessExit")]


def registry_sets(extra):
    results = {}
    lm = winreg.HKEY_LOCAL_MACHINE
    for scope, paths, readable in (("autorun/HKLM", STARTUP + MACHINE_START, True),
                                    ("policy/HKLM", USER_POLICIES, True),
                                    ("settings/HKLM", MACHINE_SETTINGS, False)):
        inv = results[scope] = Inventory()
        for path in paths:
            reg_walk(inv, lm, path, path, readable)
            if path.lower().startswith("software\\"):
                wow = "Software\\WOW6432Node\\" + path.split("\\", 1)[1]
                reg_walk(inv, lm, wow, wow, readable)
    with winreg.OpenKey(winreg.HKEY_USERS, "") as root:
        users = list(subkeys(root))
    for sid in users:
        if sid.endswith("_Classes"):
            continue
        for scope, paths, readable in (("autorun", STARTUP, True), ("policy", USER_POLICIES, True),
                                       ("user", [r"Control Panel", r"Environment", RUN + r"\Internet Settings",
                                                 RUN + r"\Explorer\Advanced", r"Software\Microsoft\Windows\Shell"], False)):
            inv = results[scope + "/" + sid] = Inventory()
            for path in paths:
                reg_walk(inv, winreg.HKEY_USERS, sid + "\\" + path, path, readable)
                if scope == "autorun":
                    wow = "Software\\Wow6432Node\\" + path.split("\\", 1)[1]
                    reg_walk(inv, winreg.HKEY_USERS, sid + "\\" + wow, wow, readable)
    with winreg.OpenKey(lm, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList") as profiles:
        for sid in set(subkeys(profiles)) - set(users):
            for scope in ("autorun", "policy", "user"):
                inv = results[scope + "/" + sid] = Inventory()
                inv.fail("", "用户注册表配置单元未加载")
    for spec in extra:
        hive_name, _, path = spec.partition("\\")
        hive = {"HKLM": lm, "HKCU": winreg.HKEY_CURRENT_USER, "HKU": winreg.HKEY_USERS}.get(hive_name.upper())
        if hive is None:
            raise ValueError("注册表路径必须以 HKLM、HKCU 或 HKU 开头")
        inv = results["registry/" + spec] = Inventory()
        reg_walk(inv, hive, path, path, False)
    return results


def file_tree(root):
    inv = Inventory()
    hashes = {}

    def visit(path, relative):
        try:
            info = path.lstat()
            if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT or stat.S_ISLNK(info.st_mode):
                item = {"entry": "reparse", "tag": getattr(info, "st_reparse_tag", 0)}
                try:
                    item["target"] = os.readlink(path)
                except OSError:
                    pass  # Some reparse tags do not contain a link target.
                inv.add(relative, item)
                inv.fail(relative + "\\", "reparse point contents excluded")
            elif stat.S_ISDIR(info.st_mode):
                for entry in path.iterdir():
                    visit(entry, (relative + "\\" + entry.name).lstrip("\\"))
            elif stat.S_ISREG(info.st_mode):
                identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                checksum = hashes.get(identity) if info.st_ino else None
                if checksum is None:
                    with path.open("rb") as stream:
                        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
                    after = path.stat()
                    if (after.st_size, after.st_mtime_ns, after.st_ino) != (info.st_size, info.st_mtime_ns, info.st_ino):
                        raise OSError("file changed during scan")
                    if info.st_ino and info.st_nlink > 1:
                        hashes[identity] = checksum
                inv.add(relative, {"size": info.st_size, "sha256": checksum})
        except OSError as exc:
            inv.fail(relative, exc)

    visit(Path(root), "")
    return inv


BROWSERS = re.compile(r"(?:^|[\\/\s\x22])(?:chrome|msedge|firefox|iexplore|brave|opera|vivaldi|qqbrowser|360chrome[x]?|360se|browser)\.exe\b|\\Opera[^\\]*\\launcher\.exe\b", re.I)
BROWSER_ALIAS = re.compile(r"(?:chrome|\bedge\b|firefox|chromium|brave|opera|vivaldi|浏览器|\bbrowser\b|360se)", re.I)
AD_ARG = re.compile(r"(?:\b(?:https?|ftp)://|\bwww\.|(?:^|\s|\x22)(?:[\w-]+\.)+[a-z]{2,}(?:[/:\s\x22]|$)|--(?:app(?:-id)?|homepage|load-extension|proxy-server|new-window)(?:=|\s))", re.I)


def shortcut_findings(inv):
    findings = []
    for path, data in inv.rows.values():
        target, args = data.get("target", ""), data.get("arguments", "")
        name = path.split("\\")[-1]
        named_browser = BROWSER_ALIAS.search(name) and not re.search(r"uninstall|卸载", name, re.I)
        if path.lower().endswith(".url") and named_browser and data.get("url"):
            findings.append({"path": path, "reason": "带浏览器名称的直接网址快捷方式", "target": "", "arguments": data["url"]})
        if not path.lower().endswith(".lnk"):
            continue
        if (BROWSERS.search(target) or BROWSERS.search(args) or named_browser
                or AD_ARG.search(args) and (not target or re.search(r"(?:cmd|powershell|pwsh|[cw]script|explorer|rundll32|mshta)\.exe$", target, re.I))):
            if args.strip() or not BROWSERS.search(target):
                reason = "网址或敏感启动参数" if AD_ARG.search(args) else "核对浏览器启动目标和参数"
                findings.append({"path": path, "reason": reason, "target": target, "arguments": args})
    return findings


def shortcuts(extra_dirs):
    inv = Inventory()
    roots = {}

    def folder(path, startup=False):
        key = os.path.normpath(path)
        roots[key] = roots.get(key, False) or startup

    common = Path(os.environ["ProgramData"], "Microsoft/Windows/Start Menu")
    folder(common)
    folder(common / "Programs/Startup", True)
    folder(Path(os.environ["PUBLIC"], "Desktop"))
    profile_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, profile_key) as profiles:
        for sid in subkeys(profiles):
            home = None
            try:
                with winreg.OpenKey(profiles, sid) as key:
                    home = Path(os.path.expandvars(winreg.QueryValueEx(key, "ProfileImagePath")[0]))
                roaming = home / "AppData/Roaming"
                folder(home / "Desktop")
                menu = roaming / "Microsoft/Windows/Start Menu"
                folder(menu)
                folder(menu / "Programs/Startup", True)
                folder(roaming / "Microsoft/Internet Explorer/Quick Launch/User Pinned")
                shell = sid + "\\" + RUN + r"\Explorer\User Shell Folders"
                with winreg.OpenKey(winreg.HKEY_USERS, shell) as key:
                    for name in ("Desktop", "Start Menu", "Startup"):
                        try:
                            raw = winreg.QueryValueEx(key, name)[0]
                        except FileNotFoundError:
                            continue
                        expanded = re.sub("%USERPROFILE%", lambda _: str(home), raw, flags=re.I)
                        expanded = re.sub("%APPDATA%", lambda _: str(roaming), expanded, flags=re.I)
                        if home == Path.home():
                            expanded = os.path.expandvars(expanded)
                        if "%" in expanded:
                            inv.fail(str(home), "Unresolved shell folder: " + raw)
                        else:
                            folder(expanded, name == "Startup")
            except FileNotFoundError:
                pass  # Offline user hive or a profile without shell-folder overrides.
            except OSError as exc:
                inv.fail(str(home) if home else sid, exc)
    for path in extra_dirs:
        folder(Path(path).absolute())
    seen = set()

    def visit(path, startup=False):
        try:
            startup |= roots.get(str(path), False)
            info = path.lstat()
            if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                inv.fail(str(path), "reparse point excluded")
            elif stat.S_ISDIR(info.st_mode):
                if (path, startup) in seen:
                    return
                seen.add((path, startup))
                for child in path.iterdir():
                    visit(child, startup)
            elif startup or path.suffix.lower() in (".lnk", ".url"):
                with path.open("rb") as f:
                    if path.suffix.lower() not in (".lnk", ".url"):
                        checksum = hashlib.file_digest(f, "sha256").hexdigest()
                        inv.add(str(path), {"sha256": checksum, "startup": startup})
                        return
                    data = f.read(8 * 1024 * 1024 + 1)
                if len(data) > 8 * 1024 * 1024:
                    raise ValueError("shortcut exceeds 8 MiB")
                item = {"sha256": digest(data), "startup": startup}
                if path.suffix.lower() == ".lnk":
                    try:
                        item.update(parse_link(data))
                    except ValueError as exc:
                        item["parseError"] = str(exc)
                        inv.fail(str(path), exc)
                else:
                    codec = "utf-16" if data[:2] in (b"\xfe\xff", b"\xff\xfe") else "utf-8-sig"
                    item["url"] = [s[4:] for s in data.decode(codec, "replace").splitlines() if s.lower().startswith("url=")]
                inv.add(str(path), item)
        except FileNotFoundError as exc:
            if str(path) not in roots:
                inv.fail(str(path), exc)
        except (ValueError, OSError) as exc:
            inv.fail(str(path), exc)

    for root, startup in sorted(roots.items()):
        visit(Path(root), startup)
    return inv


def ps_inventory(section, cursors=None, input_data=None):
    inv = Inventory()
    exe = Path(os.environ["SystemRoot"], "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    output = b""
    try:
        p = subprocess.run([str(exe), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                            "-File", str(Path(__file__).with_name("collect.ps1")), section],
                           capture_output=True, input=json.dumps(input_data).encode() if input_data is not None else None,
                           env=dict(os.environ, WM_EVENT_CURSORS=json.dumps(cursors or {})),
                           timeout=240, creationflags=subprocess.CREATE_NO_WINDOW)
        output = p.stdout
        if p.returncode:
            inv.fail("", p.stderr.decode("utf-8", "replace")[:1500] or f"exit {p.returncode}")
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"").rpartition(b"\n")[0]
        inv.fail("", f"采集超时，保留已完成记录（{exc.timeout}s）")
    except OSError as exc:
        inv.fail("", exc)
    try:
        for line in output.decode("utf-8-sig").splitlines():
            row = json.loads(line)
            if "error" in row:
                inv.fail(row["key"], row["error"])
            else:
                inv.add(row["key"], row["value"])
    except (ValueError, KeyError) as exc:
        inv.fail("", exc)
    return inv


SECTIONS = ("tasks", "firewall", "defender", "firmware", "gpo", "wmi", "system")


def collect_settings(extra_registry, extra_dirs, cursors, extra_uefi):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        pending = {s: pool.submit(ps_inventory, s) for s in SECTIONS}
        pending["events"] = pool.submit(ps_inventory, "events", cursors)
        try:
            results["shortcuts"] = shortcuts(extra_dirs)
        except OSError as exc:
            results.setdefault("shortcuts", Inventory()).fail("", exc)
        try:
            results["services"] = services()
        except OSError as exc:
            results.setdefault("services", Inventory()).fail("", exc)
        results.update(registry_sets(extra_registry))
        from firmware import read_variables
        results["uefi"] = Inventory()
        read_variables(results["uefi"], extra_uefi)
        for section, future in pending.items():
            results[section] = future.result()
    return results
