"""Observe current-user Chromium profiles without loading extensions or browsing history."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

from inventory import Inventory


def local_stat(path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise OSError("重解析点，未读取")
    return info


def file_bytes(path, limit):
    info = local_stat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError("文件类型或大小超出扫描范围")
    with path.open("rb") as f:
        data = f.read(info.st_size + 1)
    after = local_stat(path)
    if (len(data), after.st_mtime_ns, after.st_ino) != (info.st_size, info.st_mtime_ns, info.st_ino):
        raise OSError("文件在扫描期间发生变化")
    return data


def extension(path):
    manifest_bytes = file_bytes(path / "manifest.json", 2 << 20)
    manifest = json.loads(manifest_bytes.decode("utf-8-sig"))
    files = {}
    remaining = 128 << 20
    todo = [path]
    while todo:
        parent = todo.pop()
        local_stat(parent)
        for entry in parent.iterdir():
            info = local_stat(entry)
            if stat.S_ISDIR(info.st_mode):
                todo.append(entry)
                continue
            if len(files) >= 4096:
                raise ValueError("扩展超过 4096 个文件")
            data = file_bytes(entry, remaining)
            remaining -= len(data)
            files[entry.relative_to(path).as_posix()] = hashlib.sha256(data).hexdigest()
    # The permission metadata and the fingerprint must come from the same manifest.
    if files.get("manifest.json") != hashlib.sha256(manifest_bytes).hexdigest():
        raise OSError("扩展清单在扫描期间发生变化")
    return {"version": manifest["version"], "permissions": manifest.get("permissions", []),
            "hostPermissions": manifest.get("host_permissions", []), "files": files}


def redact_location(value):
    raw = str(value)
    uri = urlsplit(raw)
    return {"host": uri.hostname, "sha256": hashlib.sha256(raw.encode()).hexdigest()}


def preferences(path):
    data = json.loads(file_bytes(path, 32 << 20).decode("utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("浏览器配置不是对象")
    result = {}
    session = data.get("session", {})
    for key in ("restore_on_startup", "startup_urls"):
        if key in session:
            result[key] = [redact_location(v) for v in session[key]] if key == "startup_urls" else session[key]
    if "homepage" in data:
        result["homepage"] = redact_location(data["homepage"])
    if "homepage_is_newtabpage" in data:
        result["homepage_is_newtabpage"] = data["homepage_is_newtabpage"]
    for ext_id, settings in data.get("extensions", {}).get("settings", {}).items():
        if re.fullmatch("[a-p]{32}", ext_id):
            result[ext_id] = {k: settings[k] for k in ("state", "location", "disable_reasons", "active_permissions")
                              if k in settings}
    return result


def browser_inventory(roots=None):
    if roots is None:
        local = Path(os.environ["LOCALAPPDATA"])
        roots = {"Chrome": local / "Google/Chrome/User Data", "Edge": local / "Microsoft/Edge/User Data"}
    ext, prefs = Inventory(), Inventory()
    errors = (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError)
    for browser, root in roots.items():
        try:
            for ancestor in [*reversed(root.parents), root]:
                local_stat(ancestor)
        except FileNotFoundError:
            continue
        except OSError as exc:
            ext.fail(browser, exc)
            prefs.fail(browser, exc)
            continue
        try:
            profiles = list(root.iterdir())
        except OSError as exc:
            ext.fail(browser, exc)
            prefs.fail(browser, exc)
            continue
        for profile in profiles:
            # Standard on-disk user profile directories; guest/system caches are excluded.
            if profile.name != "Default" and not re.fullmatch(r"Profile \d+", profile.name):
                continue
            key = browser + "\\" + profile.name
            try:
                local_stat(profile)
            except OSError as exc:
                ext.fail(key, exc)
                prefs.fail(key, exc)
                continue
            for name in ("Preferences", "Secure Preferences"):
                item = key + "\\" + name
                try:
                    prefs.add(item, preferences(profile / name))
                except FileNotFoundError:
                    pass
                except errors as exc:
                    prefs.fail(item, exc)
            folder = profile / "Extensions"
            try:
                local_stat(folder)
                dirs = list(folder.iterdir())
            except FileNotFoundError:
                continue
            except OSError as exc:
                ext.fail(key, exc)
                continue
            for directory in dirs:
                if not re.fullmatch("[a-p]{32}", directory.name):
                    continue
                ext_key = key + "\\" + directory.name
                try:
                    local_stat(directory)
                    versions = list(directory.iterdir())
                except OSError as exc:
                    ext.fail(ext_key, exc)
                    continue
                for version in versions:
                    item = ext_key + "\\" + version.name
                    try:
                        if stat.S_ISDIR(local_stat(version).st_mode):
                            ext.add(item, extension(version))
                    except errors as exc:
                        ext.fail(item, exc)
    return {"browser-extensions": ext, "browser-preferences": prefs}
