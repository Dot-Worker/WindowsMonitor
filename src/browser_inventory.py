"""Observe current-user Chromium profiles without loading extensions or browsing history."""
import hashlib
import json
import ntpath
import os
from pathlib import Path, PureWindowsPath
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


def extension(path, manifest, manifest_bytes):
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


def declared_paths(manifest):
    def array(obj, field):
        values = obj.get(field, [])
        if not isinstance(values, list):
            raise ValueError("扩展清单的 " + field + " 不是数组")
        return values

    background = manifest.get("background", {})
    paths = array(background, "scripts").copy()
    for field in ("service_worker", "page"):
        if field in background:
            paths.append(background[field])
    for content in array(manifest, "content_scripts"):
        paths.extend(array(content, "js"))
        paths.extend(array(content, "css"))
    if not all(isinstance(s, str) for s in paths):
        raise ValueError("扩展入口路径格式错误")
    return list(dict.fromkeys(paths))


def entry_path(raw):
    relative = raw.removeprefix("/")
    parts = relative.split("/")
    if any(not part or part in (".", "..") or part.endswith((".", " "))
           or re.search(r'[\\:<>"|?*\x00-\x1f]', part) or reserved_name(part) for part in parts):
        raise ValueError("不是安全的扩展内相对路径")
    return relative


def reserved_name(name):
    if hasattr(ntpath, "isreserved"):
        return ntpath.isreserved(name)
    return PureWindowsPath(name).is_reserved()


def collect_extension(path, key, packages, entries):
    raw = file_bytes(path / "manifest.json", 2 << 20)
    manifest = json.loads(raw.decode("utf-8-sig"))
    manifest_info = {"version": manifest["version"], "sha256": hashlib.sha256(raw).hexdigest(),
                     "permissions": manifest.get("permissions", []), "hostPermissions": manifest.get("host_permissions", [])}
    complete = None
    try:
        complete = extension(path, manifest, raw)
    except (OSError, ValueError) as exc:
        packages.fail(key, exc)
    scripts = key + "\\scripts"
    tmp = Inventory()
    try:
        paths = declared_paths(manifest)
        if len(paths) > 128:
            raise ValueError("超过 128 个声明入口")
        remaining = 32 << 20
        for name in paths:
            item = scripts + "\\" + name
            try:
                rel = entry_path(name)
                item = scripts + "\\" + rel
                if complete is not None and rel in complete["files"]:
                    checksum = complete["files"][rel]
                else:
                    file = path
                    for part in rel.split("/")[:-1]:
                        file = file / part
                        local_stat(file)
                    data = file_bytes(path / rel, min(8 << 20, remaining))
                    remaining -= len(data)
                    checksum = hashlib.sha256(data).hexdigest()
                tmp.add(item, {"sha256": checksum, "present": True})
            except FileNotFoundError:
                tmp.add(item, {"present": False, "sha256": None})
            except (OSError, ValueError) as exc:
                tmp.fail(item, exc)
    except (ValueError, TypeError, AttributeError) as exc:
        tmp.fail(scripts, exc)
    # Only publish evidence that still belongs to this manifest.
    if file_bytes(path / "manifest.json", 2 << 20) != raw:
        raise OSError("扩展清单在扫描期间发生变化")
    if complete is not None:
        packages.add(key, complete)
    entries.add(key + "\\manifest", manifest_info)
    entries.rows.update(tmp.rows)
    entries.errors.update(tmp.errors)


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
    ext, prefs, entries = Inventory(), Inventory(), Inventory()
    def unreadable(key, reason):
        ext.fail(key, reason)
        entries.fail(key, reason)
    errors = (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError)
    for browser, root in roots.items():
        try:
            for ancestor in [*reversed(root.parents), root]:
                local_stat(ancestor)
        except FileNotFoundError:
            continue
        except OSError as exc:
            unreadable(browser, exc)
            prefs.fail(browser, exc)
            continue
        try:
            profiles = list(root.iterdir())
        except OSError as exc:
            unreadable(browser, exc)
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
                unreadable(key, exc)
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
                unreadable(key, exc)
                continue
            for directory in dirs:
                if not re.fullmatch("[a-p]{32}", directory.name):
                    continue
                ext_key = key + "\\" + directory.name
                try:
                    local_stat(directory)
                    versions = list(directory.iterdir())
                except OSError as exc:
                    unreadable(ext_key, exc)
                    continue
                for version in versions:
                    item = ext_key + "\\" + version.name
                    try:
                        if stat.S_ISDIR(local_stat(version).st_mode):
                            collect_extension(version, item, ext, entries)
                    except errors as exc:
                        unreadable(item, exc)
    return {"browser-extensions": ext, "browser-preferences": prefs, "browser-entrypoints": entries}
