"""WindowsMonitor CLI. Python >= 3.11, no third-party packages."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import html
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time

from inventory import Inventory, collect_settings, covered, file_tree, machine, services, shortcut_findings
from protections import browser_changes, defense_events, defense_state, defender_exclusions, recovery_tasks, shadow_changes, task_cache_audit, wmi_subscriptions


FROZEN = getattr(sys, "frozen", False)
SOURCE_ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = Path(__file__).with_name("VERSION") if FROZEN else SOURCE_ROOT / "VERSION"
APP_VERSION = VERSION_FILE.read_text(encoding="ascii").strip()


def default_state():
    if not FROZEN:
        return SOURCE_ROOT / ".windowsmonitor"
    exe_dir = Path(sys.executable).resolve().parent
    if exe_dir.name.casefold() == "dist" and (exe_dir.parent / "VERSION").is_file() and (exe_dir.parent / "src").is_dir():
        return exe_dir.parent / ".windowsmonitor"
    return Path(os.environ["LOCALAPPDATA"], "WindowsMonitor")


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def say(message):
    print(message, flush=True)


@contextmanager
def lock(state, job):
    import msvcrt
    state.mkdir(parents=True, exist_ok=True)
    with (state / (job + ".lock")).open("a+b") as f:
        f.seek(0)
        try:
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise ValueError(job + " 扫描正在运行") from exc
        try:
            yield
        finally:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)


def database(path):
    db = sqlite3.connect(path, timeout=120)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS metadata(name TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS items(scope TEXT, id TEXT, label TEXT, value TEXT, PRIMARY KEY(scope,id));
        CREATE TABLE IF NOT EXISTS coverage(scope TEXT PRIMARY KEY, gaps TEXT);
        CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, job TEXT, stamp TEXT, version TEXT, report TEXT);
    """)
    return db


def change(scope, label, kind, previous=None, current=None):
    row = {"scope": scope, "key": label, "kind": kind}
    if previous is not None:
        row["before"] = previous
    if current is not None:
        row["after"] = current
    return row


def delta(old, new):
    if isinstance(old, dict) and isinstance(new, dict):
        fields = {k for k in old.keys() | new.keys() if old.get(k) != new.get(k) or (k in old) != (k in new)}
        return ({k: old[k] for k in fields if k in old}, {k: new[k] for k in fields if k in new})
    return old, new


def update_scope(db, scope, inv):
    previous = db.execute("SELECT gaps FROM coverage WHERE scope=?", (scope,)).fetchone()
    old_gaps = json.loads(previous[0]) if previous else {}
    old = {k: (label, v) for k, label, v in db.execute("SELECT id,label,value FROM items WHERE scope=?", (scope,))}
    changes = []
    writes = []
    deletes = []
    for k, (label, value) in inv.rows.items():
        before = old.pop(k, None)
        if scope == "services" and before:
            value = dict(value)
            for field, prior in json.loads(before[1]).items():
                if not covered(k + "\\" + field, inv.errors):
                    value[field] = prior
        raw = encode(value)
        if before and not covered(k, inv.errors):
            continue  # Do not replace the last known complete record with a partial read.
        if before and before[1] == raw:
            continue
        if before:
            a, b = delta(json.loads(before[1]), value)
            changes.append(change(scope, label, "修改" if covered(k, old_gaps) else "重新可读，存在差异", a, b))
        elif previous:
            kind = "新增" if covered(k, old_gaps) else "首次可读"
            changes.append(change(scope, label, kind, current=value))
        writes.append((scope, k, label, raw))
    for k, (label, raw) in old.items():
        if covered(k, inv.errors):
            kind = {"system-processes": "进程不再可见", "loaded-modules": "不再观测到加载",
                    "module-files": "本轮无加载记录", "executable-memory": "不再观测到该执行区域"}.get(scope, "删除")
            changes.append(change(scope, label, kind, previous=json.loads(raw)))
            deletes.append((scope, k))
    db.executemany("INSERT OR REPLACE INTO items VALUES(?,?,?,?)", writes)
    db.executemany("DELETE FROM items WHERE scope=? AND id=?", deletes)
    db.execute("INSERT OR REPLACE INTO coverage VALUES(?,?)", (scope, encode(inv.errors)))
    return changes


def file_roots(specs):
    roots = {"Windows": Path(os.environ["SystemRoot"])}
    for spec in specs:
        label, sep, path = spec.partition("=")
        if not sep or not label.strip() or not Path(path).is_absolute() or label in roots:
            raise ValueError("--file-root 应为唯一名称=绝对路径")
        roots[label] = Path(path)
    return roots


def file_sets(roots):
    results = {}
    for label, path in roots.items():
        say(f"正在计算 SHA-256，目录 {path}")
        results["files/" + label] = file_tree(path)
    return results


def reference(path, roots, version):
    if path.exists():
        raise ValueError("清单已存在，请选择新的输出文件")
    collection = {"services": services(), **file_sets(roots)}
    # Publish only complete databases. A partial inventory retains all coverage gaps.
    fd, name = tempfile.mkstemp(dir=path.parent, suffix=".sqlite")
    os.close(fd)
    try:
        with sqlite3.connect(name) as db:
            db.executescript("""
                CREATE TABLE manifest(version TEXT, created TEXT, format INTEGER);
                CREATE TABLE scopes(scope TEXT PRIMARY KEY, gaps TEXT);
                CREATE TABLE items(scope TEXT, id TEXT, label TEXT, value TEXT, PRIMARY KEY(scope,id));
            """)
            db.execute("INSERT INTO manifest VALUES(?,?,1)", (encode(version), now()))
            for scope, inv in collection.items():
                db.execute("INSERT INTO scopes VALUES(?,?)", (scope, encode(inv.errors)))
                db.executemany("INSERT INTO items VALUES(?,?,?,?)",
                               ((scope, k, label, encode(v)) for k, (label, v) in inv.rows.items()))
                say(f"{scope}：{len(inv.rows)} 项，{len(inv.errors)} 个覆盖缺口")
        db.close()
        os.rename(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def compare_reference(path, version, collection):
    result = {"path": str(path) if path else None, "status": "未提供可信原版清单", "differences": []}
    if not path:
        return result
    db = None
    try:
        db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        db.execute("PRAGMA trusted_schema=OFF")
        row = db.execute("SELECT version,created,format FROM manifest").fetchone()
        if not row or row[2] != 1:
            raise ValueError("不支持的清单格式")
        expected = json.loads(row[0])
        result.update(version=expected, created=row[1])
        if version != expected:
            result["status"] = "系统版本、架构或安装语言不匹配，已跳过"
            return result
        result.update(status="已与匹配清单比较", scopes={}, initialServices=[])
        for scope, raw_gaps in db.execute("SELECT scope,gaps FROM scopes"):
            if scope == "files/Windows" and "module-files" in collection:
                gaps = json.loads(raw_gaps)
                result["moduleChecks"] = {}
                for path, value in collection["module-files"].rows.values():
                    if not Path(path).is_relative_to(Path(os.environ["SystemRoot"])):
                        continue
                    key = str(Path(path).relative_to(os.environ["SystemRoot"])).casefold()
                    match = db.execute("SELECT value FROM items WHERE scope=? AND id=?", (scope, key)).fetchone()
                    if not covered(key, gaps) or "sha256" not in value:
                        status = "无法比较"
                    elif not match:
                        status = "清单未收录"
                    else:
                        expected_hash = json.loads(match[0]).get("sha256")
                        status = ("与清单一致" if expected_hash == value["sha256"] else "与清单哈希不同") if expected_hash else "无法比较"
                    result["moduleChecks"][path] = status
                result["scopes"][scope] = {"checkedLoadedFiles": len(result["moduleChecks"]), "referenceGaps": gaps}
                continue
            if scope not in collection:
                result["scopes"][scope] = {"status": "本轮未扫描此范围"}
                continue
            inv = collection[scope]
            gaps = json.loads(raw_gaps)
            result["scopes"][scope] = {"referenceGaps": gaps}
            left = set(inv.rows)
            for k, label, raw in db.execute("SELECT id,label,value FROM items WHERE scope=?", (scope,)):
                left.discard(k)
                if scope == "services":
                    result["initialServices"].append(label)
                if not covered(k, inv.errors) or not covered(k, gaps):
                    continue
                if k not in inv.rows:
                    result["differences"].append(change(scope, label, "清单中存在，本机缺失", previous=json.loads(raw)))
                else:
                    expected_value, actual = json.loads(raw), inv.rows[k][1]
                    if scope == "services":
                        known = {field for field in expected_value.keys() | actual.keys()
                                 if covered(k + "\\" + field, inv.errors) and covered(k + "\\" + field, gaps)}
                        expected_value = {f: v for f, v in expected_value.items() if f in known}
                        actual = {f: v for f, v in actual.items() if f in known}
                    if expected_value != actual:
                        a, b = delta(expected_value, actual)
                        result["differences"].append(change(scope, label, "与清单内容不同", a, b))
            if scope == "services":
                for k in sorted(left):
                    if covered(k, gaps) and covered(k, inv.errors):
                        label, value = inv.rows[k]
                        result["differences"].append(change(scope, label, "清单之外的服务", current=value))
    except (sqlite3.Error, OSError, ValueError, TypeError) as exc:
        result.update(status="清单无法使用：" + str(exc), differences=[])
    finally:
        if db:
            db.close()
    return result


def atomic(path, content):
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(content)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def process_evidence(collection, reference_result):
    hosts = collection["system-processes"]
    files = collection["module-files"]
    associations = {}
    for key, host in hosts.rows.values():
        associations.setdefault(host["image"].casefold(), set()).add(key)
    for key, value in collection["loaded-modules"].rows.values():
        instance = "\\".join(key.split("\\", 3)[:3])
        associations.setdefault(value["path"].casefold(), set()).add(instance)
    findings = []
    for path, instances in sorted(associations.items()):
        label, row = files.rows.get(path, (path, {"class": "无法读取文件"}))
        check = reference_result.get("moduleChecks", {}).get(label)
        if row["class"] != "Windows 签名" or check not in (None, "与清单一致") or not covered(path, files.errors):
            findings.append({"path": label, "hosts": sorted(instances), "reference": check, **row})
    return {"hosts": len(hosts.rows), "modules": len(collection["loaded-modules"].rows), "files": len(files.rows),
            "moduleFindings": findings, "memory": dict(collection["executable-memory"].rows.values())}


def preserve_unreadable_loads(db, collection):
    files = collection["module-files"]
    for scope, field in (("system-processes", "image"), ("loaded-modules", "path")):
        gaps = collection[scope].errors
        if not gaps:
            continue
        for key, value in db.execute("SELECT id,value FROM items WHERE scope=?", (scope,)):
            if not covered(key, gaps):
                path = json.loads(value)[field]
                if path.casefold() not in files.rows:
                    files.fail(path, "上次宿主本轮不可读")


def report_html(report):
    def esc(v):
        if not isinstance(v, str):
            v = json.dumps(v, ensure_ascii=False, sort_keys=True, indent=2)
        return html.escape(v).encode("utf-8", "backslashreplace").decode()

    def cards(title, entries):
        body = []
        for heading, details in entries:
            body.append(f"<details><summary>{esc(heading)}</summary><pre>{esc(details)}</pre></details>")
        return f"<section><h2>{esc(title)} · {len(body)}</h2>{''.join(body) or '<p>本轮无记录</p>'}</section>"

    ref = report["reference"]
    proc = report.get("processes", {})
    security = report.get("security")
    audit = (security or {}).get("taskCache")
    return "".join([
        '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        '<title>WindowsMonitor 本机报告</title><style>body{max-width:1050px;margin:2em auto;padding:0 1em;background:#f4f6f8;color:#182d40;'
        'font:16px/1.55 "Segoe UI",sans-serif}section{background:white;padding:1em;margin:1em 0;border-radius:8px}'
        'h2{font-size:1.2em;margin:0 0 .7em}summary{cursor:pointer;overflow-wrap:anywhere}details{border-top:1px solid #ddd;padding:.4em}'
        'pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.87em}</style>',
        f"<h1>WindowsMonitor 本机报告</h1><p>{esc(report['time'])} · {esc(report['job'])} · {esc(report['version']['CurrentBuild'])}.{esc(report['version']['UBR'])}</p>",
        f"<p>{esc(report['baselineNote'])}。{esc(ref['status'])}。</p>",
        cards("Defender 当前配置", list(security["state"].items())) if security else "",
        cards("UEFI 启动项与 shim 运行时镜像", list(security["bootEvidence"].items())) if security and "bootEvidence" in security else "",
        cards("Defender 排除范围及可见性", [(v["type"] + " · 可见 " + str(v["visible"]) + " 项", v)
                                         for v in security["exclusions"]["categories"]]) if security and "exclusions" in security else "",
        cards("Defender 可见排除声明", [(v["type"] + " · " + v["value"], v)
                                    for v in security["exclusions"]["entries"]]) if security and "exclusions" in security else "",
        cards("阻止、审计与威胁处置事件", [(e["title"] + " · " + e["time"], e) for e in security["events"]]) if security else "",
        cards("浏览器扩展与启动配置变化", [(e["title"] + " · " + e["key"], e) for e in security["browserChanges"]]) if security else "",
        cards("登记了强制安装的浏览器扩展", [(p["browser"] + " · " + p["id"], p)
                                      for p in security.get("browserPolicies", [])]) if security else "",
        cards("可能影响系统恢复的计划任务", [(e["task"], e) for e in security["recoveryTasks"]]) if security else "",
        cards("WMI 条件触发的命令或脚本", [(v["consumer"], v) for v in security.get("wmiSubscriptions", {}).get("execution", [])]) if security else "",
        cards("WMI 订阅引用读取缺口", [(v["key"], v) for v in security.get("wmiSubscriptions", {}).get("unresolved", [])]) if security else "",
        cards("Sysmon 记录的 WMI 登记活动", [(v["title"] + " · " + v["time"], v)
                                        for v in security.get("wmiSubscriptions", {}).get("registrationEvents", [])]) if security else "",
        (f"<p>计划任务缓存根键{'可读' if audit['rootObserved'] else '未观察到'} · 可核对缓存任务 {audit['checked']} 个 · "
         f"任务计划 API 本轮列出 {audit['apiCount']} 个</p>" +
         cards("缺少安全描述符的任务缓存", [(t["task"], t) for t in audit["findings"]])) if audit else "",
        cards("卷影存储与副本的观测变化", [(e["title"] + " · " + e["key"], e) for e in security.get("shadowChanges", [])]) if security else "",
        (f"<p>{proc['hosts']} 个系统进程 · {proc['modules']} 条加载记录 · {proc['files']} 个磁盘映像。"
         "下列记录是待核对线索，JIT、热补丁和第三方扩展也会产生记录。</p>" if proc else ""),
        cards("系统进程内待核对的模块", [(x["class"] + " · " + x["path"], x) for x in proc.get("moduleFindings", [])]) if proc else "",
        cards("可执行内存线索", [(v["kind"] + " · " + k, v) for k, v in proc.get("memory", {}).items()]) if proc else "",
        cards("浏览器快捷方式待核对", [(f["reason"] + " · " + f["path"], f) for f in report["shortcuts"]]),
        cards("与上次观测的差异", [(f"{c['kind']} · {c['scope']} · {c['key']}", c) for c in report["changes"]]),
        cards("两轮之间的 Windows 事件", [(f"{channel} · {e['time']} · {e['id']}", e)
                                    for channel, v in report.get("eventLogs", {}).items() for e in v["events"]]),
        cards("事件日志读取位置", [(k, {"record": v["cursor"], "note": v["note"]}) for k, v in report.get("eventLogs", {}).items()]),
        cards("与可信原版清单的差异", [(f"{c['kind']} · {c['key']}", c) for c in ref["differences"]]),
        cards("读取范围与缺口", list(report["coverage"].items())),
        cards("参考清单覆盖", list(ref.get("scopes", {}).items())),
        cards("清单中的初始服务", [(s, s) for s in ref.get("initialServices", [])]),
        cards("当前服务和驱动", [(k, v) for k, v in report["services"].items()]),
        '</html>'])


def scan(args, job):
    host, version = machine()
    state = args.state.resolve()
    with lock(state, job):
        started = now()
        if job == "files":
            roots = file_roots(args.file_root)
            for path in roots.values():
                if state.is_relative_to(path.resolve()):
                    raise ValueError("监控数据目录必须位于文件扫描范围之外")
            collection = file_sets(roots)
        elif job == "processes":
            from processes import collect_processes
            collection = collect_processes(args.process)
        else:
            with database(state / "monitor.sqlite") as reader:
                cursors = {k[6:]: int(v) for k, v in reader.execute("SELECT name,value FROM metadata WHERE name LIKE 'event/%'")}
                previous_uefi = [r[0] for r in reader.execute("SELECT label FROM items WHERE scope='uefi'")]
            reader.close()
            collection = collect_settings(args.registry, args.shortcuts, cursors, args.uefi, previous_uefi)
            exclusions = defender_exclusions(collection["defender"])
        ref = compare_reference(args.reference, version, collection)
        db = database(state / "monitor.sqlite")
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                identity = db.execute("SELECT value FROM metadata WHERE name='host'").fetchone()
                if identity and host != identity[0]:
                    raise ValueError("该数据目录属于另一台计算机，请使用其他 --state")
                db.execute("INSERT OR IGNORE INTO metadata VALUES('host',?)", (host,))
                prev = db.execute("SELECT stamp,version FROM runs WHERE job=? ORDER BY id DESC LIMIT 1", (job,)).fetchone()
                if job == "files":
                    for name, path in roots.items():
                        key = "file-root/" + name
                        value = str(path.resolve()).casefold()
                        binding = db.execute("SELECT value FROM metadata WHERE name=?", (key,)).fetchone()
                        if binding and binding[0] != value:
                            raise ValueError("文件范围目录已变化，请更换范围名称或数据目录：" + name)
                        db.execute("INSERT OR IGNORE INTO metadata VALUES(?,?)", (key, value))
                changes = []
                event_logs = {}
                if job == "processes":
                    preserve_unreadable_loads(db, collection)
                for scope, inv in collection.items():
                    if scope == "events":
                        for channel, value in inv.rows.values():
                            event_logs[channel] = value
                            db.execute("INSERT OR REPLACE INTO metadata VALUES(?,?)", ("event/" + channel, str(value["cursor"])))
                    else:
                        changes.extend(update_scope(db, scope, inv))
                report = {
                    "monitorVersion": APP_VERSION,
                    "time": now(), "started": started, "job": job, "version": version,
                    "previousTime": prev[0] if prev else None, "previousVersion": json.loads(prev[1]) if prev else None,
                    "baselineNote": "首次建立本机观测基线" if not prev else "对比各范围上次可读记录",
                    "changes": changes, "shortcuts": shortcut_findings(collection.get("shortcuts", Inventory())),
                    "eventLogs": event_logs,
                    "coverage": {k: {"observed": len(i.rows), "errors": i.errors} for k, i in collection.items()},
                    "reference": ref,
                    "services": dict(collection.get("services", Inventory()).rows.values()),
                }
                if job == "processes":
                    report["processes"] = process_evidence(collection, ref)
                if job == "settings":
                    report["security"] = {"state": defense_state(collection["defender"]), "events": defense_events(event_logs),
                                          "exclusions": exclusions,
                                          "bootEvidence": dict(collection["uefi-details"].rows.values()),
                                          "browserChanges": browser_changes(changes), "recoveryTasks": recovery_tasks(collection["tasks"]),
                                          "shadowChanges": shadow_changes(changes),
                                          "taskCache": task_cache_audit(collection["settings/HKLM"], collection["tasks"], changes),
                                          "wmiSubscriptions": wmi_subscriptions(collection["wmi"], event_logs),
                                          "browserPolicies": [{"key": key, **value} for key, value in collection["browser-policy"].rows.values()]}
                # Journal differences and gaps. Current full inventory is in items.
                journal = {k: v for k, v in report.items() if k != "services"}
                db.execute("INSERT INTO runs(job,stamp,version,report) VALUES(?,?,?,?)",
                           (job, report["time"], encode(version), encode(journal)))
            atomic(state / (job + ".json"), json.dumps(report, ensure_ascii=True, indent=2))
            atomic(state / (job + ".html"), report_html(report))
            say(f"{job}：{len(changes)} 项变化。报告 {state / (job + '.html')}")
        finally:
            db.close()


def interval(s):
    n = int(s)
    if n < 1:
        raise argparse.ArgumentTypeError("必须为正整数")
    return n


def main():
    p = argparse.ArgumentParser(description="WindowsMonitor 本机只读监控")
    p.add_argument("--version", action="version", version="WindowsMonitor " + APP_VERSION)
    subs = p.add_subparsers(dest="command", required=True)
    for name in ("ui", "scan", "files", "processes", "watch", "reference", "history", "inventory"):
        c = subs.add_parser(name)
        if name != "reference":
            c.add_argument("--state", type=Path, default=default_state())
        if name in ("files", "reference", "watch"):
            c.add_argument("--file-root", action="append", default=[], metavar="LABEL=PATH")
        if name in ("scan", "files", "processes", "watch"):
            c.add_argument("--reference", type=Path)
        if name in ("processes", "watch"):
            c.add_argument("--process", action="append", default=[], metavar="IMAGE.EXE", help="额外监控此名称的进程")
        if name in ("scan", "watch"):
            c.add_argument("--uefi", action="append", default=[], metavar="NAME=GUID")
            c.add_argument("--registry", action="append", default=[], metavar="HIVE\\PATH")
            c.add_argument("--shortcuts", action="append", default=[], metavar="DIRECTORY")
        if name == "watch":
            c.add_argument("--interval", type=interval, default=300, help="设置扫描间隔秒数")
            c.add_argument("--file-hours", type=interval, default=24, help="文件扫描间隔小时数")
        if name == "reference":
            c.add_argument("--out", type=Path, required=True)
        if name == "history":
            c.add_argument("--limit", type=interval, default=10)
            c.add_argument("--out", type=Path)
        if name == "inventory":
            c.add_argument("--scope", help="导出指定范围，省略时列出范围及记录数")
            c.add_argument("--out", type=Path, help="将结果写入 JSON 文件")
    args = p.parse_args(sys.argv[1:] or ["ui"])
    if args.command == "ui":
        desktop(args.state)
    elif args.command == "reference":
        reference(args.out, file_roots(args.file_root), machine()[1])
    elif args.command == "inventory":
        uri = (args.state / "monitor.sqlite").resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as db:
            if args.scope:
                data = {k: json.loads(v) for k, v in db.execute("SELECT label,value FROM items WHERE scope=? ORDER BY id", (args.scope,))}
            else:
                data = dict(db.execute("SELECT scope,COUNT(*) FROM items GROUP BY scope"))
        if args.out:
            atomic(args.out, json.dumps(data, ensure_ascii=True, indent=2))
        else:
            say(json.dumps(data, ensure_ascii=True, indent=2))
    elif args.command == "history":
        uri = (args.state / "monitor.sqlite").resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as db:
            data = [json.loads(row[0]) for row in db.execute("SELECT report FROM runs ORDER BY id DESC LIMIT ?", (args.limit,))]
        if args.out:
            atomic(args.out, json.dumps(data, ensure_ascii=True, indent=2))
        else:
            for entry in data:
                say(f"{entry['time']} {entry['job']}：{len(entry['changes'])} 项变化")
    elif args.command == "watch":
        watch(args)
    else:
        scan(args, "settings" if args.command == "scan" else args.command)


def file_wait(state, delay):
    path = state / "monitor.sqlite"
    if not path.is_file():
        return 0
    try:
        with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
            last = db.execute("SELECT stamp FROM runs WHERE job='files' ORDER BY id DESC LIMIT 1").fetchone()
    except sqlite3.Error:
        return 0
    if not last:
        return 0
    age = time.time() - datetime.fromisoformat(last[0]).timestamp()
    return max(0, min(delay, delay - age))


def desktop(state):
    def launch(exe):
        cmd = [str(exe), str(state.resolve()), sys.executable, "" if FROZEN else str(Path(__file__).resolve()), APP_VERSION]
        subprocess.run(cmd, check=True)

    if FROZEN:
        launch(Path(__file__).with_name("WindowsMonitor.Desktop.exe"))
    else:
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp, "WindowsMonitor.Desktop.exe")
            powershell = Path(os.environ["SystemRoot"], "System32/WindowsPowerShell/v1.0/powershell.exe")
            subprocess.run([str(powershell), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                            str(Path(__file__).parent / "Desktop/Compile.ps1"), str(exe)], check=True)
            launch(exe)


def watch(args):
    from threading import Event, Thread
    stop = Event()
    wake = {job: Event() for job in ("settings", "processes", "files")}
    with lock(args.state, "watch"):
        pidfile = args.state / "watch.pid"
        token_info = args.state / "watch.json"
        signal = args.state / "stop.request"
        signal.unlink(missing_ok=True)
        from ctypes import windll
        atomic(token_info, encode({"pid": os.getpid(), "elevated": bool(windll.shell32.IsUserAnAdmin()), "started": now(),
                                  "monitorVersion": APP_VERSION, "manualRequests": True}))
        atomic(pidfile, str(os.getpid()))
        def loop(job, delay):
            while not stop.is_set():
                manual = wake[job].is_set()
                if manual:
                    wake[job].clear()
                if job == "files" and not manual and not args.file_root and not args.reference:
                    pending = file_wait(args.state, delay)
                    if pending:
                        wake[job].wait(pending)
                        continue
                retry_after = delay
                try:
                    scan(args, job)
                except Exception as exc:
                    say(f"{now()} {job} 扫描失败：{exc}")
                    retry_after = min(delay, 300)
                wake[job].wait(retry_after)

        workers = [Thread(target=loop, args=(job, delay), daemon=True)
                   for job, delay in (("settings", args.interval), ("processes", args.interval), ("files", args.file_hours * 3600))]
        for thread in workers:
            thread.start()
        try:
            while all(t.is_alive() for t in workers) and not signal.exists():
                for job, event in wake.items():
                    request = args.state / (job + ".request")
                    if request.exists():
                        request.unlink(missing_ok=True)
                        event.set()
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            for event in wake.values():
                event.set()
            pidfile.unlink(missing_ok=True)
            token_info.unlink(missing_ok=True)
            signal.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, sqlite3.Error) as error:
        sys.exit(str(error))
