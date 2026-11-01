"""Summarize observed settings, task actions and Windows Defender events."""
import ntpath
import re
from xml.etree import ElementTree as ET
from inventory import TASK_CACHE_TREE, covered


DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
EVENTS = {
    1116: "检测到威胁", 1117: "Defender 记录了处置动作", 1118: "威胁处置失败", 1119: "威胁处置严重错误",
    1121: "攻击面缩减规则已阻止", 1122: "攻击面缩减规则仅审计", 1129: "用户越过攻击面缩减警告",
    1123: "受控文件夹访问已阻止", 1124: "受控文件夹访问仅审计",
    1127: "受控文件夹扇区写入已阻止", 1128: "受控文件夹扇区写入仅审计",
    5001: "实时保护已关闭", 5010: "恶意或不受欢迎软件扫描已关闭", 5012: "病毒扫描已关闭",
    5013: "篡改防护已阻止设置变更",
}
RECOVERY = {
    "vssadmin": r"(?:delete\s+shadows|resize\s+shadowstorage)\b",
    "wbadmin": r"delete\s+(?:catalog|systemstatebackup|backup)\b",
    "wmic": r"shadowcopy\s+(?:call\s+)?delete\b",
    "bcdedit": r"/set\s+(?:\{[^}]+\}\s+)?(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)\b",
}


def recovery_tasks(inv):
    findings = []
    for key, data in inv.rows.values():
        try:
            xml = ET.fromstring(data["xml"])
        except (ET.ParseError, KeyError):
            continue  # The original task XML is retained in the task inventory.
        for action in xml.findall("./{*}Actions/{*}Exec"):
            command = (action.findtext("{*}Command") or "").strip().strip('"')
            name = ntpath.basename(command).casefold().removesuffix(".exe")
            arguments = (action.findtext("{*}Arguments") or "").strip()
            if name in RECOVERY and re.match(RECOVERY[name], arguments, re.I):
                reason = "任务配置了删除备份或关闭恢复的命令"
                if name == "vssadmin" and arguments.lower().startswith("resize"):
                    reason = "任务配置了卷影存储额度调整，实际影响需对比额度和副本"
                findings.append({"task": key, "enabled": data["enabled"], "command": command, "arguments": arguments, "reason": reason})
    return findings


def task_cache_audit(registry, tasks, changes):
    root = TASK_CACHE_TREE.casefold()
    formerly_had_sd = {c["key"].casefold() for c in changes if c["scope"] == "settings/HKLM"
                       and c["kind"] in ("修改", "重新可读，存在差异") and c["key"].casefold().startswith(root + "\\")
                       and any(name.casefold() == "sd" for name in c.get("before", {}))}
    result = {"rootObserved": root in registry.rows and covered(root, registry.errors),
              "apiCount": len(tasks.rows), "checked": 0, "findings": []}
    for key, (path, values) in registry.rows.items():
        if not key.startswith(root + "\\") or not covered(key, registry.errors):
            continue
        names = {n.casefold() for n in values}
        if "id" not in names:
            continue  # Folder keys are not registered task definitions.
        result["checked"] += 1
        if "sd" in names:
            continue
        name = path[len(TASK_CACHE_TREE):]
        if name.casefold() in tasks.rows:
            visibility = "本轮 API 已列出"
        elif covered(name, tasks.errors):
            visibility = "本轮 API 未列出"
        else:
            visibility = "API 枚举存在读取缺口"
        lost = key in formerly_had_sd
        result["findings"].append({"task": name, "registryKey": path, "descriptor": "Id 存在，SD 值缺失",
                                   "apiVisibility": visibility, "previouslyHadSD": lost,
                                   "highPriority": lost and visibility == "本轮 API 未列出"})
    return result


def shadow_changes(changes):
    result = []
    for row in changes:
        if row["scope"] != "shadows":
            continue
        kind = row["kind"]
        before, after = row.get("before", {}), row.get("after", {})
        review = False
        if row["key"].startswith("copies\\"):
            title = "卷影副本不再可见" if kind == "删除" else "卷影副本观测：" + kind
            review = kind == "删除"
        elif kind == "删除":
            title, review = "卷影存储关联不再可见", True
        elif "maxBytes" in before and "maxBytes" in after:
            try:
                prior, current = int(before["maxBytes"]), int(after["maxBytes"])
                review = current < prior
                title = "卷影存储额度数值下降" if review else "卷影存储额度数值上升"
            except (TypeError, ValueError):
                title = "卷影存储额度发生变化，大小未知"
                review = True
        else:
            title = "卷影存储关联观测：" + kind
        result.append({"title": title, "review": review, "key": row["key"], "kind": kind, "before": before, "after": after})
    return result


def defense_events(event_logs):
    findings = []
    for event in event_logs.get(DEFENDER, {}).get("events", []):
        if event["id"] not in EVENTS or event["provider"] != "Microsoft-Windows-Windows Defender":
            continue
        fields = {}
        try:
            xml = ET.fromstring(event["xml"])
            for field in xml.findall("./{*}EventData/{*}Data"):
                name = field.get("Name", "")
                if name.casefold() in {"path", "process name", "threat name", "action name", "status description",
                                       "detection id", "id", "target file name", "error description", "user"}:
                    fields[name] = field.text
        except ET.ParseError:
            fields["readError"] = "事件 XML 无法解析"
        findings.append({"title": EVENTS[event["id"]], "time": event["time"], "id": event["id"],
                         "record": event["record"], "fields": fields})
    return findings


def browser_changes(changes):
    findings = []
    packages = {row["key"].casefold() for row in changes if row["scope"] == "browser-extensions"}
    for row in changes:
        if row["scope"] not in ("browser-extensions", "browser-preferences", "browser-entrypoints", "browser-policy"):
            continue
        old, new = row.get("before", {}), row.get("after", {})
        item = {"key": row["key"], "kind": row["kind"]}
        if row["scope"] == "browser-policy":
            item["title"] = "浏览器强制安装策略观测变化"
            item["before"] = old
            item["after"] = new
        elif row["scope"] == "browser-entrypoints":
            package = "\\".join(row["key"].split("\\", 4)[:4]).casefold()
            if package in packages:
                continue
            item["title"] = "扩展清单或声明入口变化"
            item["before"] = old
            item["after"] = new
        elif row["scope"] == "browser-preferences":
            item["title"] = "浏览器启动或扩展配置观测变化"
            item["fields"] = sorted(old.keys() | new.keys())
        elif "files" in old and "files" in new and "version" not in old.keys() | new.keys():
            item["title"] = "扩展版本未变，文件内容有变化"
            a, b = old["files"], new["files"]
            item["files"] = sorted(k for k in a.keys() | b.keys() if a.get(k) != b.get(k))
        else:
            item["title"] = "扩展安装目录或清单变化"
        findings.append(item)
    return findings


def defense_state(inv):
    settings = {}
    for name, label, modes in (
        ("preference\\EnableControlledFolderAccess", "受控文件夹访问",
         {0: "关闭", 1: "阻止", 2: "仅审计", 3: "仅阻止扇区写入", 4: "仅审计扇区写入"}),
        ("preference\\PUAProtection", "潜在不受欢迎应用防护", {0: "关闭", 1: "阻止", 2: "仅审计"}),
        ("status\\RealTimeProtectionEnabled", "实时保护", {False: "关闭", True: "开启"}),
        ("status\\IsTamperProtected", "篡改防护", {False: "关闭", True: "开启"}),
        ("status\\AMRunningMode", "Defender 运行模式", {}),
    ):
        raw = inv.rows.get(name.casefold(), (None, None))[1]
        settings[label] = "未知" if raw is None else modes.get(raw, str(raw))
    return settings


def defender_exclusions(inv):
    """Report visible positives and protect the prior baseline when lists become opaque."""
    categories, entries = [], []
    limited = inv.errors.get("exclusionvisibility") or inv.errors.get("")
    hidden = inv.rows.get(r"preference\hideexclusionsfromlocaladmins", (None, None))[1]
    if hidden in (True, 1, "1"):
        limited = "提供程序报告本机管理员的排除列表已隐藏"
    for field, label in (("ExclusionPath", "路径"), ("ExclusionExtension", "扩展名"),
                         ("ExclusionProcess", "进程"), ("ExclusionIpAddress", "IP 地址")):
        key = ("preference\\" + field).casefold()
        raw = inv.rows.get(key, (None, None))[1]
        values = [raw] if isinstance(raw, str) else raw if isinstance(raw, list) else []
        visible = []
        partial = False
        for item in values:
            if not isinstance(item, str) or not item.strip() or re.match(r"^N/A(?:\s*:|$)", item.strip(), re.I):
                partial = True
            else:
                visible.append(item)
        reason = limited or inv.errors.get(key)
        if reason:
            visible = []
        if not reason and (not visible or partial):
            reason = "提供程序未返回完整可辨识的条目，无法区分空列表和可见性限制"
        if reason:
            inv.fail(key, reason)
            inv.rows.pop(key, None)
        categories.append({"type": label, "visible": len(visible), "visibility": reason or "本轮返回可见条目"})
        for item in visible:
            value = item.strip().replace("/", "\\").casefold()
            review, why = False, "Defender 本轮返回的排除声明"
            if field == "ExclusionPath" and re.fullmatch(r"(?:[a-z]:|%systemdrive%)(?:\\(?:\*|\*\.\*)?)?", value):
                review, why = True, "驱动器或根路径排除声明，覆盖范围很大"
            elif field == "ExclusionExtension" and value.removeprefix(".") in {"exe", "dll", "msi", "ps1", "bat", "cmd", "js", "vbs", "scr"}:
                review, why = True, "可执行文件或脚本类型的排除声明"
            elif field == "ExclusionProcess" and ntpath.basename(value) in {"powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "cscript.exe", "wscript.exe"}:
                review, why = True, "通用命令或脚本宿主排除，可影响其打开文件的实时检查"
            entries.append({"type": label, "value": item, "review": review, "reason": why})
    return {"categories": categories, "entries": entries}
