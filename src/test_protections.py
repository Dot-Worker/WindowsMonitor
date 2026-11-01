import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from browser_inventory import browser_inventory, browser_policies
from inventory import Inventory, TASK_CACHE_TREE
from monitor import database, update_scope
from protections import browser_changes, defense_events, defense_state, DEFENDER, recovery_tasks, shadow_changes, task_cache_audit


class ProtectionTests(unittest.TestCase):
    def test_missing_task_descriptor_needs_independent_evidence(self):
        reg, api = Inventory(), Inventory()
        reg.add(TASK_CACHE_TREE, {})
        reg.add(TASK_CACHE_TREE + r"\Vendor", {})  # A folder without SD is not a task.
        path = TASK_CACHE_TREE + r"\Vendor\Maintenance"
        reg.add(path, {"Id": [1, "fixture"], "sD": [3, {}]})
        reg.add(TASK_CACHE_TREE + r"Backup\Other", {"Id": [1, "unrelated"]})
        self.assertEqual([], task_cache_audit(reg, api, [])["findings"])
        db = database(":memory:")
        self.addCleanup(db.close)
        update_scope(db, "settings/HKLM", reg)
        reg.add(path, {"iD": [1, "fixture"]})
        changes = update_scope(db, "settings/HKLM", reg)
        result = task_cache_audit(reg, api, changes)
        self.assertTrue(result["rootObserved"])
        self.assertEqual(1, result["checked"])
        self.assertTrue(result["findings"][0]["highPriority"])
        self.assertFalse(task_cache_audit(reg, api, [])["findings"][0]["highPriority"])
        api.fail(r"\Vendor", "denied")
        f = task_cache_audit(reg, api, changes)["findings"][0]
        self.assertIn("缺口", f["apiVisibility"])
        self.assertFalse(f["highPriority"])
        api.add(r"\VENDOR\maintenance", {"enabled": True})
        self.assertEqual("本轮 API 已列出", task_cache_audit(reg, api, changes)["findings"][0]["apiVisibility"])
        reg.fail(path, "denied")
        self.assertEqual([], task_cache_audit(reg, api, changes)["findings"])

    def test_force_policy_inventory_and_changes(self):
        db = database(":memory:")
        self.addCleanup(db.close)
        extension_id = "a" * 32
        key = r"Software\WOW6432Node\Policies\Microsoft\Edge\ExtensionInstallForcelist"
        inv = Inventory()
        inv.add(key, {"1": [1, extension_id + ";https://user:secret@updates.example/feed?token=private"]})
        current = browser_policies({"policy/HKLM": inv})
        item = next(iter(current.rows.values()))[1]
        self.assertEqual(("Edge", extension_id, "updates.example"), (item["browser"], item["id"], item["update"]["host"]))
        self.assertNotIn("secret", json.dumps(item))
        self.assertNotIn("private", json.dumps(item))
        self.assertEqual([], update_scope(db, "browser-policy", current))
        denied = Inventory()
        denied.fail(r"software\wow6432node\policies", "denied")
        self.assertEqual([], update_scope(db, "browser-policy", browser_policies({"policy/HKLM": denied})))
        result = browser_changes(update_scope(db, "browser-policy", Inventory()))
        self.assertEqual("删除", result[0]["kind"])
        self.assertEqual(extension_id, result[0]["before"]["id"])

    def test_grouped_settings_and_invalid_json_preserve_evidence(self):
        key = r"Software\Policies\Google\Chrome"
        eid = "b"*32
        registry = Inventory()
        scope = {"policy/S-1-test": registry}
        def settings(value):
            registry.add(key, {"ExtensionSettings": [1, value]})
            return browser_policies(scope)
        current = settings(json.dumps({eid + "," + "c"*32: {"installation_mode": "force_installed",
                                   "update_url": "file:///local/update.xml"}, "*": {"installation_mode": "blocked"}}))
        self.assertEqual(2, len(current.rows))
        db = database(":memory:")
        self.addCleanup(db.close)
        update_scope(db, "browser-policy", current)
        broken = settings("{")
        self.assertTrue(broken.errors)
        self.assertEqual([], update_scope(db, "browser-policy", broken))
        allowed = settings(json.dumps({eid: {"installation_mode":"allowed"}}))
        self.assertFalse(allowed.rows)
        self.assertEqual(2, len(update_scope(db, "browser-policy", allowed)))
        registry.add(key + r"\Recommended\ExtensionInstallForcelist", {"1": [1, eid]})
        self.assertFalse(browser_policies(scope).rows)

    def test_entrypoints_survive_package_limit_and_one_unreadable_script(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "Default" / "Extensions" / ("b" * 32) / "1.0_0"
            folder.mkdir(parents=True)
            (folder / "manifest.json").write_text(json.dumps({"version": "1.0",
                "background": {"service_worker": "/worker.js"},
                "content_scripts": [{"js": ["large.js", "missing.js", "../escape.js"]}]}))
            with (folder / "assets.bin").open("wb") as f:
                f.truncate((128 << 20) + 1)
            with (folder / "large.js").open("wb") as f:
                f.truncate((8 << 20) + 1)
            worker = folder / "worker.js"
            worker.write_text("original")
            db = database(":memory:")
            self.addCleanup(db.close)
            def scan():
                inv = browser_inventory({"Edge": root})
                entries = inv["browser-entrypoints"]
                self.assertEqual(1, len(inv["browser-extensions"].errors))
                self.assertEqual(2, len(entries.errors))
                missing = next(v for k, (_, v) in entries.rows.items() if k.endswith("missing.js"))
                self.assertFalse(missing["present"])
                return browser_changes(update_scope(db, "browser-entrypoints", entries))
            self.assertEqual([], scan())
            worker.write_text("changed")
            findings = scan()
            self.assertEqual(1, len(findings))
            self.assertTrue(findings[0]["key"].endswith("scripts\\worker.js"))
            self.assertNotEqual(findings[0]["before"]["sha256"], findings[0]["after"]["sha256"])
            self.assertEqual([], scan())

    def test_manifest_paths_cannot_direct_reads_outside_extension(self):
        import browser_inventory as browser
        with TemporaryDirectory() as tmp:
            folder = Path(tmp) / "Default" / "Extensions" / ("a" * 32) / "1.0"
            folder.mkdir(parents=True)
            names = ["../escape", "//host/share", "C:/secret", "file:ads", "NUL", r"..\escape"]
            (folder / "manifest.json").write_text(json.dumps({"version": "1", "background": {"scripts": names}}))
            with patch.object(browser, "file_bytes", wraps=browser.file_bytes) as read:
                data = browser_inventory({"Chrome": Path(tmp)})["browser-entrypoints"]
            self.assertEqual(len(names), len(data.errors))
            self.assertFalse(any(c.args[0].name not in ("manifest.json", "Preferences", "Secure Preferences") for c in read.call_args_list))

    def test_changed_script_under_same_version_and_unreadable_manifest(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "Default" / "Extensions" / ("b" * 32) / "1.0_0"
            directory.mkdir(parents=True)
            manifest = directory / "manifest.json"
            manifest.write_text('{"version":"1.0","permissions":["storage"]}')
            script = directory / "content.js"
            script.write_text("original")
            db = database(":memory:")
            self.addCleanup(db.close)

            def scan():
                inv = browser_inventory({"Chrome": root})["browser-extensions"]
                return inv, browser_changes(update_scope(db, "browser-extensions", inv))

            self.assertEqual(scan()[1], [])
            script.write_text("changed")
            evidence = scan()[1]
            self.assertEqual("扩展版本未变，文件内容有变化", evidence[0]["title"])
            self.assertEqual(["content.js"], evidence[0]["files"])
            manifest.write_text("{")
            inv, findings = scan()
            self.assertTrue(inv.errors)
            self.assertEqual([], findings)
            manifest.write_text('{"version":"1.1","permissions":["tabs"]}')
            evidence = scan()[1]
            self.assertEqual("扩展安装目录或清单变化", evidence[0]["title"])

    def test_keeps_only_selected_preferences_and_redacts_url(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "Profile 2"
            profile.mkdir()
            (profile / "Preferences").write_text(json.dumps({"homepage": "https://user:secret@example.test/a?token=SECRET",
                                                           "unrelated": "personal-data"}))
            row = browser_inventory({"Edge": root})["browser-preferences"].rows
            prefs = next(iter(row.values()))[1]
            self.assertEqual("example.test", prefs["homepage"]["host"])
            self.assertNotIn("secret", json.dumps(prefs).lower())
            self.assertNotIn("personal-data", json.dumps(prefs))

    def test_audit_block_tamper_and_provider_disambiguation(self):
        xml = '<Event xmlns="urn:fixture"><EventData><Data Name="Process Name">example.exe</Data></EventData></Event>'
        base = {"record": 50, "provider": "Microsoft-Windows-Windows Defender", "time": "now", "xml": xml}
        events = [dict(base, id=i) for i in (1123, 1124, 5013, 1117)] + [dict(base, id=1123, provider="unrelated")]
        findings = defense_events({DEFENDER: {"events": events}})
        self.assertEqual(4, len(findings))
        self.assertIn("已阻止", findings[0]["title"])
        self.assertIn("仅审计", findings[1]["title"])
        self.assertEqual("example.exe", findings[0]["fields"]["Process Name"])
        self.assertIn("处置动作", findings[-1]["title"])
        self.assertEqual("未知", defense_state(Inventory())["潜在不受欢迎应用防护"])

    def test_recovery_task_distinguishes_inspection_from_deletion(self):
        inv = Inventory()
        for k, command, args in (("inspect", "vssadmin", "list shadows"), ("delete", "vssadmin.exe", "delete shadows /all"),
                                 ("text", "notepad", "vssadmin.exe delete shadows"), ("bcd", "bcdedit.exe", "/enum")):
            xml = f'<Task xmlns="urn:task"><Actions><Exec><Command>{command}</Command><Arguments>{args}</Arguments></Exec></Actions></Task>'
            inv.add(k, {"xml": xml, "enabled": False})
        findings = recovery_tasks(inv)
        self.assertEqual(["delete"], [f["task"] for f in findings])
        self.assertFalse(findings[0]["enabled"])

    def test_resize_task_is_configuration_not_deletion(self):
        inv = Inventory()
        for name, args in (("adjust", "ReSize  shadowStorage /maxsize=401MB"), ("inspect", "list shadowstorage"),
                           ("invalid", "resize shadowstoragex"), ("free-text", "help resize shadowstorage")):
            xml = f"<Task><Actions><Exec><Command>vssadmin.exe</Command><Arguments>{args}</Arguments></Exec></Actions></Task>"
            inv.add(name, {"xml": xml, "enabled": True})
        findings = recovery_tasks(inv)
        self.assertEqual(["adjust"], [f["task"] for f in findings])
        self.assertIn("实际影响需对比", findings[0]["reason"])

    def test_shadow_loss_requires_observation_and_tracks_quota_direction(self):
        db = database(":memory:")
        self.addCleanup(db.close)
        assoc = "storage\\source\\dest"
        def observe(maximum, copy_ids=(), gaps=()):
            inv = Inventory()
            inv.add(assoc, {"maxBytes": str(maximum)})
            for key in copy_ids:
                inv.add("copies\\" + key, {"volume": "source"})
            for prefix in gaps:
                inv.fail(prefix, "denied")
            return shadow_changes(update_scope(db, "shadows", inv))
        self.assertEqual([], observe(8000, ("first",)))
        self.assertEqual([], observe(8000, gaps=("copies",)))
        events = observe(4000)
        self.assertEqual({"卷影存储额度数值下降", "卷影副本不再可见"}, {e["title"] for e in events})
        self.assertTrue(all(e["review"] for e in events))
        self.assertEqual("8000", next(e for e in events if e["key"] == assoc)["before"]["maxBytes"])
        events = observe(9000, ("new",))
        self.assertFalse(any(e["review"] for e in events))
