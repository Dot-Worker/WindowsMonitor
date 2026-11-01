import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from browser_inventory import browser_inventory
from inventory import Inventory
from monitor import database, update_scope
from protections import browser_changes, defense_events, defense_state, DEFENDER, recovery_tasks, shadow_changes


class ProtectionTests(unittest.TestCase):
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
