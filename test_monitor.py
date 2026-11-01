import hashlib
import os
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from inventory import Inventory, file_tree, shortcut_findings
from monitor import compare_reference, database, reference, update_scope
from shortcuts import parse_link


def snapshot(values, gaps=()):
    inv = Inventory()
    for k, v in values.items():
        inv.add(k, v)
    for k in gaps:
        inv.fail(k, "denied")
    return inv


def link(target, args):
    header = bytearray(76)
    struct.pack_into("<I", header, 0, 76)
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    struct.pack_into("<I", header, 20, 8 | 32 | 128)
    def field(s):
        b = s.encode("utf-16le")
        return struct.pack("<H", len(b) // 2) + b
    return bytes(header) + field(target) + field(args) + bytes(4)


class DriftTest(unittest.TestCase):
    def setUp(self):
        self.db = database(":memory:")
        self.addCleanup(self.db.close)

    def test_partial_reads_preserve_state_and_edits(self):
        def update(vals, gaps=()):
            return update_scope(self.db, "settings", snapshot(vals, gaps))
        self.assertEqual([], update({"A\\key": {"v": 1}, "B": {}, "D": 5}))
        changes = update({"b": {"v": 0}, "C": 3}, ["a"])
        self.assertEqual({"新增", "修改", "删除"}, {c["kind"] for c in changes})
        self.assertEqual([], update({}, [""]))
        result = update({"a\\key": {"v": 2}, "B": {"v": 0}, "C": 3})
        self.assertEqual(["重新可读，存在差异"], [c["kind"] for c in result])
        self.assertEqual({"v": 1}, result[0]["before"])
        self.assertEqual([], update({"a\\key": {"v": 2}, "B": {"v": 0}, "C": 3}))

    def test_protected_service_parameter_does_not_hide_start_change(self):
        old = {"Start": 3, "Parameters\\Policy": {"secret": 7}}
        update_scope(self.db, "services", snapshot({"svc": old}))
        result = update_scope(self.db, "services", snapshot({"svc": {"Start": 2}}, ["svc\\Parameters\\Policy"]))
        self.assertEqual({"Start": 3}, result[0]["before"])
        self.assertEqual({"Start": 2}, result[0]["after"])

    def test_reparse_replacement_is_visible_and_children_are_unknown(self):
        update_scope(self.db, "files/Windows", snapshot({"a": {"sha256": "one"}, "a\\child": {"sha256": "two"}}))
        result = update_scope(self.db, "files/Windows", snapshot({"a": {"entry": "reparse"}}, ["a\\"]))
        self.assertEqual(["修改"], [c["kind"] for c in result])
        self.assertEqual({"entry": "reparse"}, result[0]["after"])

    def test_reference_exact_match_and_known_absence(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "Windows"
            root.mkdir()
            (root / "x.dll").write_bytes(b"original")
            (root / "missing.exe").write_bytes(b"original")
            (root / "denied.dll").write_bytes(b"something")
            path = Path(tmp) / "clean.sqlite"
            version = {"CurrentBuild": "100", "UBR": 2}
            with patch("monitor.services", return_value=snapshot({"Orig": {"Start": 2}})):
                reference(path, {"Windows": root}, version)
            (root / "x.dll").write_bytes(b"modified")
            (root / "missing.exe").unlink()
            (root / "denied.dll").unlink()
            files = file_tree(root)
            files.fail("denied.dll", "denied")
            state = {"files/Windows": files, "services": snapshot({"orig": {"Start": 3}, "NEW": {}})}
            r = compare_reference(path, version, state)
            self.assertEqual(["Orig"], r["initialServices"])
            self.assertEqual({"Orig", "NEW", "x.dll", "missing.exe"}, {c["key"] for c in r["differences"]})
            x = next(c for c in r["differences"] if c["key"] == "x.dll")
            self.assertEqual(hashlib.sha256(b"original").hexdigest(), x["before"]["sha256"])
            self.assertEqual([], compare_reference(path, dict(version, UBR=3), state)["differences"])
            self.assertIn("未提供", compare_reference(None, version, state)["status"])
            loaded = {"module-files": snapshot({str(root / "x.dll"): {"class": "Windows 签名", **files.rows["x.dll"][1]}})}
            with patch.dict(os.environ, {"SystemRoot": str(root)}):
                self.assertEqual("与清单哈希不同", compare_reference(path, version, loaded)["moduleChecks"][str(root / "x.dll")])

    def test_argument_is_observed_on_first_scan_and_after_change(self):
        path = r"C:\Desktop\browser.lnk"
        original = parse_link(link("msedge.exe", "--profile-directory=Default"))
        tampered = parse_link(link("msedge.exe", "https://ads.example/首页"))
        inv = snapshot({path: tampered})
        self.assertIn("网址", shortcut_findings(inv)[0]["reason"])
        update_scope(self.db, "shortcuts", snapshot({path: original}))
        diff = update_scope(self.db, "shortcuts", inv)
        self.assertEqual({"arguments": "https://ads.example/首页"}, diff[0]["after"])
        self.assertEqual("删除", update_scope(self.db, "shortcuts", Inventory())[0]["kind"])
        with self.assertRaises(ValueError):
            parse_link(link("msedge.exe", "a")[:-7])

    @unittest.skipUnless(os.name == "nt", "Windows inventory")
    def test_real_shortcut_directory(self):
        from inventory import shortcuts
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "无广告.lnk"
            path.write_bytes(link("chrome.exe", "--app=https://example.test/ad"))
            inv = shortcuts([tmp])
            self.assertIn(str(path), {f["path"] for f in shortcut_findings(inv)})
            self.assertEqual(inv.rows[str(path).casefold()][1]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    @unittest.skipUnless(os.name == "nt", "Windows process mappings")
    def test_private_executable_region_and_non_windows_module(self):
        import ctypes as C
        from ctypes import wintypes as W
        from processes import api, entries, identity, inspect_memory, module_class, process_handle
        from inventory import ps_inventory
        alloc = api("VirtualAlloc", W.LPVOID, W.LPVOID, C.c_size_t, W.DWORD, W.DWORD)
        free = api("VirtualFree", W.BOOL, W.LPVOID, C.c_size_t, W.DWORD)
        # Allocate an empty page in the test process. No payload or code execution.
        page = alloc(None, 4096, 0x3000, 0x20)
        self.assertTrue(page)
        try:
            pid = os.getpid()
            modules = dict(entries(pid))
            with process_handle(pid, 0x400) as proc:
                path, birth = identity(proc)
                self.assertTrue(birth)
                inv = Inventory()
                inspect_memory(proc, "fixture", modules, inv)
            self.assertEqual("私有可执行内存", inv.rows["fixture\\" + hex(page)][1]["kind"])
            self.assertIn(Path(path), [Path(p) for p in modules.values()])
            sig = ps_inventory("signatures", input_data=[path]).rows[path.casefold()][1]
            self.assertNotEqual("Windows 签名", module_class(path, sig))
            self.assertEqual(64, len(sig["sha256"]))
        finally:
            self.assertTrue(free(page, 0, 0x8000))


if __name__ == "__main__":
    unittest.main()
