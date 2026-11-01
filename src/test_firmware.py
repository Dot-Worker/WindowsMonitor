import os
import struct
import unittest
from unittest.mock import MagicMock, patch

from inventory import Inventory
from monitor import database, update_scope


@unittest.skipUnless(os.name == "nt", "Windows firmware observer")
class FirmwareEvidenceTests(unittest.TestCase):
    def option(self):
        name = "Windows 示例".encode("utf-16le") + bytes(2)
        path = r"\EFI\Vendor\boot.efi".encode("utf-16le") + bytes(2)
        nodes = struct.pack("<BBH", 4, 4, len(path)+4) + path + bytes.fromhex("7fff0400")
        return struct.pack("<IH", 1, len(nodes)) + name + nodes + b"opaque-test-data"

    def observe(self, data, previous=(), specs=()):
        from firmware import observe_variables
        raw, details, read = Inventory(), Inventory(), []
        def reader(key, guid):
            read.append((key,guid))
            value = data.get(key)
            if isinstance(value, OSError):
                raise value
            return None if value is None else (value, 7)
        observe_variables(raw, details, specs, previous, reader)
        return raw, details, read

    def test_recheck_unreferenced_boot_variable_before_declaring_loss(self):
        db = database(":memory:")
        self.addCleanup(db.close)
        state = {"BootOrder": bytes([7,0]), "Boot0007": self.option()}
        raw, details, _ = self.observe(state)
        update_scope(db, "uefi", raw)
        entry = details.rows["boot0007"][1]
        self.assertEqual([r"\EFI\Vendor\boot.efi"], entry["filePaths"])
        self.assertEqual("Windows 示例", entry["description"])
        self.assertNotIn("opaque-test-data", str(entry))
        state.update(BootOrder=bytes([9,0]), Boot0009=self.option())
        raw, _, calls = self.observe(state, previous=["Boot0007"])
        self.assertIn("Boot0007", [k for k, _ in calls])
        changed = update_scope(db, "uefi", raw)
        self.assertFalse(any(c["key"]=="Boot0007" for c in changed))
        state["Boot0007"] = OSError("permission denied")
        raw, _, _ = self.observe(state, previous=["Boot0007"])
        self.assertEqual([],update_scope(db,"uefi",raw))
        del state["Boot0007"]
        raw, _, _ = self.observe(state, previous=["Boot0007"])
        self.assertEqual([("Boot0007","删除")],[(c["key"],c["kind"]) for c in update_scope(db,"uefi",raw)])

    def test_mirror_absence_and_malformed_option_are_distinct_from_denial(self):
        from firmware import SHIM_GUID
        key = ("MokListRT="+SHIM_GUID.strip("{}")).casefold()
        raw, details, _ = self.observe({"BootOrder":bytes([3,0]), "Boot0003":b"short"})
        self.assertIn("sha256",raw.rows["boot0003"][1])
        self.assertIn("boot0003",details.errors)
        self.assertIn("未找到",details.rows[key][1]["status"])
        _, denied, _ = self.observe({"MokListRT":OSError("denied")})
        self.assertNotIn(key,denied.rows)
        self.assertIn(key,denied.errors)
        raw, seen, _ = self.observe({"MokListRT":b"test"})
        self.assertNotIn(key,raw.rows)
        self.assertEqual(4,seen.rows[key][1]["length"])
        custom = "Unselected="+SHIM_GUID.strip("{}")
        raw, _, calls = self.observe({}, previous=[custom])
        self.assertIn(custom.casefold(),raw.errors)
        self.assertNotIn("Unselected",[n for n,_ in calls])

    def test_win32_reader_passes_prior_labels_and_restores_token(self):
        import ctypes
        import firmware
        kernel, adv, queried = MagicMock(), MagicMock(), []
        def open_token(process, access, handle):
            handle._obj.value = 1
            return True
        def adjust(token, all_disabled, requested, size, old, returned):
            if old is not None:
                old._obj.count = 1
            return True
        def read(name, guid, buf, size, attrs):
            queried.append(name)
            ctypes.set_last_error(203)  # ERROR_ENVVAR_NOT_FOUND
            return 0
        adv.OpenProcessToken.side_effect = open_token
        adv.AdjustTokenPrivileges.side_effect = adjust
        kernel.GetFirmwareEnvironmentVariableExW.side_effect = read
        raw, detail = Inventory(), Inventory()
        with patch.object(firmware, "WinDLL", side_effect=[kernel, adv]):
            firmware.read_variables(raw, [], ["Boot0007"], detail)
        self.assertIn("Boot0007", queried)
        self.assertFalse(raw.errors)
        self.assertEqual(2, adv.AdjustTokenPrivileges.call_count)
        kernel.CloseHandle.assert_called_once()
