"""Read Shell Link fields without asking the shell to resolve or launch the target."""
import ntpath
import os


def parse_link(data):
    ansi = "mbcs" if os.name == "nt" else "cp1252"

    def field(buf, pos, size):
        if pos < 0 or pos + size > len(buf):
            raise ValueError("truncated Shell Link")
        return buf[pos:pos + size]

    def integer(buf, pos, size=4):
        return int.from_bytes(field(buf, pos, size), "little")

    def string(buf, pos, wide=False):
        if not pos:
            return ""
        step = 2 if wide else 1
        end = pos
        while field(buf, end, step) != b"\0" * step:
            end += step
        return buf[pos:end].decode("utf-16le" if wide else ansi, "replace")

    if integer(data, 0) != 76 or field(data, 4, 16) != bytes.fromhex("0114020000000000c000000000000046"):
        raise ValueError("invalid Shell Link header")
    flags = integer(data, 20)
    pos = 76
    if flags & 1:
        length = integer(data, pos, 2)
        field(data, pos + 2, length)
        pos += 2 + length
    result = {"arguments": "", "workingDir": "", "target": ""}
    if flags & 2:
        size = integer(data, pos)
        info = field(data, pos, size)
        header = integer(info, 4)
        modes = integer(info, 8)
        if header < 28 or header > size:
            raise ValueError("invalid LinkInfo header")
        suffix_w = integer(info, 32) if header >= 36 else 0
        suffix = string(info, suffix_w, True) or string(info, integer(info, 24))
        base = ""
        if modes & 1:
            base_w = integer(info, 28) if header >= 36 else 0
            base = string(info, base_w, True) or string(info, integer(info, 16))
        elif modes & 2:
            start = integer(info, 20)
            net = field(info, start, integer(info, start))
            offset = integer(net, 8)
            base = (string(net, integer(net, 20), True) if offset > 20 else "") or string(net, offset)
        result["target"] = ntpath.join(base, suffix) if suffix else base
        pos += size
    wide = bool(flags & 128)
    for bit, name in ((4, "description"), (8, "relativePath"), (16, "workingDir"), (32, "arguments"), (64, "icon")):
        if flags & bit:
            length = integer(data, pos, 2) * (2 if wide else 1)
            result[name] = field(data, pos + 2, length).decode("utf-16le" if wide else ansi, "replace")
            pos += 2 + length
    while pos < len(data):
        size = integer(data, pos)
        if size == 0:
            break
        block = field(data, pos, size)
        if size < 8:
            raise ValueError("invalid Shell Link extra block")
        if integer(block, 4) == 0xA0000001:
            env_target = string(block, 268, True) or string(block, 8)
            result["environmentTarget"] = env_target
            if not result["target"] or flags & (1 << 25):
                result["target"] = env_target
        pos += size
    if not result["target"]:
        result["target"] = result.get("relativePath", "")
    if not result["target"]:
        result["targetNote"] = "Shell namespace / IDList 目标，未解析路径"
    return result
