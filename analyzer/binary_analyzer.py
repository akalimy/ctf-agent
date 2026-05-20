"""
Collects raw data from a binary file.
Uses system tools (file/checksec/nm/objdump/readelf) with pure-Python fallbacks.
Works on Linux (full), Windows (Python fallback), macOS.
"""
import subprocess, os, platform, struct


class BinaryAnalyzer:
    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self._data = None

    # ── helpers ───────────────────────────────────────────────────────────

    def _read(self) -> bytes:
        if self._data is None:
            with open(self.binary_path, "rb") as f:
                self._data = f.read()
        return self._data

    def _run(self, cmd: list) -> str:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=15, errors="replace")
            return (r.stdout + r.stderr).strip()
        except FileNotFoundError:
            return f"__NOTFOUND__{cmd[0]}"
        except subprocess.TimeoutExpired:
            return "[timeout]"
        except Exception as e:
            return f"[error: {e}]"

    def _missing(self, s: str) -> bool:
        return s.startswith("__NOTFOUND__")

    # ── file info ─────────────────────────────────────────────────────────

    def get_file_info(self) -> str:
        data = self._read()
        size  = len(data)
        magic = data[:4]

        lines = [
            f"Path   : {self.binary_path}",
            f"Size   : {size} bytes  ({size/1024:.1f} KB)",
            f"Magic  : {magic.hex().upper()}",
        ]

        # PE (Windows)
        if magic[:2] == b"MZ":
            lines.append("Format : Windows PE Executable")
            try:
                off = struct.unpack_from("<I", data, 0x3c)[0]
                machine = struct.unpack_from("<H", data, off + 4)[0]
                arch = {0x8664: "x86-64", 0x014c: "x86 (32-bit)",
                        0xaa64: "ARM64"}.get(machine, hex(machine))
                lines.append(f"Arch   : {arch}")
            except Exception:
                pass
        # ELF (Linux)
        elif magic == b"\x7fELF":
            ei_class  = data[4]
            ei_data   = data[5]
            e_machine = struct.unpack_from(
                "<H" if ei_data == 1 else ">H", data, 18)[0]
            arch_map = {0x03:"x86", 0x3e:"x86-64", 0x28:"ARM",
                        0xb7:"AArch64", 0x08:"MIPS", 0x15:"PowerPC"}
            lines += [
                "Format : ELF Binary",
                f"Class  : {'64-bit' if ei_class == 2 else '32-bit'}",
                f"Arch   : {arch_map.get(e_machine, hex(e_machine))}",
                f"Endian : {'Little-endian' if ei_data == 1 else 'Big-endian'}",
            ]
        # Mach-O (macOS)
        elif data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
            lines.append("Format : Mach-O Executable (macOS)")
        else:
            lines.append("Format : Unknown / Script / Data file")

        # Try system 'file' command
        out = self._run(["file", self.binary_path])
        if not self._missing(out):
            lines.append(f"\nfile   : {out}")

        return "\n".join(lines)

    # ── strings ───────────────────────────────────────────────────────────

    def get_strings(self, min_len: int = 6) -> str:
        data = self._read()
        strings, buf = [], ""
        for byte in data:
            if 0x20 <= byte <= 0x7e:
                buf += chr(byte)
            else:
                if len(buf) >= min_len:
                    strings.append(buf)
                buf = ""
        if len(buf) >= min_len:
            strings.append(buf)

        CTF_KEYWORDS = [
            "flag", "ctf", "win", "lose", "password", "passwd", "secret",
            "key", "token", "input", "correct", "wrong", "congratul",
            "hack", "pwn", "/bin/sh", "/bin/bash", "system", "execve",
            "printf", "scanf", "gets", "strcpy", "strcat", "read",
            "fgets", "sprintf", "admin", "root", "sudo",
        ]
        interesting = [s for s in strings
                       if any(kw in s.lower() for kw in CTF_KEYWORDS)]

        out  = f"Total strings found : {len(strings)}\n"
        out += f"Interesting hits    : {len(interesting)}\n\n"
        if interesting:
            out += "=== Interesting strings ===\n"
            out += "\n".join(f"  {s}" for s in interesting[:50])
            out += "\n\n"
        out += "=== First 30 strings ===\n"
        out += "\n".join(f"  {s}" for s in strings[:30])
        return out

    # ── checksec ──────────────────────────────────────────────────────────

    def get_checksec(self) -> str:
        # Try checksec tool
        out = self._run(["checksec", "--file=" + self.binary_path])
        if not self._missing(out) and out:
            return out

        # Try pwntools
        cmd = (
            f"from pwn import *; e=ELF('{self.binary_path}',checksec=False); "
            f"print('NX:',e.nx); print('PIE:',e.pie); "
            f"print('Canary:',e.canary); print('RELRO:',e.relro)"
        )
        out = self._run(["python3", "-c", cmd])
        if not self._missing(out) and "Error" not in out and out:
            return out

        # Pure Python ELF parse (fallback)
        data = self._read()
        if data[:4] != b"\x7fELF":
            return "Non-ELF file — checksec not applicable"

        ei_class = data[4]
        result = "=== Security Protections (manual ELF parse) ===\n"

        canary = b"__stack_chk_fail" in data
        fortify = b"__printf_chk" in data or b"__memcpy_chk" in data
        result += f"Stack Canary   : {'ENABLED  ✓' if canary  else 'DISABLED ✗'}\n"
        result += f"FORTIFY_SOURCE : {'ENABLED  ✓' if fortify else 'DISABLED ✗'}\n"

        e_type = struct.unpack_from("<H", data, 16)[0]
        pie = (e_type == 3)
        result += f"PIE            : {'ENABLED  ✓' if pie     else 'DISABLED ✗'}\n"

        # NX: read PT_GNU_STACK flags
        if ei_class == 2:
            phoff     = struct.unpack_from("<Q", data, 32)[0]
            phentsize = struct.unpack_from("<H", data, 54)[0]
            phnum     = struct.unpack_from("<H", data, 56)[0]
        else:
            phoff     = struct.unpack_from("<I", data, 28)[0]
            phentsize = struct.unpack_from("<H", data, 42)[0]
            phnum     = struct.unpack_from("<H", data, 44)[0]

        nx = True
        for i in range(min(phnum, 40)):
            base = phoff + i * phentsize
            p_type = struct.unpack_from("<I", data, base)[0]
            if p_type == 0x6474e551:  # PT_GNU_STACK
                flag_off = base + (4 if ei_class == 2 else 24)
                p_flags = struct.unpack_from("<I", data, flag_off)[0]
                nx = not bool(p_flags & 0x1)  # executable bit
                break
        result += f"NX / DEP       : {'ENABLED  ✓' if nx      else 'DISABLED ✗'}\n"
        result += "\nTip: `pip install pwntools` for full RELRO/RPATH detection"
        return result

    # ── functions ─────────────────────────────────────────────────────────

    def get_functions(self) -> str:
        parts = []
        checks = [
            (["nm", "-D", self.binary_path],
             "Dynamic symbols (nm -D)"),
            (["readelf", "-s", self.binary_path],
             "Symbol table (readelf -s)"),
            (["objdump", "-d", "--no-show-raw-insn",
              "--section=.text", self.binary_path],
             "Disassembly preview (objdump)"),
        ]
        for cmd, label in checks:
            out = self._run(cmd)
            if not self._missing(out) and out.strip():
                parts.append(f"=== {label} ===\n{out[:2000]}")

        if parts:
            return "\n\n".join(parts)

        # Fallback: scan for known libc imports
        data = self._read()
        known = [b"system", b"execve", b"gets", b"strcpy", b"strcat",
                 b"scanf",  b"printf", b"read",  b"fgets", b"malloc",
                 b"free",   b"puts",   b"open",  b"mmap",  b"mprotect"]
        found = [f.decode() for f in known if f in data]
        return (
            "Tools not found (nm / readelf / objdump)\n\n"
            "=== Detected libc imports (byte scan) ===\n"
            + (", ".join(found) if found else "None detected")
        )

    # ── aggregate ─────────────────────────────────────────────────────────

    def collect_all(self) -> dict:
        print("[*] 1/4  File info ...")
        fi = self.get_file_info()
        print("[*] 2/4  Strings ...")
        st = self.get_strings()
        print("[*] 3/4  Security protections ...")
        cs = self.get_checksec()
        print("[*] 4/4  Functions & symbols ...")
        fn = self.get_functions()
        return {"file_info": fi, "strings": st,
                "checksec": cs, "functions": fn}