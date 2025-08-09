#!/usr/bin/env python3

import os
import sys
import hashlib
import magic  # pip install python-magic (file type)
import pefile  # pip install pefile (Windows PE only)
import yara  # pip install yara-python
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import subprocess
import re

console = Console()

# ------------------ CONFIG: YARA Rules (Basic Examples) ------------------
YARA_RULES = """
rule Suspicious_Packed {
    strings:
        $upx = "UPX" ascii
        $aspack = "ASPack" ascii
    condition:
        $upx at entrypoint or $aspack
}

rule Suspicious_API_Calls {
    strings:
        $create_remote_thread = "CreateRemoteThread" ascii
        $write_process_memory = "WriteProcessMemory" ascii
        $virtual_alloc_ex = "VirtualAllocEx" ascii
    condition:
        # of ($create_remote_thread, $write_process_memory, $virtual_alloc_ex) >= 2
}

rule Embedded_IP_or_URL {
    strings:
        $ip = /\b(?:\d{1,3}\.){3}\d{1,3}\b/ ascii
        $url = /https?:\/\/[^\s]+/ ascii
        $exec = /\.(exe|bat|vbs|ps1)/ ascii
    condition:
        $ip or $url or $exec
}
"""

# Compile YARA rules
try:
    compiled_rules = yara.compile(source=YARA_RULES)
except Exception as e:
    console.print(f"[yellow]YARA compile error (skipping): {e}[/yellow]")
    compiled_rules = None

# ------------------ FILE INFO EXTRACTOR ------------------
class MalwareFileScanner:
    def __init__(self, filepath):
        self.filepath = filepath
        self.info = {
            "path": filepath,
            "exists": False,
            "size": 0,
            "md5": "",
            "sha1": "",
            "sha256": "",
            "type": "Unknown",
            "magic": "",
            "created": "",
            "modified": "",
            "accessed": "",
            "is_pe": False,
            "arch": "",
            "entry_point": "",
            "imports": [],
            "sections": [],
            "entropy": 0.0,
            "suspicious_strings": [],
            "yara_matches": [],
            "warnings": [],
        }

    def scan(self):
        if not os.path.exists(self.filepath):
            self.info["warnings"].append("File not found")
            return False

        self.info["exists"] = True
        stat = os.stat(self.filepath)

        # Basic info
        self.info["size"] = stat.st_size
        self.info["created"] = datetime.fromtimestamp(stat.st_ctime).isoformat()
        self.info["modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
        self.info["accessed"] = datetime.fromtimestamp(stat.st_atime).isoformat()

        # File type via magic
        try:
            self.info["magic"] = magic.from_file(self.filepath)
            self.info["type"] = self.info["magic"].split(",")[0]
        except:
            self.info["magic"] = "Unable to detect"

        # Hashes
        self._hash_file()

        # Read raw bytes for entropy and strings
        with open(self.filepath, "rb") as f:
            data = f.read()

        self._calculate_entropy(data)
        self._extract_strings(data)

        # PE file analysis (Windows)
        if self.filepath.lower().endswith((".exe", ".dll", ".sys")) or "PE32" in self.info["magic"]:
            self._analyze_pe(data)

        # YARA scan
        if compiled_rules:
            self._scan_yara(data)

        # Final warnings
        self._generate_warnings()

        return True

    def _hash_file(self):
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(self.filepath, "rb") as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        self.info["md5"] = md5.hexdigest()
        self.info["sha1"] = sha1.hexdigest()
        self.info["sha256"] = sha256.hexdigest()

    def _calculate_entropy(self, data):
        if len(data) == 0:
            return 0.0
        from collections import Counter
        import math
        counts = Counter(data)
        entropy = 0
        for count in counts.values():
            prob = count / len(data)
            if prob > 0:
                entropy -= prob * math.log2(prob)
        self.info["entropy"] = round(entropy, 3)
        if entropy > 7.0:
            self.info["warnings"].append("High entropy (possibly packed/encrypted)")

    def _extract_strings(self, data):
        # Extract printable strings >= 6 chars
        strings = re.findall(b"[ -~]{6,}", data)
        decoded = [s.decode("utf-8", errors="ignore") for s in strings]
        suspicious = []
        for s in decoded:
            if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s):  # IP
                suspicious.append(f"IP: {s}")
            if "http://" in s or "https://" in s:
                suspicious.append(f"URL: {s}")
            if re.search(r"\.(exe|bat|vbs|ps1|dll)$", s, re.I):
                suspicious.append(f"Executable: {s}")
            if "api." in s or "malware" in s:
                suspicious.append(f"Suspicious: {s}")
        self.info["suspicious_strings"] = suspicious[:20]  # top 20

    def _analyze_pe(self, data):
        try:
            pe = pefile.PE(data=data)
            self.info["is_pe"] = True
            self.info["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            self.info["arch"] = {
                0x14c: "x86",
                0x8664: "x64",
                0x200: "IA64"
            }.get(pe.FILE_HEADER.Machine, "Unknown")

            # Imports
            imports = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        func_name = imp.name.decode() if imp.name else "unknown"
                        imports.append(f"{entry.dll.decode()}!{func_name}")
            self.info["imports"] = imports[:50]

            # Sections
            sections = []
            for section in pe.sections:
                sec_info = {
                    "name": section.Name.strip(b'\x00').decode(),
                    "size": section.Misc_VirtualSize,
                    "entropy": section.get_entropy(),
                }
                sections.append(sec_info)
                if sec_info["entropy"] > 7.0:
                    self.info["warnings"].append(f"High entropy in section: {sec_info['name']}")
            self.info["sections"] = sections

        except Exception as e:
            self.info["warnings"].append(f"PE parse error: {e}")

    def _scan_yara(self, data):
        try:
            matches = compiled_rules.match(data=data)
            for m in matches:
                self.info["yara_matches"].append(m.rule)
                self.info["warnings"].append(f"YARA match: {m.rule}")
        except Exception as e:
            self.info["warnings"].append(f"YARA scan failed: {e}")

    def _generate_warnings(self):
        if self.info["entropy"] > 7.5:
            self.info["warnings"].append("Very high entropy — likely packed (UPX, etc.)")
        if len(self.info["imports"]) > 100:
            self.info["warnings"].append("Excessive imports — possible malware")
        if "N/A" in self.info["magic"]:
            self.info["warnings"].append("Invalid or corrupted file header")

# ------------------ REPORT GENERATOR ------------------
def print_report(scanner):
    info = scanner.info

    console.print(Panel(f"[bold green]File Analysis Report[/bold green]"))
    console.print(f"📄 File: [cyan]{info['path']}[/cyan]")
    console.print(f"📏 Size: {info['size']} bytes")
    console.print(f"📂 Type: {info['type']}")
    console.print(f"🔧 Magic: {info['magic']}")
    console.print(f"📅 Created: {info['created']}")
    console.print(f"🔄 Modified: {info['modified']}")

    # Hashes
    table = Table("Algorithm", "Hash", title="🔐 Cryptographic Hashes")
    table.add_row("MD5", info["md5"])
    table.add_row("SHA1", info["sha1"])
    table.add_row("SHA256", info["sha256"])
    console.print(table)

    # PE Info
    if info["is_pe"]:
        pe_table = Table("Property", "Value", title="💻 PE Header Info")
        pe_table.add_row("Architecture", info["arch"])
        pe_table.add_row("Entry Point", info["entry_point"])
        pe_table.add_row("Total Imports", str(len(info["imports"])))
        console.print(pe_table)

        # Sections
        sec_table = Table("Section", "Size", "Entropy", title="🗂️ Sections")
        for sec in info["sections"]:
            entropy_style = "red" if sec["entropy"] > 7 else "yellow" if sec["entropy"] > 6 else "green"
            sec_table.add_row(
                sec["name"],
                str(sec["size"]),
                Text(str(round(sec["entropy"], 3)), style=entropy_style)
            )
        console.print(sec_table)

    # Strings
    if info["suspicious_strings"]:
        str_table = Table("Suspicious Strings", title="🔍 Suspicious Content")
        for s in info["suspicious_strings"]:
            str_table.add_row(s)
        console.print(str_table)

    # YARA
    if info["yara_matches"]:
        yara_table = Table("YARA Match", title="🧩 YARA Detection")
        for m in info["yara_matches"]:
            yara_table.add_row(m)
        console.print(yara_table)

    # Warnings
    if info["warnings"]:
        warn_panel = Panel(
            "\n".join([f"⚠️ {w}" for w in info["warnings"]]),
            title="🚨 Warnings",
            style="bold red"
        )
        console.print(warn_panel)
    else:
        console.print("[green]✅ No red flags detected.[/green]")

# ------------------ MAIN ------------------
def main():
    if len(sys.argv) != 2:
        console.print("[bold red]Usage: python file_detector.py <file_path>[/bold red]")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.isfile(filepath):
        console.print(f"[red]File not found: {filepath}[/red]")
        sys.exit(1)

    scanner = MalwareFileScanner(filepath)
    console.print(f"[bold blue]🔍 Scanning: {filepath}[/bold blue]")
    if scanner.scan():
        print_report(scanner)
    else:
        console.print("[red]Scan failed.[/red]")

if __name__ == "__main__":
    main()