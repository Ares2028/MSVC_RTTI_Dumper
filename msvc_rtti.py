#!/usr/bin/env python3
"""
msvc-rtti: Recover class names and inheritance metadata from 64-bit MSVC PE DLLs.

Requirements:
    Python 3.10+
    pip install pefile

Examples:
    python msvc_rtti.py input.dll
    python msvc_rtti.py input.dll -o out --format all
    python msvc_rtti.py input.dll --format json
    python msvc_rtti.py input.dll --format dot

This is a static parser. It does not load or execute the target DLL.
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    import pefile
except ImportError:
    print("Missing dependency: pefile\nInstall it with: python -m pip install pefile", file=sys.stderr)
    raise SystemExit(2)


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def i32(data: bytes, off: int) -> int:
    return struct.unpack_from("<i", data, off)[0]


class PEImage:
    def __init__(self, path: str):
        self.path = path
        self.pe = pefile.PE(path, fast_load=False)
        self.data = Path(path).read_bytes()
        self.image_base = int(self.pe.OPTIONAL_HEADER.ImageBase)
        self.is_64 = self.pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
        if not self.is_64:
            raise ValueError("This first version supports PE32+ (64-bit) files only.")
        self.sections = []
        for sec in self.pe.sections:
            start = int(sec.VirtualAddress)
            raw_size = int(sec.SizeOfRawData)
            raw_ptr = int(sec.PointerToRawData)
            virtual_size = int(sec.Misc_VirtualSize)
            self.sections.append({
                "name": sec.Name.rstrip(b"\0").decode("ascii", "replace"),
                "rva": start,
                "raw_size": raw_size,
                "raw_ptr": raw_ptr,
                "virtual_size": virtual_size,
                "scan_size": min(raw_size, max(raw_size, virtual_size)),
            })

    def rva_to_offset(self, rva: int) -> int | None:
        if rva < 0:
            return None
        # Headers may contain relevant data too.
        headers_size = int(self.pe.OPTIONAL_HEADER.SizeOfHeaders)
        if rva < headers_size and rva < len(self.data):
            return rva
        for s in self.sections:
            delta = rva - s["rva"]
            if 0 <= delta < s["raw_size"]:
                off = s["raw_ptr"] + delta
                if off < len(self.data):
                    return off
        return None

    def read(self, rva: int, size: int) -> bytes | None:
        off = self.rva_to_offset(rva)
        if off is None or size < 0 or off + size > len(self.data):
            return None
        return self.data[off:off + size]

    def read_u32(self, rva: int) -> int | None:
        b = self.read(rva, 4)
        return u32(b, 0) if b is not None else None

    def c_string(self, rva: int, limit: int = 4096) -> str | None:
        off = self.rva_to_offset(rva)
        if off is None:
            return None
        end = self.data.find(b"\0", off, min(len(self.data), off + limit))
        if end < 0:
            return None
        return self.data[off:end].decode("ascii", "replace")

    def in_image_rva(self, rva: int) -> bool:
        return self.rva_to_offset(rva) is not None

    def section_ranges(self):
        for s in self.sections:
            # Only scan bytes that physically exist in the file.
            n = min(s["raw_size"], len(self.data) - s["raw_ptr"])
            if n > 0:
                yield s["name"], s["rva"], s["raw_ptr"], n


class RTTIParser:
    # MSVC RTTI attribute flags (from the compiler ABI).
    BCD_NOTVISIBLE = 0x01
    BCD_AMBIGUOUS = 0x02
    BCD_PRIVORPROTBASE = 0x04
    BCD_PRIVORPROTINCOMPOBJ = 0x08
    BCD_VBOFCONTOBJ = 0x10
    BCD_NONPOLYMORPHIC = 0x20
    BCD_HASPCHD = 0x40

    def __init__(self, image: PEImage):
        self.pe = image
        self.type_names: dict[int, str] = {}
        self.chds: dict[int, dict[str, Any]] = {}
        self.bcds: dict[int, dict[str, Any]] = {}
        self.cols: dict[int, dict[str, Any]] = {}
        self.vftables: list[dict[str, Any]] = []
        self.warnings: list[str] = []

    def type_name(self, td_rva: int) -> str | None:
        if td_rva in self.type_names:
            return self.type_names[td_rva]
        # x64 TypeDescriptor: pVFTable (8), spare (8), decorated name at +0x10.
        if not self.pe.in_image_rva(td_rva):
            return None
        name = self.pe.c_string(td_rva + 0x10)
        if not name or not (name.startswith(".?A") or name.startswith("?")):
            return None
        self.type_names[td_rva] = name
        return name

    @staticmethod
    def pretty_type(decorated: str | None) -> str | None:
        if not decorated:
            return None
        # Keep decorated names as a source of truth; demangling is deliberately
        # not guessed here. Common class/struct names can be presented simply.
        if decorated.startswith(".?AV") and decorated.endswith("@@"):
            return decorated[4:-2].replace("@", "::")
        if decorated.startswith(".?AU") and decorated.endswith("@@"):
            return decorated[4:-2].replace("@", "::")
        return decorated

    def parse_col_at(self, rva: int) -> dict[str, Any] | None:
        b = self.pe.read(rva, 24)
        if b is None:
            return None
        sig, offset, cd_offset, td_rva, chd_rva, self_rva = struct.unpack("<6I", b)
        # For x64, signature is 1 and pSelf is the COL's own RVA.
        if sig != 1 or self_rva != rva:
            return None
        if not self.pe.in_image_rva(td_rva) or not self.pe.in_image_rva(chd_rva):
            return None
        decorated = self.type_name(td_rva)
        if not decorated:
            return None
        chd = self.parse_chd(chd_rva)
        if chd is None:
            return None
        return {
            "rva": rva,
            "va": self.pe.image_base + rva,
            "signature": sig,
            "offset": offset,
            "cd_offset": cd_offset,
            "type_descriptor_rva": td_rva,
            "decorated_name": decorated,
            "name": self.pretty_type(decorated),
            "class_hierarchy_descriptor_rva": chd_rva,
        }

    def parse_chd(self, rva: int) -> dict[str, Any] | None:
        if rva in self.chds:
            return self.chds[rva]
        b = self.pe.read(rva, 16)
        if b is None:
            return None
        signature, attributes, count, array_rva = struct.unpack("<4I", b)
        if signature not in (0, 1) or count == 0 or count > 10000:
            return None
        if not self.pe.in_image_rva(array_rva) or self.pe.read(array_rva, count * 4) is None:
            return None
        base_rvas = [u32(self.pe.read(array_rva + i * 4, 4), 0) for i in range(count)]
        bases = []
        for bcd_rva in base_rvas:
            bcd = self.parse_bcd(bcd_rva)
            if bcd is None:
                return None
            bases.append(bcd)
        result = {
            "rva": rva,
            "signature": signature,
            "attributes": attributes,
            "base_count": count,
            "base_class_array_rva": array_rva,
            "bases": bases,
        }
        self.chds[rva] = result
        return result

    def parse_bcd(self, rva: int) -> dict[str, Any] | None:
        if rva in self.bcds:
            return self.bcds[rva]
        # x64 BaseClassDescriptor is seven 32-bit fields (28 bytes).
        b = self.pe.read(rva, 28)
        if b is None:
            return None
        td_rva, contained, mdisp, pdisp, vdisp, attrs, chd_rva = struct.unpack("<7I", b)
        name = self.type_name(td_rva)
        if not name or contained > 10000:
            return None
        result = {
            "rva": rva,
            "type_descriptor_rva": td_rva,
            "decorated_name": name,
            "name": self.pretty_type(name),
            "num_contained_bases": contained,
            "pmd": {"mdisp": self._signed(mdisp), "pdisp": self._signed(pdisp), "vdisp": self._signed(vdisp)},
            "attributes": attrs,
            "attribute_flags": self.decode_bcd_flags(attrs),
            "class_hierarchy_descriptor_rva": chd_rva,
        }
        self.bcds[rva] = result
        return result

    @staticmethod
    def _signed(value: int) -> int:
        return value - 0x100000000 if value & 0x80000000 else value

    @classmethod
    def decode_bcd_flags(cls, attrs: int) -> list[str]:
        flags = [
            (cls.BCD_NOTVISIBLE, "not-visible"),
            (cls.BCD_AMBIGUOUS, "ambiguous"),
            (cls.BCD_PRIVORPROTBASE, "private-or-protected-base"),
            (cls.BCD_PRIVORPROTINCOMPOBJ, "private-or-protected-in-complete-object"),
            (cls.BCD_VBOFCONTOBJ, "virtual-base-of-complete-object"),
            (cls.BCD_NONPOLYMORPHIC, "non-polymorphic"),
            (cls.BCD_HASPCHD, "has-class-hierarchy-descriptor"),
        ]
        return [label for bit, label in flags if attrs & bit]

    def scan(self) -> dict[str, Any]:
        # COL structures are 4-byte aligned in MSVC PE sections.
        for section, start_rva, raw_ptr, size in self.pe.section_ranges():
            end = start_rva + size
            for rva in range((start_rva + 3) & ~3, end - 23, 4):
                sig = self.pe.read_u32(rva)
                if sig != 1:
                    continue
                col = self.parse_col_at(rva)
                if col:
                    col["section"] = section
                    self.cols[rva] = col

        # A vftable's preceding pointer-sized slot points to its COL.
        # Scan aligned qwords for VA values matching recovered COL addresses.
        col_by_va = {v["va"]: v for v in self.cols.values()}
        for section, start_rva, raw_ptr, size in self.pe.section_ranges():
            start_off = raw_ptr
            end_off = raw_ptr + size
            for off in range((start_off + 7) & ~7, end_off - 7, 8):
                value = struct.unpack_from("<Q", self.pe.data, off)[0]
                col = col_by_va.get(value)
                if not col:
                    continue
                slot_rva = next(
                    (
                        s["rva"] + (off - s["raw_ptr"])
                        for s in self.pe.sections
                        if s["raw_ptr"] <= off < s["raw_ptr"] + s["raw_size"]
                    ),
                    None,
                )
                if slot_rva is None:
                    continue
                # slot_rva is vftable[-1]; the first virtual function slot is +8.
                self.vftables.append({
                    "col_rva": col["rva"],
                    "class_name": col["name"],
                    "decorated_name": col["decorated_name"],
                    "locator_slot_rva": slot_rva,
                    "vftable_rva": slot_rva + 8,
                    "section": section,
                })

        classes: dict[str, dict[str, Any]] = {}
        for col in self.cols.values():
            key = col["decorated_name"]
            chd = self.chds[col["class_hierarchy_descriptor_rva"]]
            entry = classes.setdefault(key, {
                "name": col["name"],
                "decorated_name": key,
                "type_descriptor_rvas": [],
                "complete_object_locators": [],
                "base_classes": [],
                "direct_bases": [],
                "hierarchy_descriptor_rvas": [],
                "vftables": [],
            })
            if col["type_descriptor_rva"] not in entry["type_descriptor_rvas"]:
                entry["type_descriptor_rvas"].append(col["type_descriptor_rva"])
            entry["complete_object_locators"].append({
                "rva": col["rva"], "offset": col["offset"], "cd_offset": col["cd_offset"],
                "section": col.get("section"),
            })
            if chd["rva"] not in entry["hierarchy_descriptor_rvas"]:
                entry["hierarchy_descriptor_rvas"].append(chd["rva"])
            # The base-class array is preorder: element 0 describes the
            # complete class, then each direct base is followed by all of its
            # descendants. numContainedBases is the number of descriptors in
            # that base's subtree, so advance by 1 + numContainedBases to
            # reach the next direct base (not by testing for a leaf).
            seen_base_descriptors = {item["rva"] for item in entry["base_classes"]}
            for index, base in enumerate(chd["bases"]):
                if base["rva"] not in seen_base_descriptors:
                    entry["base_classes"].append({
                        "name": base["name"],
                        "decorated_name": base["decorated_name"],
                        "rva": base["rva"],
                        "pmd": base["pmd"],
                        "attributes": base["attributes"],
                        "attribute_flags": base["attribute_flags"],
                        "num_contained_bases": base["num_contained_bases"],
                        "index_in_base_array": index,
                        "class_hierarchy_descriptor_rva": chd["rva"],
                    })
                    seen_base_descriptors.add(base["rva"])

            i = 1  # skip the complete-class descriptor at index 0
            while i < len(chd["bases"]):
                base = chd["bases"][i]
                direct = {
                    "name": base["name"],
                    "decorated_name": base["decorated_name"],
                    "pmd": base["pmd"],
                    "attributes": base["attributes"],
                    "attribute_flags": base["attribute_flags"],
                }
                # Multiple CHDs may describe the same class; retain distinct
                # base subobjects (e.g. repeated non-virtual bases) by PMD.
                direct_key = (
                    direct["decorated_name"],
                    direct["pmd"]["mdisp"],
                    direct["pmd"]["pdisp"],
                    direct["pmd"]["vdisp"],
                    direct["attributes"],
                )
                existing_keys = {
                    (b["decorated_name"], b["pmd"]["mdisp"], b["pmd"]["pdisp"],
                     b["pmd"]["vdisp"], b["attributes"])
                    for b in entry["direct_bases"]
                }
                if direct_key not in existing_keys:
                    entry["direct_bases"].append(direct)
                i += 1 + base["num_contained_bases"]

        for vt in self.vftables:
            for entry in classes.values():
                if entry["decorated_name"] == vt["decorated_name"]:
                    entry["vftables"].append({
                        "rva": vt["vftable_rva"],
                        "locator_slot_rva": vt["locator_slot_rva"],
                        "section": vt["section"],
                    })

        # Remove duplicate COL entries caused by repeated identical metadata.
        for entry in classes.values():
            unique = {}
            for col in entry["complete_object_locators"]:
                unique[(col["rva"], col["offset"], col["cd_offset"])] = col
            entry["complete_object_locators"] = list(unique.values())

        return {
            "input": os.path.abspath(self.pe.path),
            "architecture": "PE32+ / AMD64 (64-bit)",
            "image_base": hex(self.pe.image_base),
            "summary": {
                "classes": len(classes),
                "complete_object_locators": len(self.cols),
                "class_hierarchy_descriptors": len(self.chds),
                "base_class_descriptors": len(self.bcds),
                "vftable_candidates": len(self.vftables),
            },
            "classes": sorted(classes.values(), key=lambda x: (x["name"] or "")),
            "complete_object_locators": sorted(self.cols.values(), key=lambda x: x["rva"]),
            "warnings": self.warnings,
        }


def dot_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def to_dot(result: dict[str, Any]) -> str:
    lines = [
        "digraph MSVC_RTTI {",
        '  graph [rankdir="BT", overlap=false, splines=true];',
        '  node [shape=box, style="rounded"];',
    ]
    known = set()
    edges = set()
    for cls in result["classes"]:
        child = cls["name"] or cls["decorated_name"]
        known.add(child)
        for base in cls["direct_bases"]:
            parent = base["name"] or base["decorated_name"]
            known.add(parent)
            if child != parent:
                edges.add((child, parent))
    for name in sorted(known):
        lines.append(f'  "{dot_escape(name)}";')
    for child, parent in sorted(edges):
        # Graphviz rankdir=BT makes base classes visually above derived classes.
        lines.append(f'  "{dot_escape(child)}" -> "{dot_escape(parent)}";')
    lines.append("}")
    return "\n".join(lines) + "\n"


def text_report(result: dict[str, Any]) -> str:
    lines = [
        f"Input: {result['input']}",
        f"Architecture: {result['architecture']}",
        f"Image base: {result['image_base']}",
        "Summary: " + ", ".join(f"{k}={v}" for k, v in result["summary"].items()),
        "",
    ]
    for cls in result["classes"]:
        lines.append(f"{cls['name'] or cls['decorated_name']}  [{cls['decorated_name']}]")
        if cls["direct_bases"]:
            for base in cls["direct_bases"]:
                details = base["pmd"]
                flags = ", ".join(base["attribute_flags"]) or "none"
                lines.append(
                    f"  inherits: {base['name'] or base['decorated_name']} "
                    f"(PMD mdisp={details['mdisp']}, pdisp={details['pdisp']}, "
                    f"vdisp={details['vdisp']}; flags={flags})"
                )
        else:
            lines.append("  inherits: (no direct base recovered)")
        lines.append(f"  COLs: {len(cls['complete_object_locators'])}; vftables: {len(cls['vftables'])}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Recover class hierarchy metadata from a 64-bit MSVC RTTI DLL.")
    ap.add_argument("dll", help="Input PE32+ DLL or EXE")
    ap.add_argument("-o", "--output-dir", default="rtti-out", help="Output directory (default: rtti-out)")
    ap.add_argument("--format", choices=("all", "json", "dot", "txt"), default="all",
                    help="Output formats to generate (default: all)")
    args = ap.parse_args()

    try:
        image = PEImage(args.dll)
        parser = RTTIParser(image)
        result = parser.scan()
    except (OSError, ValueError, pefile.PEFormatError, struct.error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    formats = ("json", "dot", "txt") if args.format == "all" else (args.format,)
    for fmt in formats:
        path = outdir / f"{Path(args.dll).stem}_rtti.{fmt if fmt != 'txt' else 'txt'}"
        if fmt == "json":
            path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        elif fmt == "dot":
            path.write_text(to_dot(result), encoding="utf-8")
        else:
            path.write_text(text_report(result) + "\n", encoding="utf-8")
        print(f"Wrote {path}")

    print("Summary:")
    for key, value in result["summary"].items():
        print(f"  {key}: {value}")
    if result["summary"]["classes"] == 0:
        print("No valid x64 MSVC RTTI class hierarchy descriptors were found.")
        print("Check that RTTI is enabled, the file is PE32+, and RTTI data was not stripped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
