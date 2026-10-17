# MSVC RTTI Hierarchy Extractor

A first-pass static parser for class hierarchy metadata in 64-bit MSVC-compiled PE files. It does not execute or load the target DLL and does not require a PDB or Ghidra.

## Requirements

- Windows, Linux, or WSL
- Python 3.10+
- `pefile`

Install dependency:

```bash
python -m pip install pefile
```

## Run

```bash
python msvc_rtti.py path/to/target.dll
```

By default, results go into `rtti-out/`:

- `target_rtti.json` — structured class, RTTI, and base-class metadata
- `target_rtti.dot` — inheritance graph for Graphviz
- `target_rtti.txt` — readable report

Choose one format:

```bash
python msvc_rtti.py target.dll -o results --format json
python msvc_rtti.py target.dll -o results --format dot
```

Render the graph if Graphviz is installed:

```bash
dot -Tsvg results/target_rtti.dot -o results/target_hierarchy.svg
```

## What it parses

For PE32+ / x64 MSVC RTTI, the parser looks for:

- `TypeDescriptor` names
- `RTTICompleteObjectLocator` records (including the x64 self-relative RVA)
- `RTTIClassHierarchyDescriptor` records
- `RTTIBaseClassDescriptor` records
- candidate vftables whose preceding pointer refers to a recovered complete object locator

The JSON preserves decorated MSVC names and includes PMD values (`mdisp`, `pdisp`, `vdisp`) and base-descriptor attribute flags.

## Important limitations

This is an initial implementation, not a fully validated production parser. It assumes standard x64 MSVC RTTI layouts and scans file-backed PE sections for structures. Optimizations, unusual linker layouts, malformed files, packed binaries, or stripped/partially removed RTTI can affect results. Direct bases are selected by walking the MSVC preorder base-class array and advancing by `1 + numContainedBases` for each direct base. This follows the hierarchy descriptor's subtree counts; multiple and virtual inheritance should still be validated against representative classes in a disassembler.

The tool does not currently demangle every MSVC decorated name, recover source-level access specifiers perfectly, or prove that every candidate vftable belongs to a live class. It reports RTTI metadata and should be treated as evidence to validate, not infallible source reconstruction.

For a DLL reported by Ghidra as `x86:LE:64:default`, this PE32+ version is the intended starting point. It is not a 32-bit parser.
