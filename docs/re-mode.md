# Reverse Engineering Mode

English | [中文](./re-mode.zh-CN.md)

Reverse Engineering Mode, or RE Mode, turns Kun into a binary-analysis workbench. It is a dedicated mode with its own prompt, tool surface, workspace artifacts, protected-binary heuristics, and optional Ghidra MCP integration.

RE Mode is designed for fast triage first, then focused function-level work. It keeps raw tool output on disk and passes compact summaries to the model.

## Enabling RE Mode

Open the **Reverse Engineering** tab in the workspace mode switcher. New chats started from that tab are created with mode `re`; Kun then advertises RE-only tools and injects the RE Mode instructions.

The composer also exposes an RE chip and a right-side RE panel with quick workflows:

- Binary triage
- Protected analysis
- Crypto / decoders
- IOC extraction
- Patch diff
- Report generation

## Supported Intake

The local helpers support a no-dependency MVP for:

- PE, ELF, Mach-O, ZIP, APK, raw, and unknown file detection
- File metadata and hashes
- PE sections, imports, and exports
- ELF sections, imports, and exports
- Mach-O segments and sections
- APK/ZIP entry summaries
- ASCII and UTF-16LE strings
- Entropy and rolling entropy windows
- IOC extraction
- Capability classification
- Packer and obfuscation indicators
- Protected-binary behavior graph generation
- Markdown report generation

Optional external tools are discovered at runtime. They are not hard requirements.

## Optional Dependencies

Run `re_tool_availability` inside RE Mode to see what is installed. Current optional tools include:

- `file`
- `strings`
- `objdump`
- `readelf`
- `otool`
- `rabin2`
- `rizin`
- `radare2`
- `yara`
- `capa`
- `diec`
- `ghidra`
- `apktool`
- `jadx`

Missing tools degrade gracefully. RE Mode should explain which feature is limited and continue with local helpers, saved artifacts, MCP discovery, or user-provided snippets.

## Ghidra MCP

RE Mode is Ghidra MCP-aware but not Ghidra-dependent.

When a trusted Ghidra MCP server is connected, RE Mode treats it as the high-fidelity backend for:

- Open programs/projects
- Program metadata
- Functions and signatures
- Decompiled pseudocode
- Disassembly
- Callers and callees
- Xrefs to/from addresses, strings, data, and functions
- Symbols, labels, namespaces, imports, and exports
- Memory blocks and sections
- Strings and data references
- Rename/comment/navigation operations when supported
- Call graph and data-flow hints when supported

Use `re_ghidra_status` first. If multiple programs are open and the MCP backend does not expose an active program, the agent should ask the user to choose one.

Raw Ghidra responses are saved under `.re-mode/raw/ghidra/`. Normalized function summaries are saved under `.re-mode/functions/`.

## Workspace Artifacts

RE Mode writes sidecar state under the workspace root:

```text
.re-mode/
  analysis.json
  symbols.json
  iocs.json
  notes.md
  report.md
  behavior-graph.json
  raw/
    ghidra/
  functions/
  diffs/
```

Responsibilities:

- `analysis.json`: current sample, format, hashes, sections, imports, exports, strings, entropy, capabilities, packer hints, and recommendations.
- `symbols.json`: function renames, variable renames, address labels, symbol confidence, and per-function notes.
- `iocs.json`: URLs, domains, IPs, emails, registry keys, paths, commands, encoded blobs, crypto constants, and suspicious APIs.
- `notes.md`: human-readable analysis notes.
- `report.md`: generated markdown report.
- `behavior-graph.json`: linked evidence graph for protected/obfuscated analysis.
- `raw/`: raw local tool outputs kept out of the chat context.
- `raw/ghidra/`: raw Ghidra MCP responses.
- `functions/`: normalized function summaries.
- `diffs/`: binary diff outputs.

## Core Tooling

Primary local tools:

- `re_tool_availability`
- `re_triage`
- `re_file_info`
- `re_hash`
- `re_detect_format`
- `re_strings`
- `re_entropy`
- `re_sections`
- `re_imports`
- `re_exports`
- `re_extract_iocs`
- `re_capabilities`
- `re_detect_packer`
- `re_find_crypto`
- `re_compare_binaries`
- `re_generate_report`
- `re_save_note`
- `re_load_analysis_state`
- `re_update_symbols`
- `re_export_iocs`

Protected-binary tools:

- `re_protection_indicators`
- `re_find_vm_dispatchers`
- `re_find_vm_handlers`
- `re_find_decode_loops`
- `re_find_unpacked_regions`
- `re_find_dynamic_api_resolution`
- `re_find_indirect_control_flow`
- `re_find_bytecode_buffers`
- `re_find_opaque_predicates`
- `re_find_control_flow_flattening`
- `re_find_string_decoders`
- `re_find_config_decoders`
- `re_find_import_hashing`
- `re_find_export_table_walkers`
- `re_find_suspicious_memory_permissions`
- `re_find_self_modifying_indicators`
- `re_build_behavior_graph`
- `re_update_behavior_graph`
- `re_trace_artifact_usage`
- `re_find_blob_consumers`
- `re_correlate_findings`
- `re_rank_re_targets`
- `re_stage_execution_model`
- `re_load_behavior_graph`
- `re_save_function_summary`

Ghidra MCP adapter tools:

- `re_ghidra_status`
- `re_ghidra_list_programs`
- `re_ghidra_program_info`
- `re_ghidra_list_functions`
- `re_ghidra_get_function`
- `re_ghidra_decompile_function`
- `re_ghidra_disassemble_function`
- `re_ghidra_xrefs_to`
- `re_ghidra_xrefs_from`
- `re_ghidra_callers`
- `re_ghidra_callees`
- `re_ghidra_callgraph`
- `re_ghidra_strings`
- `re_ghidra_memory_blocks`
- `re_ghidra_symbols`
- `re_ghidra_imports`
- `re_ghidra_exports`
- `re_ghidra_rename_function`
- `re_ghidra_set_comment`
- `re_ghidra_navigate_to`
- `re_ghidra_trace_dataflow`

## Binary Triage Workflow

Prompt examples:

```text
Triage this binary.
Extract IOCs.
Find suspicious imports.
Generate a reverse engineering report.
```

The intake pipeline:

1. Detect file type.
2. Compute hashes.
3. Extract metadata.
4. Parse headers.
5. Summarize sections or segments.
6. Extract imports, exports, and symbols where supported.
7. Extract strings.
8. Extract IOCs.
9. Estimate entropy.
10. Detect packing indicators.
11. Generate a triage summary.
12. Save results under `.re-mode/`.

## Protected Binary Analysis

Prompt examples:

```text
Analyze protection/obfuscation for this binary.
Find virtualization indicators and rank likely dispatcher candidates.
Build a behavior graph linking high-entropy blobs, decoders, and consumers.
Find dynamic API resolution and connect resolved APIs to capabilities.
Find staged unpacking/decryption flow.
Rank the top 10 functions to reverse first.
```

Protected analysis looks for correlated evidence, not isolated hints:

- High-entropy sections, segments, overlays, and blobs
- Executable/writeable or RWX permissions
- Unusual section names
- Tiny import tables with richer behavior hints
- Entrypoint stubs and staged transitions
- Suspicious memory permission APIs
- Self-modifying or unpacking-like behavior
- Decrypt/decode loops
- Runtime string/config/code decryption
- Dynamic API resolution
- Import hashing
- Export table walking
- PEB/TEB access
- Anti-debug and anti-VM indicators
- Indirect jumps and calls
- Control-flow flattening
- Opaque predicates
- VM dispatchers
- VM handler clusters
- Bytecode buffers

The main model is a behavior graph:

```text
high_entropy_blob -> decoder_function -> decoded_artifact -> consumer_function -> capability
entrypoint_stub -> unpacking_region -> memory_permission_change -> transferred_execution
dispatcher -> handlers -> bytecode_blob -> virtualized_behavior_candidates
api_hash_loop -> resolved_function_table -> capability_cluster
```

The graph is stored in `.re-mode/behavior-graph.json` and includes nodes, edges, stages, ranked targets, and known unknowns.

## Function-Level Workflow

Prompt examples:

```text
Use Ghidra to explain function 0x1400129A0.
Use Ghidra xrefs to trace consumers of this decoded string.
Pull the decompiled code for this candidate dispatcher.
Suggest better names for this decompiled function.
Use Ghidra MCP to rename likely config decoder functions.
Save this analysis as Ghidra comments if supported.
```

When Ghidra MCP is available, RE Mode should pull only the smallest useful context:

- Function metadata
- Signature
- Decompiled pseudocode summary
- Disassembly summary
- Callers and callees
- Xrefs
- Imports used
- Strings referenced
- Constants

The normalized function cache shape is:

```json
{
  "address": "0x1400129A0",
  "name": "sub_1400129A0",
  "suggestedName": "possible_config_decoder",
  "confidence": "medium",
  "signature": "undefined8 sub_1400129A0(...)",
  "size": 438,
  "callers": [],
  "callees": [],
  "xrefsTo": [],
  "xrefsFrom": [],
  "importsUsed": [],
  "stringsReferenced": [],
  "constants": [],
  "decompilerSummary": "Tight byte-wise decode loop over a high-entropy blob.",
  "disassemblySummary": "Loop contains XOR/add/rotate-like operations.",
  "tags": ["decoder", "config_candidate"],
  "notes": [],
  "rawOutputPaths": {
    "decompile": ".re-mode/raw/ghidra/0x1400129A0.decompile.txt",
    "disassembly": ".re-mode/raw/ghidra/0x1400129A0.disasm.txt"
  }
}
```

## Patch Diff Workflow

Prompt example:

```text
Compare old.exe and new.exe.
```

RE Mode compares:

- Hashes
- Format and architecture
- Sections and entropy
- Imports and exports
- Strings
- IOC-like deltas
- Suspicious capability deltas

Function-level diffing needs Ghidra MCP or another decompiler/disassembler backend.

## Reporting

Prompt example:

```text
Generate RE report.
```

The report is saved to `.re-mode/report.md` and includes:

- Executive summary
- Scope
- Sample metadata
- Hashes
- Format and architecture
- Static analysis summary
- Sections and entropy
- Imports and exports
- Strings of interest
- Capabilities
- IOCs
- Function analysis
- Protected/obfuscated findings
- Crypto/encoding findings
- Diff findings
- Hypotheses
- Confidence levels
- Limitations
- Recommended next steps

## Token Policy

RE Mode keeps token ROI high:

- Do not paste full strings output into chat.
- Do not paste full disassembly unless explicitly requested.
- Do not paste full decompiler output unless explicitly requested.
- Save raw output under `.re-mode/raw/`.
- Save Ghidra raw output under `.re-mode/raw/ghidra/`.
- Save structured facts under `.re-mode/*.json`.
- Save function summaries under `.re-mode/functions/`.
- Pass compact summaries, addresses, offsets, hashes, imports, strings of interest, IOCs, constants, and relationship edges to the model.

## Limitations

- Local helpers are heuristic and do not fully unpack, devirtualize, or emulate protected binaries.
- PE/ELF/Mach-O parsing is intentionally MVP-level and should be extended with LIEF/rizin/radare2/Ghidra backends when available.
- Function-level analysis is limited without Ghidra MCP, another MCP decompiler backend, or user-provided snippets.
- Protected-binary labels are confidence-rated candidates, not proofs.

## Extension Points

Useful next integrations:

- LIEF-backed rich PE/ELF/Mach-O parsing
- rizin/radare2 disassembly and xref fallback
- capa and YARA wrappers
- DIE packer/compiler detection
- Ghidra MCP schemas for backend-specific tools
- Function graph visualization in the UI
- IOC export UI button
- Raw output viewer
- Ghidra rename/comment suggestion queue
- Decoded artifact registry
- Dynamic API resolver map
- Handler cluster view
