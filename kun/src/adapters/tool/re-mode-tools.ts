import { readFile, writeFile } from 'node:fs/promises'
import { join, relative } from 'node:path'
import { LocalToolHost, type LocalTool } from './local-tool-host.js'
import { normalizeToolPath, resolveWorkspacePath, withToolBoundary, workspaceRoot } from './builtin-tool-utils.js'
import type { ToolHostContext } from '../../ports/tool-host.js'
import type { McpServerDiagnostic } from './mcp-tool-provider.js'
import type { McpSearchCatalogState } from './mcp-tool-search.js'
import {
  analyzeCapabilities,
  analyzeCrypto,
  analyzeEntropy,
  analyzeExports,
  analyzeFileInfo,
  analyzeImports,
  analyzeIocs,
  analyzePacker,
  analyzeSections,
  analyzeStrings,
  appendNote,
  compareBinaries,
  detectFormat,
  ensureReWorkspace,
  generateReport,
  hashFile,
  loadAnalysisState,
  loadSymbolsState,
  readBinarySample,
  reWorkspacePaths,
  saveSymbolsState,
  toolAvailability,
  triageBinary,
  type ReResolvedFile
} from '../../re-mode/re-analysis.js'
import {
  callGhidraOperation,
  ghidraStatus,
  type ReGhidraOperation
} from '../../re-mode/ghidra-mcp.js'
import {
  analyzeProtection,
  loadBehaviorGraph,
  rankHighValueTargets,
  saveFunctionSummary,
  updateBehaviorGraph,
  type ReBehaviorGraph,
  type GhidraEvidencePack,
  type ReBehaviorGraphEdge,
  type ReBehaviorGraphNode,
  type ReBehaviorStage
} from '../../re-mode/protected-analysis.js'

export const RE_TOOL_NAMES = [
  're_tool_availability',
  're_triage',
  're_file_info',
  're_hash',
  're_detect_format',
  're_strings',
  're_entropy',
  're_sections',
  're_imports',
  're_exports',
  're_extract_iocs',
  're_capabilities',
  're_detect_packer',
  're_find_crypto',
  're_compare_binaries',
  're_generate_report',
  're_save_note',
  're_load_analysis_state',
  're_update_symbols',
  're_export_iocs',
  're_protection_indicators',
  're_find_vm_dispatchers',
  're_find_vm_handlers',
  're_find_decode_loops',
  're_find_unpacked_regions',
  're_find_dynamic_api_resolution',
  're_find_indirect_control_flow',
  're_find_bytecode_buffers',
  're_find_opaque_predicates',
  're_find_control_flow_flattening',
  're_find_string_decoders',
  're_find_config_decoders',
  're_find_import_hashing',
  're_find_export_table_walkers',
  're_find_suspicious_memory_permissions',
  're_find_self_modifying_indicators',
  're_build_behavior_graph',
  're_update_behavior_graph',
  're_trace_artifact_usage',
  're_find_blob_consumers',
  're_correlate_findings',
  're_rank_re_targets',
  're_stage_execution_model',
  're_load_behavior_graph',
  're_save_function_summary',
  're_ghidra_status',
  're_ghidra_list_programs',
  're_ghidra_program_info',
  're_ghidra_list_functions',
  're_ghidra_get_function',
  're_ghidra_decompile_function',
  're_ghidra_disassemble_function',
  're_ghidra_xrefs_to',
  're_ghidra_xrefs_from',
  're_ghidra_callers',
  're_ghidra_callees',
  're_ghidra_callgraph',
  're_ghidra_strings',
  're_ghidra_memory_blocks',
  're_ghidra_symbols',
  're_ghidra_imports',
  're_ghidra_exports',
  're_ghidra_rename_function',
  're_ghidra_set_comment',
  're_ghidra_navigate_to',
  're_ghidra_trace_dataflow'
] as const

export type ReModeLocalToolsOptions = {
  mcpCatalog?: McpSearchCatalogState
  mcpDiagnostics?: McpServerDiagnostic[]
}

export function isReToolContextActive(context: ToolHostContext | undefined): boolean {
  return context?.threadMode === 're'
}

export function buildReModeLocalTools(options: ReModeLocalToolsOptions = {}): LocalTool[] {
  return [
    defineReTool({
      name: 're_tool_availability',
      description: [
        'Reverse Engineering Mode only. Detect optional local RE tools on PATH and report enabled/disabled features.',
        'Use this before advanced workflows that may need file, strings, objdump, readelf, otool, rabin2, rizin, radare2, yara, capa, diec, ghidra, apktool, or jadx.'
      ].join(' '),
      inputSchema: emptySchema(),
      execute: async () => ({ output: toolAvailability() })
    }),
    defineReTool({
      name: 're_triage',
      description: [
        'Reverse Engineering Mode only. Run the binary intake pipeline for one file: detect format, hash, parse sections, imports, exports, strings, IOCs, entropy, packer hints, capability hints, recommended targets, and save state under .re-mode/.',
        'Use this for user requests like "triage this binary".'
      ].join(' '),
      inputSchema: fileSchema('Binary file to triage.'),
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await triageBinary(resolveReFile(args, context))
      }))
    }),
    defineReTool({
      name: 're_file_info',
      description: 'Reverse Engineering Mode only. Return file metadata, hashes, and detected binary format, then update .re-mode/analysis.json.',
      inputSchema: fileSchema('Binary file to inspect.'),
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await analyzeFileInfo(resolveReFile(args, context))
      }))
    }),
    defineReTool({
      name: 're_hash',
      description: 'Reverse Engineering Mode only. Compute MD5, SHA1, SHA256, and SHA512 for a binary file.',
      inputSchema: fileSchema('File to hash.'),
      execute: async (args, context) => withToolBoundary(async () => {
        const file = resolveReFile(args, context)
        const hashes = await hashFile(file.absolutePath)
        return {
          output: {
            ok: true,
            file: normalizeToolPath(file.relativePath),
            ...hashes
          }
        }
      })
    }),
    defineReTool({
      name: 're_detect_format',
      description: 'Reverse Engineering Mode only. Detect PE, ELF, Mach-O, APK, ZIP, raw, or unknown binary format from magic/header bytes.',
      inputSchema: fileSchema('File to identify.'),
      execute: async (args, context) => withToolBoundary(async () => {
        const file = resolveReFile(args, context)
        const sample = await readBinarySample(file.absolutePath, 16 * 1024 * 1024)
        return {
          output: {
            ok: true,
            file: normalizeToolPath(file.relativePath),
            format: detectFormat(sample.buffer),
            warnings: sample.truncated ? ['format detection used the first 16 MiB only'] : []
          }
        }
      })
    }),
    defineReTool({
      name: 're_strings',
      description: [
        'Reverse Engineering Mode only. Extract ASCII and UTF-16LE strings, tag interesting strings, return a compact subset, and save full output under .re-mode/raw/.',
        'Use include/min_length/limit to keep output focused.'
      ].join(' '),
      inputSchema: {
        type: 'object',
        properties: {
          file: { type: 'string', description: 'Binary file to scan.' },
          min_length: { type: 'number', description: 'Minimum string length. Defaults to 4.' },
          limit: { type: 'number', description: 'Maximum strings returned to the model. Defaults to 200.' },
          include: { type: 'string', description: 'Optional case-insensitive substring filter.' },
          max_bytes: { type: 'number', description: 'Optional maximum bytes to scan from the start of the file.' }
        },
        required: ['file']
      },
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await analyzeStrings(resolveReFile(args, context), {
          minLength: numberArg(args.min_length),
          limit: numberArg(args.limit),
          include: stringArg(args.include),
          maxBytes: numberArg(args.max_bytes)
        })
      }))
    }),
    defineReTool({
      name: 're_entropy',
      description: 'Reverse Engineering Mode only. Calculate overall, rolling-window, and section entropy for packer/encryption triage.',
      inputSchema: {
        type: 'object',
        properties: {
          file: { type: 'string', description: 'Binary file to analyze.' },
          window_size: { type: 'number', description: 'Rolling entropy window size. Defaults to 4096.' }
        },
        required: ['file']
      },
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await analyzeEntropy(resolveReFile(args, context), numberArg(args.window_size) ?? 4096)
      }))
    }),
    defineReTool({
      name: 're_sections',
      description: 'Reverse Engineering Mode only. Parse PE sections, ELF sections, Mach-O segments/sections, or ZIP/APK entries with offsets, sizes, flags, and entropy.',
      inputSchema: fileSchema('Binary file to parse.'),
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await analyzeSections(resolveReFile(args, context))
      }))
    }),
    defineReTool({
      name: 're_imports',
      description: 'Reverse Engineering Mode only. Parse imports/dynamic symbols where supported. PE and ELF have native MVP parsing; unsupported formats degrade with warnings.',
      inputSchema: fileSchema('Binary file to parse.'),
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await analyzeImports(resolveReFile(args, context))
      }))
    }),
    defineReTool({
      name: 're_exports',
      description: 'Reverse Engineering Mode only. Parse exports/symbols where supported. PE and ELF have native MVP parsing; unsupported formats degrade with warnings.',
      inputSchema: fileSchema('Binary file to parse.'),
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await analyzeExports(resolveReFile(args, context))
      }))
    }),
    defineReTool({
      name: 're_extract_iocs',
      description: 'Reverse Engineering Mode only. Extract and classify URLs, domains, IPs, emails, registry keys, paths, filenames, mutex-like strings, commands, encoded blobs, crypto strings, and suspicious APIs. Saves .re-mode/iocs.json.',
      inputSchema: fileSchema('Binary file to scan for IOCs.'),
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await analyzeIocs(resolveReFile(args, context))
      }))
    }),
    defineReTool({
      name: 're_capabilities',
      description: 'Reverse Engineering Mode only. Summarize behavior capabilities from imports and strings with evidence and confidence.',
      inputSchema: fileSchema('Binary file to analyze.'),
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await analyzeCapabilities(resolveReFile(args, context))
      }))
    }),
    defineReTool({
      name: 're_detect_packer',
      description: 'Reverse Engineering Mode only. Detect packer/obfuscation indicators from entropy, sections, imports, and strings.',
      inputSchema: fileSchema('Binary file to analyze.'),
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await analyzePacker(resolveReFile(args, context))
      }))
    }),
    defineReTool({
      name: 're_find_crypto',
      description: 'Reverse Engineering Mode only. Find crypto/encoding candidates from imports, strings, known constants, high entropy data, and decode/decrypt hints.',
      inputSchema: fileSchema('Binary file to analyze.'),
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await analyzeCrypto(resolveReFile(args, context))
      }))
    }),
    defineReTool({
      name: 're_compare_binaries',
      description: 'Reverse Engineering Mode only. Compare two binary versions: hashes, formats, sections, imports, exports, strings, interesting deltas, and review targets. Saves a diff artifact under .re-mode/diffs/.',
      inputSchema: {
        type: 'object',
        properties: {
          file_a: { type: 'string', description: 'Old or baseline binary.' },
          file_b: { type: 'string', description: 'New or patched binary.' }
        },
        required: ['file_a', 'file_b']
      },
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await compareBinaries(resolveReFile(args, context, 'file_a'), resolveReFile(args, context, 'file_b'))
      }))
    }),
    defineReTool({
      name: 're_generate_report',
      description: 'Reverse Engineering Mode only. Generate .re-mode/report.md from current RE state, optional current file, notes, symbols, IOCs, and tool summaries.',
      toolKind: 'file_change',
      inputSchema: {
        type: 'object',
        properties: {
          file: { type: 'string', description: 'Optional file to triage if no current sample exists.' }
        },
        required: []
      },
      execute: async (args, context) => withToolBoundary(async () => {
        const root = workspaceRoot(context.workspace)
        const file = stringArg(args.file) ? resolveReFile(args, context) : undefined
        return { output: await generateReport(root, file) }
      })
    }),
    defineReTool({
      name: 're_save_note',
      description: 'Reverse Engineering Mode only. Append persistent analyst notes to .re-mode/notes.md.',
      toolKind: 'file_change',
      inputSchema: {
        type: 'object',
        properties: {
          note: { type: 'string', description: 'Markdown note to append.' },
          title: { type: 'string', description: 'Optional note heading.' }
        },
        required: ['note']
      },
      execute: async (args, context) => withToolBoundary(async () => {
        const note = stringArg(args.note)
        if (!note) return { output: { ok: false, error: 'note is required' }, isError: true }
        return { output: await appendNote(workspaceRoot(context.workspace), note, stringArg(args.title)) }
      })
    }),
    defineReTool({
      name: 're_load_analysis_state',
      description: 'Reverse Engineering Mode only. Load persistent RE workspace state from .re-mode/analysis.json, symbols.json, iocs.json, and notes.md.',
      inputSchema: emptySchema(),
      execute: async (_args, context) => withToolBoundary(async () => {
        const root = workspaceRoot(context.workspace)
        const paths = await ensureReWorkspace(root)
        const [analysis, symbols, iocs, notes] = await Promise.all([
          loadAnalysisState(root),
          loadSymbolsState(root),
          readFile(paths.iocs, 'utf8').then((text) => JSON.parse(text) as unknown).catch(() => null),
          readFile(paths.notes, 'utf8').catch(() => '')
        ])
        return {
          output: {
            ok: true,
            analysis,
            symbols,
            iocs,
            notesPreview: notes.slice(0, 12_000),
            paths: {
              analysis: normalizeToolPath(relative(root, paths.analysis)),
              symbols: normalizeToolPath(relative(root, paths.symbols)),
              iocs: normalizeToolPath(relative(root, paths.iocs)),
              notes: normalizeToolPath(relative(root, paths.notes)),
              report: normalizeToolPath(relative(root, paths.report))
            }
          }
        }
      })
    }),
    defineReTool({
      name: 're_update_symbols',
      description: 'Reverse Engineering Mode only. Persist function names, variable names, labels, notes, and confidence in .re-mode/symbols.json.',
      toolKind: 'file_change',
      inputSchema: {
        type: 'object',
        properties: {
          kind: { type: 'string', enum: ['function', 'variable', 'label'] },
          id: { type: 'string', description: 'Function address/name, variable id, or label address.' },
          suggested_name: { type: 'string' },
          user_name: { type: 'string' },
          label: { type: 'string' },
          notes: { type: 'string' },
          confidence: { type: 'string', enum: ['low', 'medium', 'high'] }
        },
        required: ['kind', 'id']
      },
      execute: async (args, context) => withToolBoundary(async () => {
        const root = workspaceRoot(context.workspace)
        const symbols = await loadSymbolsState(root)
        const kind = stringArg(args.kind)
        const id = stringArg(args.id)
        if (!id || (kind !== 'function' && kind !== 'variable' && kind !== 'label')) {
          return { output: { ok: false, error: 'kind must be function, variable, or label and id is required' }, isError: true }
        }
        const confidence = confidenceArg(args.confidence)
        if (kind === 'function') {
          symbols.functions[id] = {
            ...(symbols.functions[id] ?? {}),
            ...(stringArg(args.suggested_name) ? { suggestedName: stringArg(args.suggested_name) } : {}),
            ...(stringArg(args.user_name) ? { userName: stringArg(args.user_name) } : {}),
            ...(stringArg(args.notes) ? { notes: stringArg(args.notes) } : {}),
            ...(confidence ? { confidence } : {})
          }
        } else if (kind === 'variable') {
          symbols.variables[id] = {
            ...(symbols.variables[id] ?? {}),
            ...(stringArg(args.suggested_name) ? { suggestedName: stringArg(args.suggested_name) } : {}),
            ...(stringArg(args.user_name) ? { userName: stringArg(args.user_name) } : {}),
            ...(stringArg(args.notes) ? { notes: stringArg(args.notes) } : {}),
            ...(confidence ? { confidence } : {})
          }
        } else {
          const label = stringArg(args.label) || stringArg(args.user_name) || stringArg(args.suggested_name)
          if (!label) return { output: { ok: false, error: 'label, user_name, or suggested_name is required for labels' }, isError: true }
          symbols.labels[id] = {
            ...(symbols.labels[id] ?? { name: label }),
            name: label,
            ...(stringArg(args.notes) ? { notes: stringArg(args.notes) } : {}),
            ...(confidence ? { confidence } : {})
          }
        }
        await saveSymbolsState(root, symbols)
        return { output: { ok: true, symbolsPath: '.re-mode/symbols.json', symbols } }
      })
    }),
    defineReTool({
      name: 're_export_iocs',
      description: 'Reverse Engineering Mode only. Export current .re-mode/iocs.json as JSON, Markdown, or CSV.',
      toolKind: 'file_change',
      inputSchema: {
        type: 'object',
        properties: {
          format: { type: 'string', enum: ['json', 'markdown', 'csv'], description: 'Export format. Defaults to json.' }
        },
        required: []
      },
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await exportIocs(workspaceRoot(context.workspace), stringArg(args.format) || 'json')
      }))
    }),
    defineReTool({
      name: 're_protection_indicators',
      description: 'Reverse Engineering Mode only. Analyze protected/obfuscated binary indicators and correlate sections, entropy, imports, strings, capabilities, and optional Ghidra evidence into .re-mode/behavior-graph.json.',
      inputSchema: protectedFileSchema(),
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await analyzeProtection(resolveReFile(args, context), ghidraEvidenceArg(args.ghidra_evidence))
      }))
    }),
    ...PROTECTED_FOCUS_TOOLS.map(({ name, description, focus }) => defineReTool({
      name,
      description,
      inputSchema: protectedFileSchema(),
      execute: async (args, context) => withToolBoundary(async () => ({
        output: protectedFocusOutput(
          await analyzeProtection(resolveReFile(args, context), ghidraEvidenceArg(args.ghidra_evidence)),
          focus
        )
      }))
    })),
    defineReTool({
      name: 're_build_behavior_graph',
      description: 'Reverse Engineering Mode only. Build or refresh .re-mode/behavior-graph.json by correlating high-entropy regions, decoders, dynamic API resolution, VM-like control flow, Ghidra evidence, capabilities, and high-value targets.',
      toolKind: 'file_change',
      inputSchema: protectedFileSchema(),
      execute: async (args, context) => withToolBoundary(async () => ({
        output: {
          ...(await analyzeProtection(resolveReFile(args, context), ghidraEvidenceArg(args.ghidra_evidence))),
          artifact: '.re-mode/behavior-graph.json'
        }
      }))
    }),
    defineReTool({
      name: 're_update_behavior_graph',
      description: 'Reverse Engineering Mode only. Merge confirmed or hypothesized nodes, edges, stages, and known unknowns into .re-mode/behavior-graph.json.',
      toolKind: 'file_change',
      inputSchema: {
        type: 'object',
        properties: {
          nodes: { type: 'array', description: 'Behavior/evidence graph nodes to merge.' },
          edges: { type: 'array', description: 'Behavior/evidence graph edges to merge.' },
          stages: { type: 'array', description: 'Execution stages to merge.' },
          known_unknowns: { type: 'array', description: 'Known unknowns to preserve.' }
        },
        required: []
      },
      execute: async (args, context) => withToolBoundary(async () => {
        const root = workspaceRoot(context.workspace)
        const graph = await updateBehaviorGraph(root, {
          nodes: arrayArg<ReBehaviorGraphNode>(args.nodes),
          edges: arrayArg<ReBehaviorGraphEdge>(args.edges),
          stages: arrayArg<ReBehaviorStage>(args.stages),
          knownUnknowns: arrayArg<string>(args.known_unknowns).filter((item): item is string => typeof item === 'string')
        })
        return { output: { ok: true, behaviorGraphPath: '.re-mode/behavior-graph.json', graph } }
      })
    }),
    defineReTool({
      name: 're_load_behavior_graph',
      description: 'Reverse Engineering Mode only. Load .re-mode/behavior-graph.json with evidence links, stages, high-value targets, and known unknowns.',
      inputSchema: emptySchema(),
      execute: async (_args, context) => withToolBoundary(async () => ({
        output: {
          ok: true,
          behaviorGraphPath: '.re-mode/behavior-graph.json',
          graph: await loadBehaviorGraph(workspaceRoot(context.workspace))
        }
      }))
    }),
    defineReTool({
      name: 're_correlate_findings',
      description: 'Reverse Engineering Mode only. Return compact behavior graph correlations: stages, top targets, decoder-to-consumer links, dynamic API links, and known unknowns.',
      inputSchema: emptySchema(),
      execute: async (_args, context) => withToolBoundary(async () => ({
        output: correlateGraph(await loadBehaviorGraph(workspaceRoot(context.workspace)))
      }))
    }),
    defineReTool({
      name: 're_rank_re_targets',
      description: 'Reverse Engineering Mode only. Rank high-value reverse engineering targets from the current behavior graph.',
      inputSchema: emptySchema(),
      execute: async (_args, context) => withToolBoundary(async () => ({
        output: await rankHighValueTargets(workspaceRoot(context.workspace))
      }))
    }),
    defineReTool({
      name: 're_stage_execution_model',
      description: 'Reverse Engineering Mode only. Return the suspected staged flow from .re-mode/behavior-graph.json, such as loader -> decoder -> resolver -> behavior execution.',
      inputSchema: emptySchema(),
      execute: async (_args, context) => withToolBoundary(async () => {
        const graph = await loadBehaviorGraph(workspaceRoot(context.workspace))
        return {
          output: {
            ok: true,
            behaviorGraphPath: '.re-mode/behavior-graph.json',
            stages: graph.stages,
            stageEdges: graph.edges.filter((edge) => edge.relationship === 'transfers_to' || edge.relationship === 'decodes_to' || edge.relationship === 'consumed_by')
          }
        }
      })
    }),
    defineReTool({
      name: 're_trace_artifact_usage',
      description: 'Reverse Engineering Mode only. Trace graph edges around an artifact, address, string, blob, section, or function id to connect producers, decoded artifacts, consumers, and capabilities.',
      inputSchema: traceGraphSchema('Artifact/function/blob/section id or address to trace.'),
      execute: async (args, context) => withToolBoundary(async () => {
        const graph = await loadBehaviorGraph(workspaceRoot(context.workspace))
        return { output: traceGraph(graph, stringArg(args.id) || stringArg(args.address) || stringArg(args.artifact)) }
      })
    }),
    defineReTool({
      name: 're_find_blob_consumers',
      description: 'Reverse Engineering Mode only. Find known or suspected consumers/readers of high-entropy blobs and decoded artifact candidates from the behavior graph.',
      inputSchema: traceGraphSchema('Optional blob node id or address to focus on.'),
      execute: async (args, context) => withToolBoundary(async () => {
        const graph = await loadBehaviorGraph(workspaceRoot(context.workspace))
        return { output: blobConsumers(graph, stringArg(args.id) || stringArg(args.address) || stringArg(args.artifact)) }
      })
    }),
    defineReTool({
      name: 're_save_function_summary',
      description: 'Reverse Engineering Mode only. Save a normalized function summary under .re-mode/functions/ for reuse across protected-binary and Ghidra-backed workflows.',
      toolKind: 'file_change',
      inputSchema: {
        type: 'object',
        properties: {
          address: { type: 'string' },
          name: { type: 'string' },
          suggested_name: { type: 'string' },
          confidence: { type: 'string', enum: ['low', 'medium', 'high'] },
          signature: { type: 'string' },
          size: { type: 'number' },
          callers: { type: 'array' },
          callees: { type: 'array' },
          xrefs_to: { type: 'array' },
          xrefs_from: { type: 'array' },
          imports_used: { type: 'array' },
          strings_referenced: { type: 'array' },
          constants: { type: 'array' },
          decompiler_summary: { type: 'string' },
          disassembly_summary: { type: 'string' },
          tags: { type: 'array' },
          notes: { type: 'array' },
          raw_output_paths: { type: 'object' }
        },
        required: ['address']
      },
      execute: async (args, context) => withToolBoundary(async () => {
        const address = stringArg(args.address)
        if (!address) return { output: { ok: false, error: 'address is required' }, isError: true }
        return {
          output: await saveFunctionSummary(workspaceRoot(context.workspace), {
            address,
            ...(stringArg(args.name) ? { name: stringArg(args.name) } : {}),
            ...(stringArg(args.suggested_name) ? { suggestedName: stringArg(args.suggested_name) } : {}),
            ...(confidenceArg(args.confidence) ? { confidence: confidenceArg(args.confidence) } : {}),
            ...(stringArg(args.signature) ? { signature: stringArg(args.signature) } : {}),
            ...(numberArg(args.size) ? { size: numberArg(args.size) } : {}),
            callers: stringArrayArg(args.callers),
            callees: stringArrayArg(args.callees),
            xrefsTo: stringArrayArg(args.xrefs_to),
            xrefsFrom: stringArrayArg(args.xrefs_from),
            importsUsed: stringArrayArg(args.imports_used),
            stringsReferenced: stringArrayArg(args.strings_referenced),
            constants: stringArrayArg(args.constants),
            ...(stringArg(args.decompiler_summary) ? { decompilerSummary: stringArg(args.decompiler_summary) } : {}),
            ...(stringArg(args.disassembly_summary) ? { disassemblySummary: stringArg(args.disassembly_summary) } : {}),
            tags: stringArrayArg(args.tags),
            notes: stringArrayArg(args.notes),
            ...(objectArg(args.raw_output_paths) ? { rawOutputPaths: objectArg(args.raw_output_paths) as Record<string, string> } : {})
          })
        }
      })
    }),
    defineReTool({
      name: 're_ghidra_status',
      description: 'Reverse Engineering Mode only. Discover whether a trusted Ghidra MCP backend is connected and which decompiler/xref/callgraph/symbol operations appear available.',
      inputSchema: emptySchema(),
      execute: async (_args, context) => withToolBoundary(async () => ({
        output: ghidraStatus({ catalog: options.mcpCatalog, diagnostics: options.mcpDiagnostics }, context)
      }))
    }),
    ...GHIDRA_OPERATION_TOOLS.map(({ name, operation, description, mutating }) => defineReTool({
      name,
      description,
      ...(mutating ? { policy: 'on-request' as const } : {}),
      inputSchema: ghidraOperationSchema(operation),
      execute: async (args, context) => withToolBoundary(async () => ({
        output: await callGhidraOperation(
          { catalog: options.mcpCatalog, diagnostics: options.mcpDiagnostics },
          context,
          operation,
          args
        )
      }))
    }))
  ]
}

function defineReTool(
  tool: Omit<LocalTool, 'policy' | 'shouldAdvertise' | 'toolKind'> & {
    policy?: LocalTool['policy']
    toolKind?: LocalTool['toolKind']
  }
): LocalTool {
  return LocalToolHost.defineTool({
    ...tool,
    toolKind: tool.toolKind ?? 'tool_call',
    policy: tool.policy ?? 'auto',
    shouldAdvertise: isReToolContextActive
  })
}

function resolveReFile(args: Record<string, unknown>, context: ToolHostContext, key = 'file'): ReResolvedFile {
  const rawPath = stringArg(args[key] ?? args.path)
  if (!rawPath) throw new Error(`${key} is required`)
  const resolved = resolveWorkspacePath(rawPath, context)
  return {
    workspaceRoot: resolved.workspaceRoot,
    absolutePath: resolved.absolutePath,
    relativePath: normalizeToolPath(resolved.relativePath)
  }
}

type ProtectedFocus =
  | 'vm_dispatchers'
  | 'vm_handlers'
  | 'decode_loops'
  | 'unpacked_regions'
  | 'dynamic_api_resolution'
  | 'indirect_control_flow'
  | 'bytecode_buffers'
  | 'opaque_predicates'
  | 'control_flow_flattening'
  | 'string_decoders'
  | 'config_decoders'
  | 'import_hashing'
  | 'export_table_walkers'
  | 'memory_permissions'
  | 'self_modifying'

const PROTECTED_FOCUS_TOOLS: Array<{
  name: string
  focus: ProtectedFocus
  description: string
}> = [
  {
    name: 're_find_vm_dispatchers',
    focus: 'vm_dispatchers',
    description: 'Reverse Engineering Mode only. Find likely VM dispatcher, bytecode interpreter, and central indirect-dispatch candidates from local evidence and optional Ghidra evidence.'
  },
  {
    name: 're_find_vm_handlers',
    focus: 'vm_handlers',
    description: 'Reverse Engineering Mode only. Find likely VM handler candidates and handler-like clusters connected to dispatcher evidence.'
  },
  {
    name: 're_find_decode_loops',
    focus: 'decode_loops',
    description: 'Reverse Engineering Mode only. Find decrypt/decode loop candidates, especially XOR/add/sub/rotate loops connected to high-entropy or encoded artifacts.'
  },
  {
    name: 're_find_unpacked_regions',
    focus: 'unpacked_regions',
    description: 'Reverse Engineering Mode only. Find unpacking/staged-loader indicators such as high entropy, write/exec sections, memory permission APIs, and transferred execution hints.'
  },
  {
    name: 're_find_dynamic_api_resolution',
    focus: 'dynamic_api_resolution',
    description: 'Reverse Engineering Mode only. Find LoadLibrary/GetProcAddress, PEB/export-table walking, import hashing, and resolved-function-table indicators.'
  },
  {
    name: 're_find_indirect_control_flow',
    focus: 'indirect_control_flow',
    description: 'Reverse Engineering Mode only. Find indirect branches, computed dispatch, switch/jump-table, and control-flow-obfuscation indicators.'
  },
  {
    name: 're_find_bytecode_buffers',
    focus: 'bytecode_buffers',
    description: 'Reverse Engineering Mode only. Find bytecode buffer candidates from encoded blobs, high-entropy regions, VM strings, and dispatcher relationships.'
  },
  {
    name: 're_find_opaque_predicates',
    focus: 'opaque_predicates',
    description: 'Reverse Engineering Mode only. Find opaque predicate and junk-control-flow hints from current graph and optional Ghidra decompiler/disassembly evidence.'
  },
  {
    name: 're_find_control_flow_flattening',
    focus: 'control_flow_flattening',
    description: 'Reverse Engineering Mode only. Find control-flow flattening candidates, especially large dispatcher-like functions with switch/indirect control-flow evidence.'
  },
  {
    name: 're_find_string_decoders',
    focus: 'string_decoders',
    description: 'Reverse Engineering Mode only. Find runtime string decoder candidates and connect decoded-string artifacts to likely consumers.'
  },
  {
    name: 're_find_config_decoders',
    focus: 'config_decoders',
    description: 'Reverse Engineering Mode only. Find config decoder candidates by correlating encoded blobs, decode loops, high entropy, and behavior consumers.'
  },
  {
    name: 're_find_import_hashing',
    focus: 'import_hashing',
    description: 'Reverse Engineering Mode only. Find import hashing candidates from hash-like constants, export-table walking, and dynamic API resolver patterns.'
  },
  {
    name: 're_find_export_table_walkers',
    focus: 'export_table_walkers',
    description: 'Reverse Engineering Mode only. Find export-table walking candidates and connect them to dynamic API resolution and capability clusters.'
  },
  {
    name: 're_find_suspicious_memory_permissions',
    focus: 'memory_permissions',
    description: 'Reverse Engineering Mode only. Find suspicious VirtualAlloc/VirtualProtect/NtProtectVirtualMemory and write/execute permission transition indicators.'
  },
  {
    name: 're_find_self_modifying_indicators',
    focus: 'self_modifying',
    description: 'Reverse Engineering Mode only. Find self-modifying/unpacking-like indicators from write/exec sections, memory permission APIs, and code-write behavior hints.'
  }
]

const GHIDRA_OPERATION_TOOLS: Array<{
  name: string
  operation: ReGhidraOperation
  description: string
  mutating?: boolean
}> = [
  ['re_ghidra_list_programs', 'list_programs', 'List programs/projects currently open in a connected Ghidra MCP backend.'],
  ['re_ghidra_program_info', 'program_info', 'Read current Ghidra program metadata.'],
  ['re_ghidra_list_functions', 'list_functions', 'List functions from Ghidra with compact metadata.'],
  ['re_ghidra_get_function', 'get_function', 'Read one function summary/signature from Ghidra.'],
  ['re_ghidra_decompile_function', 'decompile_function', 'Read decompiled pseudocode for one function through Ghidra MCP and save raw output under .re-mode/raw/ghidra/.'],
  ['re_ghidra_disassemble_function', 'disassemble_function', 'Read disassembly for one function through Ghidra MCP and save raw output under .re-mode/raw/ghidra/.'],
  ['re_ghidra_xrefs_to', 'xrefs_to', 'Read Ghidra xrefs to an address, string, data item, or function.'],
  ['re_ghidra_xrefs_from', 'xrefs_from', 'Read Ghidra xrefs from an address, data item, or function.'],
  ['re_ghidra_callers', 'callers', 'Read callers of a function from Ghidra.'],
  ['re_ghidra_callees', 'callees', 'Read callees of a function from Ghidra.'],
  ['re_ghidra_callgraph', 'callgraph', 'Read a compact call graph or neighborhood from Ghidra.'],
  ['re_ghidra_strings', 'strings', 'Read strings and data references from Ghidra.'],
  ['re_ghidra_memory_blocks', 'memory_blocks', 'Read memory blocks/segments/sections from Ghidra.'],
  ['re_ghidra_symbols', 'symbols', 'Read symbols, labels, namespaces, and names from Ghidra.'],
  ['re_ghidra_imports', 'imports', 'Read imports from Ghidra.'],
  ['re_ghidra_exports', 'exports', 'Read exports from Ghidra.'],
  ['re_ghidra_rename_function', 'rename_function', 'Rename a function in Ghidra when the MCP backend supports it.', true],
  ['re_ghidra_set_comment', 'set_comment', 'Save a comment/note in Ghidra when the MCP backend supports it.', true],
  ['re_ghidra_navigate_to', 'navigate_to', 'Navigate Ghidra to an address or function when supported.', true],
  ['re_ghidra_trace_dataflow', 'trace_dataflow', 'Pull data-flow hints from Ghidra when the MCP backend supports it.']
].map(([name, operation, description, mutating]) => ({
  name: name as string,
  operation: operation as ReGhidraOperation,
  description: `Reverse Engineering Mode only. ${description as string}`,
  ...(mutating ? { mutating: true } : {})
}))

function protectedFileSchema(): Record<string, unknown> {
  return {
    type: 'object',
    properties: {
      file: { type: 'string', description: 'Binary file to analyze.' },
      ghidra_evidence: {
        type: 'object',
        description: 'Optional normalized Ghidra/user evidence pack with functions, xrefs, and notes to merge into the behavior graph.'
      }
    },
    required: ['file']
  }
}

function protectedFocusOutput(
  result: Awaited<ReturnType<typeof analyzeProtection>>,
  focus: ProtectedFocus
): Record<string, unknown> {
  const graph = result.evidenceMap
  const matchTags = focusTags(focus)
  const nodes = graph.nodes.filter((node) => node.tags.some((tag) => matchTags.some((needle) => tag.includes(needle))))
  const targets = result.highValueTargets.filter((target) =>
    target.reasons.some((reason) => matchTags.some((needle) => reason.toLowerCase().includes(needle))) ||
    matchTags.some((needle) => target.label.toLowerCase().includes(needle))
  )
  return {
    ok: true,
    file: result.file,
    focus,
    summary: result.summary,
    protectionScore: result.protectionScore,
    candidates: focusCandidates(result, focus, nodes, targets),
    relatedFindings: result.protectionIndicators.filter((finding) =>
      finding.evidence.some((item) => matchTags.some((needle) => item.toLowerCase().includes(needle))) ||
      matchTags.some((needle) => finding.label.toLowerCase().includes(needle))
    ),
    behaviorGraphPath: result.behaviorGraphPath,
    recommendedNextActions: result.recommendedNextActions,
    warnings: result.warnings
  }
}

function focusCandidates(
  result: Awaited<ReturnType<typeof analyzeProtection>>,
  focus: ProtectedFocus,
  nodes: ReBehaviorGraphNode[],
  targets: Array<{ id: string; label: string; score: number }>
): unknown[] {
  switch (focus) {
    case 'vm_dispatchers':
    case 'bytecode_buffers':
    case 'control_flow_flattening':
      return result.dispatcherVmCandidates
    case 'vm_handlers':
      return result.handlerCandidates
    case 'decode_loops':
    case 'string_decoders':
    case 'config_decoders':
      return result.decryptDecodeCandidates
    case 'dynamic_api_resolution':
    case 'import_hashing':
    case 'export_table_walkers':
      return result.dynamicApiResolution
    case 'indirect_control_flow':
    case 'opaque_predicates':
      return result.indirectControlFlow
    case 'unpacked_regions':
    case 'memory_permissions':
    case 'self_modifying':
      return targets.length ? targets : nodes
  }
}

function focusTags(focus: ProtectedFocus): string[] {
  switch (focus) {
    case 'vm_dispatchers':
      return ['dispatcher', 'bytecode', 'interpreter', 'indirect']
    case 'vm_handlers':
      return ['handler', 'dispatcher cluster']
    case 'decode_loops':
      return ['decode', 'decrypt', 'xor', 'rotate', 'entropy']
    case 'unpacked_regions':
      return ['unpack', 'loader', 'memory permission', 'write_exec', 'rwx', 'high entropy']
    case 'dynamic_api_resolution':
      return ['dynamic api', 'resolver', 'getprocaddress', 'loadlibrary']
    case 'indirect_control_flow':
      return ['indirect', 'computed', 'switch', 'jump']
    case 'bytecode_buffers':
      return ['bytecode', 'encoded', 'high entropy', 'blob']
    case 'opaque_predicates':
      return ['opaque', 'predicate', 'indirect', 'control']
    case 'control_flow_flattening':
      return ['flattening', 'dispatcher', 'switch', 'indirect']
    case 'string_decoders':
      return ['string', 'decode', 'decoded artifact']
    case 'config_decoders':
      return ['config', 'decode', 'decoded artifact', 'entropy']
    case 'import_hashing':
      return ['hash', 'import', 'api', 'resolver']
    case 'export_table_walkers':
      return ['export', 'table', 'resolver']
    case 'memory_permissions':
      return ['memory permission', 'virtualprotect', 'virtualalloc', 'page_execute']
    case 'self_modifying':
      return ['self modifying', 'memory permission', 'write_exec', 'unpack']
  }
}

function correlateGraph(graph: ReBehaviorGraph): Record<string, unknown> {
  return {
    ok: true,
    behaviorGraphPath: '.re-mode/behavior-graph.json',
    summary: {
      nodes: graph.nodes.length,
      edges: graph.edges.length,
      stages: graph.stages.length,
      targets: graph.targets.length
    },
    stages: graph.stages,
    topTargets: graph.targets.slice(0, 20),
    decoderConsumerLinks: graph.edges.filter((edge) => edge.relationship === 'decodes_to' || edge.relationship === 'consumed_by').slice(0, 60),
    dynamicApiLinks: graph.edges.filter((edge) =>
      /api|resolver|import/i.test(edge.from) || /api|resolver|import/i.test(edge.to)
    ).slice(0, 60),
    highEntropyLinks: graph.edges.filter((edge) =>
      /blob:|high_entropy|section:/i.test(edge.from) || /blob:|high_entropy|section:/i.test(edge.to)
    ).slice(0, 60),
    knownUnknowns: graph.knownUnknowns
  }
}

function traceGraph(graph: ReBehaviorGraph, id: string): Record<string, unknown> {
  if (!id) return { ok: false, error: 'id, address, or artifact is required' }
  const normalized = normalizeGraphId(id)
  const exact = new Set([id, normalized, `func:${id}`, `artifact:${id}`])
  const matchingNodes = graph.nodes.filter((node) =>
    exact.has(node.id) ||
    node.id.includes(id) ||
    node.label.includes(id)
  )
  const ids = new Set(matchingNodes.map((node) => node.id))
  for (const edge of graph.edges) {
    if (ids.has(edge.from)) ids.add(edge.to)
    if (ids.has(edge.to)) ids.add(edge.from)
  }
  return {
    ok: true,
    query: id,
    nodes: graph.nodes.filter((node) => ids.has(node.id)).slice(0, 80),
    edges: graph.edges.filter((edge) => ids.has(edge.from) || ids.has(edge.to)).slice(0, 120),
    targets: graph.targets.filter((target) => ids.has(target.id)).slice(0, 20),
    knownUnknowns: graph.knownUnknowns
  }
}

function blobConsumers(graph: ReBehaviorGraph, id: string): Record<string, unknown> {
  const blobNodes = id
    ? graph.nodes.filter((node) => node.id.includes(id) || node.label.includes(id))
    : graph.nodes.filter((node) => node.tags.includes('high_entropy') || node.tags.includes('decode_input_candidate') || node.tags.includes('decoded_artifact_candidate'))
  const blobIds = new Set(blobNodes.map((node) => node.id))
  const edges = graph.edges.filter((edge) =>
    blobIds.has(edge.from) || blobIds.has(edge.to) ||
    (edge.relationship === 'consumed_by' || edge.relationship === 'read_by' || edge.relationship === 'decodes_to')
  )
  const relatedIds = new Set<string>()
  for (const edge of edges) {
    if (blobIds.has(edge.from) || blobIds.has(edge.to) || edge.relationship === 'consumed_by' || edge.relationship === 'read_by') {
      relatedIds.add(edge.from)
      relatedIds.add(edge.to)
    }
  }
  return {
    ok: true,
    query: id || null,
    blobs: blobNodes.slice(0, 50),
    consumers: graph.nodes.filter((node) => relatedIds.has(node.id) && !blobIds.has(node.id)).slice(0, 80),
    edges: edges.slice(0, 120),
    targets: graph.targets.filter((target) => relatedIds.has(target.id)).slice(0, 25)
  }
}

function traceGraphSchema(description: string): Record<string, unknown> {
  return {
    type: 'object',
    properties: {
      id: { type: 'string', description },
      address: { type: 'string', description: 'Optional address to trace.' },
      artifact: { type: 'string', description: 'Optional artifact id or label to trace.' }
    },
    required: []
  }
}

function ghidraOperationSchema(operation: ReGhidraOperation): Record<string, unknown> {
  const mutating = operation === 'rename_function' || operation === 'set_comment' || operation === 'navigate_to'
  return {
    type: 'object',
    properties: {
      program: { type: 'string', description: 'Optional Ghidra program/project identifier. Uses active/current program when omitted if the MCP backend supports it.' },
      address: { type: 'string', description: 'Address, offset, or data location.' },
      function: { type: 'string', description: 'Function name or address.' },
      symbol: { type: 'string', description: 'Symbol, label, string, or data item.' },
      name: { type: 'string', description: 'Current name for rename/navigation operations.' },
      new_name: { type: 'string', description: 'New name for rename operations.' },
      comment: { type: 'string', description: 'Comment text for set-comment operations.' },
      comment_type: { type: 'string', description: 'Backend-specific comment type such as eol, pre, post, plate, or repeatable.' },
      max_items: { type: 'number', description: 'Maximum results to return when supported.' },
      depth: { type: 'number', description: 'Traversal depth for callgraph/dataflow operations when supported.' },
      arguments: { type: 'object', description: 'Backend-specific MCP arguments. Common fields above are merged in.' }
    },
    required: mutating && operation === 'rename_function' ? ['new_name'] : []
  }
}

function ghidraEvidenceArg(value: unknown): GhidraEvidencePack | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined
  return value as GhidraEvidencePack
}

function normalizeGraphId(value: string): string {
  const trimmed = value.trim()
  if (/^(func|artifact|blob|section|import|capability):/i.test(trimmed)) return trimmed
  if (/^0x[0-9a-f]+$/i.test(trimmed)) return `func:${trimmed}`
  return trimmed
}

async function exportIocs(workspaceRootPath: string, format: string): Promise<{
  ok: true
  format: string
  path: string
}> {
  const paths = await ensureReWorkspace(workspaceRootPath)
  const raw = await readFile(paths.iocs, 'utf8').catch(() => '{}')
  const iocs = JSON.parse(raw) as Record<string, unknown>
  if (format === 'markdown') {
    const target = join(paths.root, 'iocs.md')
    const lines = ['# IOCs', '']
    for (const [category, values] of Object.entries(iocs)) {
      if (!Array.isArray(values) || values.length === 0) continue
      lines.push(`## ${category}`, '', '| Value |', '| --- |')
      for (const value of values) lines.push(`| ${String(value).replaceAll('|', '\\|')} |`)
      lines.push('')
    }
    await writeFile(target, lines.join('\n'), 'utf8')
    return { ok: true, format: 'markdown', path: normalizeToolPath(relative(workspaceRootPath, target)) }
  }
  if (format === 'csv') {
    const target = join(paths.root, 'iocs.csv')
    const rows = ['category,value']
    for (const [category, values] of Object.entries(iocs)) {
      if (!Array.isArray(values)) continue
      for (const value of values) rows.push(`${csvCell(category)},${csvCell(String(value))}`)
    }
    await writeFile(target, rows.join('\n'), 'utf8')
    return { ok: true, format: 'csv', path: normalizeToolPath(relative(workspaceRootPath, target)) }
  }
  return { ok: true, format: 'json', path: normalizeToolPath(relative(workspaceRootPath, reWorkspacePaths(workspaceRootPath).iocs)) }
}

function fileSchema(description: string): Record<string, unknown> {
  return {
    type: 'object',
    properties: {
      file: { type: 'string', description }
    },
    required: ['file']
  }
}

function emptySchema(): Record<string, unknown> {
  return { type: 'object', properties: {}, required: [] }
}

function stringArg(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function numberArg(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return undefined
}

function objectArg(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined
}

function arrayArg<T = unknown>(value: unknown): T[] {
  return Array.isArray(value) ? value as T[] : []
}

function stringArrayArg(value: unknown): string[] {
  return arrayArg<unknown>(value)
    .map((item) => typeof item === 'string' ? item.trim() : '')
    .filter(Boolean)
}

function confidenceArg(value: unknown): 'low' | 'medium' | 'high' | undefined {
  return value === 'low' || value === 'medium' || value === 'high' ? value : undefined
}

function csvCell(value: string): string {
  return `"${value.replaceAll('"', '""')}"`
}
