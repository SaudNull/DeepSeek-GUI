import { existsSync } from 'node:fs'
import { readFile, writeFile } from 'node:fs/promises'
import { basename, join, relative } from 'node:path'
import {
  analyzeCapabilities,
  analyzeEntropy,
  analyzeImports,
  analyzePacker,
  analyzeSections,
  analyzeStrings,
  ensureReWorkspace,
  reWorkspacePaths,
  saveRawOutput,
  triageBinary,
  type ReCapability,
  type ReImport,
  type ReResolvedFile,
  type ReSection,
  type ReStringRecord
} from './re-analysis.js'

export type ReConfidence = 'low' | 'medium' | 'high'

export type ReBehaviorGraphNode = {
  id: string
  type:
    | 'function'
    | 'data_blob'
    | 'section'
    | 'artifact'
    | 'import'
    | 'capability'
    | 'stage'
    | 'unknown'
  label: string
  confidence: ReConfidence
  source: string[]
  evidence: string[]
  tags: string[]
  score?: number
  metadata?: Record<string, unknown>
}

export type ReBehaviorGraphEdge = {
  from: string
  to: string
  relationship:
    | 'read_by'
    | 'writes_to'
    | 'decodes_to'
    | 'consumed_by'
    | 'calls'
    | 'resolves'
    | 'uses'
    | 'references'
    | 'transfers_to'
    | 'correlates_with'
  evidence?: string[]
  confidence?: ReConfidence
}

export type ReBehaviorStage = {
  id: string
  label: string
  confidence: ReConfidence
  nodes: string[]
  evidence?: string[]
}

export type ReTargetRank = {
  id: string
  rank: number
  label: string
  confidence: ReConfidence
  score: number
  sources: string[]
  reasons: string[]
  recommendedAction: string
}

export type ReBehaviorGraph = {
  version: 1
  sample?: string
  updatedAt: string
  nodes: ReBehaviorGraphNode[]
  edges: ReBehaviorGraphEdge[]
  stages: ReBehaviorStage[]
  targets: ReTargetRank[]
  knownUnknowns: string[]
}

export type ReProtectionFinding = {
  category:
    | 'packer'
    | 'virtualization'
    | 'decode'
    | 'dynamic_api_resolution'
    | 'anti_analysis'
    | 'indirect_control_flow'
    | 'self_modifying'
    | 'staging'
    | 'control_flow_obfuscation'
  label: string
  confidence: ReConfidence
  evidence: string[]
  relatedNodes: string[]
}

export type ReProtectedAnalysisResult = {
  ok: true
  file: string
  protectionScore: number
  virtualizationConfidence: ReConfidence
  summary: string
  protectionIndicators: ReProtectionFinding[]
  evidenceMap: ReBehaviorGraph
  suspectedExecutionStages: ReBehaviorStage[]
  dispatcherVmCandidates: ReTargetRank[]
  handlerCandidates: ReTargetRank[]
  decryptDecodeCandidates: ReTargetRank[]
  highEntropyRegions: ReBehaviorGraphNode[]
  indirectControlFlow: ReProtectionFinding[]
  dynamicApiResolution: ReProtectionFinding[]
  decodedArtifactCandidates: ReBehaviorGraphNode[]
  ghidraFindings: string[]
  behaviorGraphPath: string
  rawOutputPath: string
  highValueTargets: ReTargetRank[]
  recommendedNextActions: string[]
  confidence: ReConfidence
  warnings: string[]
}

export type GhidraEvidencePack = {
  source?: 'ghidra-mcp' | 'user-snippet'
  functions?: Array<{
    address?: string
    name?: string
    signature?: string
    size?: number
    callers?: string[]
    callees?: string[]
    xrefsTo?: string[]
    xrefsFrom?: string[]
    stringsReferenced?: string[]
    importsUsed?: string[]
    constants?: string[]
    decompilerText?: string
    disassemblyText?: string
    summary?: string
  }>
  xrefs?: Array<{ from: string; to: string; kind?: string; evidence?: string }>
  notes?: string[]
}

export function emptyBehaviorGraph(sample?: string): ReBehaviorGraph {
  return {
    version: 1,
    ...(sample ? { sample } : {}),
    updatedAt: new Date().toISOString(),
    nodes: [],
    edges: [],
    stages: [],
    targets: [],
    knownUnknowns: []
  }
}

export async function loadBehaviorGraph(workspaceRoot: string): Promise<ReBehaviorGraph> {
  const paths = await ensureReWorkspace(workspaceRoot)
  if (!existsSync(paths.behaviorGraph)) {
    const graph = emptyBehaviorGraph()
    await saveBehaviorGraph(workspaceRoot, graph)
    return graph
  }
  try {
    return normalizeBehaviorGraph(JSON.parse(await readFile(paths.behaviorGraph, 'utf8')) as unknown)
  } catch {
    return emptyBehaviorGraph()
  }
}

export async function saveBehaviorGraph(workspaceRoot: string, graph: ReBehaviorGraph): Promise<void> {
  const paths = await ensureReWorkspace(workspaceRoot)
  await writeFile(paths.behaviorGraph, `${JSON.stringify(normalizeBehaviorGraph({
    ...graph,
    updatedAt: new Date().toISOString()
  }), null, 2)}\n`, 'utf8')
}

export async function updateBehaviorGraph(
  workspaceRoot: string,
  patch: {
    nodes?: ReBehaviorGraphNode[]
    edges?: ReBehaviorGraphEdge[]
    stages?: ReBehaviorStage[]
    knownUnknowns?: string[]
  }
): Promise<ReBehaviorGraph> {
  const graph = await loadBehaviorGraph(workspaceRoot)
  const next = mergeBehaviorGraph(graph, {
    ...graph,
    nodes: patch.nodes ?? [],
    edges: patch.edges ?? [],
    stages: patch.stages ?? [],
    targets: [],
    knownUnknowns: patch.knownUnknowns ?? []
  })
  next.targets = rankReTargets(next)
  await saveBehaviorGraph(workspaceRoot, next)
  return next
}

export async function analyzeProtection(
  file: ReResolvedFile,
  ghidraEvidence?: GhidraEvidencePack
): Promise<ReProtectedAnalysisResult> {
  const [triage, sectionsResult, importsResult, stringsResult, entropyResult, packerResult, capabilitiesResult] =
    await Promise.all([
      triageBinary(file),
      analyzeSections(file),
      analyzeImports(file).catch((error: unknown) => ({ imports: [] as ReImport[], warnings: [errorMessage(error)] })),
      analyzeStrings(file, { minLength: 4, limit: 1_000 }),
      analyzeEntropy(file),
      analyzePacker(file),
      analyzeCapabilities(file)
    ])

  const graph = buildLocalBehaviorGraph({
    file,
    sections: sectionsResult.sections,
    imports: importsResult.imports,
    strings: stringsResult.strings,
    entropy: entropyResult,
    capabilities: capabilitiesResult.capabilities,
    packerIndicators: packerResult.indicators,
    ghidraEvidence
  })
  const findings = buildProtectionFindings(graph)
  graph.targets = rankReTargets(graph)
  const existing = await loadBehaviorGraph(file.workspaceRoot)
  const merged = mergeBehaviorGraph(existing, graph)
  merged.sample = file.relativePath
  merged.targets = rankReTargets(merged)
  await saveBehaviorGraph(file.workspaceRoot, merged)
  const paths = reWorkspacePaths(file.workspaceRoot)
  const rawOutputPath = await saveRawOutput(file.workspaceRoot, 'protected-analysis', file.relativePath, {
    triage,
    findings,
    graph: merged,
    ghidraEvidenceSummary: summarizeGhidraEvidence(ghidraEvidence)
  })

  const highEntropyRegions = merged.nodes.filter((node) => node.tags.includes('high_entropy')).slice(0, 25)
  const dispatcherVmCandidates = merged.targets.filter((target) =>
    /dispatcher|bytecode|vm|interpreter/i.test(target.label) ||
    target.reasons.some((reason) => /dispatcher|bytecode|vm|indirect|handler/i.test(reason))
  ).slice(0, 15)
  const handlerCandidates = merged.targets.filter((target) =>
    /handler/i.test(target.label) ||
    target.reasons.some((reason) => /handler|small repeated|dispatcher cluster/i.test(reason))
  ).slice(0, 15)
  const decryptDecodeCandidates = merged.targets.filter((target) =>
    /decode|decrypt|crypto|string|config/i.test(target.label) ||
    target.reasons.some((reason) => /decode|decrypt|xor|entropy|string|config/i.test(reason))
  ).slice(0, 15)
  const indirectControlFlow = findings.filter((finding) => finding.category === 'indirect_control_flow' || finding.category === 'control_flow_obfuscation')
  const dynamicApiResolution = findings.filter((finding) => finding.category === 'dynamic_api_resolution')
  const decodedArtifactCandidates = merged.nodes.filter((node) => node.tags.includes('decoded_artifact_candidate')).slice(0, 25)
  const protectionScore = scoreProtection(findings, merged)
  const confidence = protectionScore >= 70 ? 'high' : protectionScore >= 35 ? 'medium' : 'low'
  const virtualizationConfidence = dispatcherVmCandidates.length >= 2 ? 'high' : dispatcherVmCandidates.length === 1 ? 'medium' : 'low'
  const warnings = [
    ...sectionsResult.warnings,
    ...(importsResult.warnings ?? []),
    ...stringsResult.warnings,
    ...entropyResult.warnings,
    ...packerResult.warnings,
    ...capabilitiesResult.warnings,
    ...(ghidraEvidence ? [] : ['No Ghidra MCP evidence was provided; function-level protected-flow conclusions are heuristic and limited.'])
  ]
  return {
    ok: true,
    file: file.relativePath,
    protectionScore,
    virtualizationConfidence,
    summary: summarizeProtection(findings, merged, protectionScore),
    protectionIndicators: findings,
    evidenceMap: compactGraphForModel(merged),
    suspectedExecutionStages: merged.stages,
    dispatcherVmCandidates,
    handlerCandidates,
    decryptDecodeCandidates,
    highEntropyRegions,
    indirectControlFlow,
    dynamicApiResolution,
    decodedArtifactCandidates,
    ghidraFindings: summarizeGhidraEvidence(ghidraEvidence),
    behaviorGraphPath: normalizePath(relative(file.workspaceRoot, paths.behaviorGraph)),
    rawOutputPath,
    highValueTargets: merged.targets.slice(0, 25),
    recommendedNextActions: recommendProtectedNextActions({
      ghidraEvidence,
      dispatcherVmCandidates,
      decryptDecodeCandidates,
      dynamicApiResolution,
      highEntropyRegions
    }),
    confidence,
    warnings
  }
}

export async function rankHighValueTargets(
  workspaceRoot: string
): Promise<{ ok: true; targets: ReTargetRank[]; behaviorGraphPath: string }> {
  const graph = await loadBehaviorGraph(workspaceRoot)
  graph.targets = rankReTargets(graph)
  await saveBehaviorGraph(workspaceRoot, graph)
  return {
    ok: true,
    targets: graph.targets,
    behaviorGraphPath: normalizePath(relative(workspaceRoot, reWorkspacePaths(workspaceRoot).behaviorGraph))
  }
}

export async function saveFunctionSummary(
  workspaceRoot: string,
  summary: {
    address: string
    name?: string
    suggestedName?: string
    confidence?: ReConfidence
    signature?: string
    size?: number
    callers?: string[]
    callees?: string[]
    xrefsTo?: string[]
    xrefsFrom?: string[]
    importsUsed?: string[]
    stringsReferenced?: string[]
    constants?: string[]
    decompilerSummary?: string
    disassemblySummary?: string
    tags?: string[]
    notes?: string[]
    rawOutputPaths?: Record<string, string>
  }
): Promise<{ ok: true; path: string }> {
  const paths = await ensureReWorkspace(workspaceRoot)
  const safe = sanitizeFileName(summary.address || summary.name || `function-${Date.now()}`)
  const target = join(paths.functions, `${safe}.json`)
  await writeFile(target, `${JSON.stringify(summary, null, 2)}\n`, 'utf8')
  return { ok: true, path: normalizePath(relative(workspaceRoot, target)) }
}

function buildLocalBehaviorGraph(input: {
  file: ReResolvedFile
  sections: ReSection[]
  imports: ReImport[]
  strings: ReStringRecord[]
  entropy: Awaited<ReturnType<typeof analyzeEntropy>>
  capabilities: ReCapability[]
  packerIndicators: Array<{ indicator: string; confidence: ReConfidence; evidence: string[] }>
  ghidraEvidence?: GhidraEvidencePack
}): ReBehaviorGraph {
  const graph = emptyBehaviorGraph(input.file.relativePath)
  const addNode = (node: ReBehaviorGraphNode): void => {
    graph.nodes.push(node)
  }
  const addEdge = (edge: ReBehaviorGraphEdge): void => {
    graph.edges.push(edge)
  }

  const fileNode = node({
    id: `file:${input.file.relativePath}`,
    type: 'artifact',
    label: basename(input.file.relativePath),
    confidence: 'high',
    evidence: [`workspace path: ${input.file.relativePath}`],
    tags: ['sample']
  })
  addNode(fileNode)

  for (const section of input.sections) {
    const tags = [
      'section',
      ...(section.flags ?? []),
      ...(Number(section.entropy ?? 0) >= 7.2 ? ['high_entropy', 'encrypted_or_packed_region_candidate'] : []),
      ...(section.flags?.some((flag) => /exec/i.test(flag)) && section.flags?.some((flag) => /write/i.test(flag)) ? ['rwx_or_write_exec'] : []),
      ...(UNUSUAL_SECTION_NAME.test(section.name) ? ['unusual_section_name'] : [])
    ]
    const sectionNode = node({
      id: `section:${section.name}`,
      type: 'section',
      label: section.name,
      confidence: Number(section.entropy ?? 0) >= 7.2 ? 'high' : 'medium',
      evidence: [
        ...(section.entropy !== undefined ? [`entropy=${section.entropy}`] : []),
        ...(section.virtualAddress ? [`va=${section.virtualAddress}`] : []),
        ...(section.rawOffset !== undefined ? [`raw_offset=${section.rawOffset}`] : []),
        ...(section.flags?.length ? [`flags=${section.flags.join(',')}`] : [])
      ],
      tags,
      metadata: section
    })
    addNode(sectionNode)
    addEdge({ from: fileNode.id, to: sectionNode.id, relationship: 'references', confidence: 'high' })
    if (tags.includes('high_entropy')) {
      const blobNode = node({
        id: `blob:${section.name}:${section.rawOffset ?? section.virtualAddress ?? section.name}`,
        type: 'data_blob',
        label: `${section.name} high entropy region`,
        confidence: 'high',
        evidence: [`section ${section.name} entropy=${section.entropy}`],
        tags: ['high_entropy', 'encrypted_data', 'blob', 'decode_input_candidate'],
        metadata: { section: section.name, rawOffset: section.rawOffset, rawSize: section.rawSize }
      })
      addNode(blobNode)
      addEdge({ from: sectionNode.id, to: blobNode.id, relationship: 'references', confidence: 'high' })
    }
  }

  const flattenedImports = input.imports.flatMap((entry) => entry.symbols.map((symbol) => `${entry.library}!${symbol}`))
  for (const importName of flattenedImports.filter((name) => SUSPICIOUS_PROTECTION_API.test(name)).slice(0, 200)) {
    const importNode = node({
      id: `import:${importName}`,
      type: 'import',
      label: importName,
      confidence: 'high',
      evidence: [apiEvidence(importName)],
      tags: apiTags(importName)
    })
    addNode(importNode)
    addEdge({ from: fileNode.id, to: importNode.id, relationship: 'uses', confidence: 'high' })
  }

  for (const capability of input.capabilities) {
    const capabilityNode = node({
      id: `capability:${capability.capability}`,
      type: 'capability',
      label: capability.capability,
      confidence: capability.confidence,
      evidence: capability.evidence,
      tags: ['capability']
    })
    addNode(capabilityNode)
    for (const evidence of capability.evidence.slice(0, 10)) {
      const importId = `import:${evidence}`
      if (graph.nodes.some((item) => item.id === importId)) {
        addEdge({ from: importId, to: capabilityNode.id, relationship: 'uses', confidence: capability.confidence })
      }
    }
  }

  for (const entry of input.strings.slice(0, 1_000)) {
    const tags = stringProtectionTags(entry.value)
    if (!tags.length) continue
    const stringNode = node({
      id: `artifact:string:${entry.offset}`,
      type: 'artifact',
      label: entry.value.slice(0, 96),
      confidence: tags.includes('encoded_blob') || tags.includes('api_hash_hint') ? 'medium' : 'low',
      evidence: [`string at ${hex(entry.offset)}: ${entry.value.slice(0, 180)}`],
      tags: ['string', ...tags],
      metadata: { offset: entry.offset, encoding: entry.encoding }
    })
    addNode(stringNode)
    addEdge({ from: fileNode.id, to: stringNode.id, relationship: 'references', confidence: 'medium' })
  }

  for (const indicator of input.packerIndicators) {
    const indicatorNode = node({
      id: `artifact:packer:${slug(indicator.indicator)}`,
      type: 'artifact',
      label: indicator.indicator,
      confidence: indicator.confidence,
      evidence: indicator.evidence,
      tags: ['packer_indicator', 'protected_binary_indicator']
    })
    addNode(indicatorNode)
    addEdge({ from: fileNode.id, to: indicatorNode.id, relationship: 'correlates_with', confidence: indicator.confidence })
  }

  addGhidraEvidence(graph, input.ghidraEvidence)
  graph.stages = inferStages(graph)
  graph.knownUnknowns = knownUnknowns(graph, input.ghidraEvidence)
  graph.targets = rankReTargets(graph)
  return normalizeBehaviorGraph(graph)
}

function addGhidraEvidence(graph: ReBehaviorGraph, evidence: GhidraEvidencePack | undefined): void {
  if (!evidence) return
  const source = evidence.source ?? 'ghidra-mcp'
  for (const fn of evidence.functions ?? []) {
    const id = functionId(fn.address || fn.name || `unknown_${graph.nodes.length}`)
    const text = [fn.decompilerText, fn.disassemblyText, fn.summary].filter(Boolean).join('\n')
    const tags = functionTagsFromText(text, fn)
    const functionNode = node({
      id,
      type: 'function',
      label: fn.name || fn.address || id,
      confidence: tags.length ? 'medium' : 'low',
      source: [source],
      evidence: [
        ...(fn.signature ? [`signature=${fn.signature}`] : []),
        ...(fn.size ? [`size=${fn.size}`] : []),
        ...(fn.summary ? [fn.summary] : []),
        ...patternEvidenceFromText(text)
      ],
      tags,
      metadata: {
        address: fn.address,
        name: fn.name,
        signature: fn.signature,
        size: fn.size,
        callers: fn.callers,
        callees: fn.callees,
        xrefsTo: fn.xrefsTo,
        xrefsFrom: fn.xrefsFrom,
        stringsReferenced: fn.stringsReferenced,
        importsUsed: fn.importsUsed,
        constants: fn.constants
      }
    })
    graph.nodes.push(functionNode)
    for (const callee of fn.callees ?? []) {
      graph.edges.push({ from: functionNode.id, to: functionId(callee), relationship: 'calls', confidence: 'medium', evidence: ['Ghidra callee'] })
    }
    for (const caller of fn.callers ?? []) {
      graph.edges.push({ from: functionId(caller), to: functionNode.id, relationship: 'calls', confidence: 'medium', evidence: ['Ghidra caller'] })
    }
    for (const xref of fn.xrefsTo ?? []) {
      const from = normalizeArtifactId(xref)
      graph.edges.push({
        from,
        to: functionNode.id,
        relationship: from.startsWith('blob:') ? 'read_by' : 'references',
        confidence: 'medium',
        evidence: ['Ghidra xref-to']
      })
    }
    for (const xref of fn.xrefsFrom ?? []) {
      graph.edges.push({ from: functionNode.id, to: normalizeArtifactId(xref), relationship: 'references', confidence: 'medium', evidence: ['Ghidra xref-from'] })
    }
    for (const importName of fn.importsUsed ?? []) {
      graph.edges.push({ from: functionNode.id, to: `import:${importName}`, relationship: 'uses', confidence: 'medium', evidence: ['Ghidra function import usage'] })
    }
  }
  for (const xref of evidence.xrefs ?? []) {
    const from = normalizeGhidraXrefEndpoint(xref.from, evidence)
    const to = normalizeGhidraXrefEndpoint(xref.to, evidence)
    graph.edges.push({
      from,
      to,
      relationship: ghidraXrefRelationship(xref.kind, from, to),
      confidence: 'medium',
      evidence: xref.evidence ? [xref.evidence] : ['Ghidra xref']
    })
  }
}

function normalizeGhidraXrefEndpoint(value: string, evidence: GhidraEvidencePack): string {
  const trimmed = value.trim()
  for (const fn of evidence.functions ?? []) {
    if (fn.address && trimmed === fn.address) return functionId(fn.address)
    if (fn.name && trimmed === fn.name) return functionId(fn.address || fn.name)
    if (fn.address && trimmed === functionId(fn.address)) return functionId(fn.address)
    if (fn.name && trimmed === functionId(fn.name)) return functionId(fn.address || fn.name)
  }
  return normalizeArtifactId(trimmed)
}

function ghidraXrefRelationship(
  kind: string | undefined,
  from: string,
  to: string
): ReBehaviorGraphEdge['relationship'] {
  if (/call/i.test(kind ?? '')) return 'calls'
  if (/write/i.test(kind ?? '')) return 'writes_to'
  if (/read/i.test(kind ?? '') && from.startsWith('blob:') && to.startsWith('func:')) return 'read_by'
  return 'references'
}

export function rankReTargets(graph: ReBehaviorGraph): ReTargetRank[] {
  const targets = graph.nodes
    .map((node) => {
      const reasons = targetReasons(node, graph)
      const score = scoreNode(node, graph, reasons)
      if (score <= 0) return null
      return {
        id: node.id,
        rank: 0,
        label: node.label,
        confidence: node.confidence,
        score,
        sources: node.source,
        reasons,
        recommendedAction: recommendedAction(node, reasons)
      } satisfies ReTargetRank
    })
    .filter((target): target is ReTargetRank => target !== null)
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .slice(0, 100)
  return targets.map((target, index) => ({ ...target, rank: index + 1 }))
}

function buildProtectionFindings(graph: ReBehaviorGraph): ReProtectionFinding[] {
  const findings: ReProtectionFinding[] = []
  const nodesByTag = (tag: string) => graph.nodes.filter((node) => node.tags.includes(tag))
  addFinding(findings, {
    category: 'packer',
    label: 'High-entropy or packed region indicators',
    confidence: nodesByTag('high_entropy').length >= 2 ? 'high' : nodesByTag('high_entropy').length ? 'medium' : 'low',
    evidence: nodesByTag('high_entropy').flatMap((node) => node.evidence).slice(0, 20),
    relatedNodes: nodesByTag('high_entropy').map((node) => node.id)
  })
  addFinding(findings, {
    category: 'self_modifying',
    label: 'Suspicious memory permission or self-modifying indicators',
    confidence: nodesByTag('memory_permission').length || nodesByTag('rwx_or_write_exec').length ? 'medium' : 'low',
    evidence: [...nodesByTag('memory_permission'), ...nodesByTag('rwx_or_write_exec')].flatMap((node) => node.evidence).slice(0, 20),
    relatedNodes: [...nodesByTag('memory_permission'), ...nodesByTag('rwx_or_write_exec')].map((node) => node.id)
  })
  addFinding(findings, {
    category: 'dynamic_api_resolution',
    label: 'Dynamic API resolution or import hashing indicators',
    confidence: nodesByTag('dynamic_api_resolution').length || nodesByTag('api_hash_hint').length ? 'medium' : 'low',
    evidence: [...nodesByTag('dynamic_api_resolution'), ...nodesByTag('api_hash_hint')].flatMap((node) => node.evidence).slice(0, 20),
    relatedNodes: [...nodesByTag('dynamic_api_resolution'), ...nodesByTag('api_hash_hint')].map((node) => node.id)
  })
  addFinding(findings, {
    category: 'decode',
    label: 'Decrypt/decode loop or encoded artifact indicators',
    confidence: nodesByTag('decode_loop_candidate').length || nodesByTag('encoded_blob').length ? 'medium' : 'low',
    evidence: [...nodesByTag('decode_loop_candidate'), ...nodesByTag('encoded_blob'), ...nodesByTag('decode_input_candidate')].flatMap((node) => node.evidence).slice(0, 30),
    relatedNodes: [...nodesByTag('decode_loop_candidate'), ...nodesByTag('encoded_blob'), ...nodesByTag('decode_input_candidate')].map((node) => node.id)
  })
  addFinding(findings, {
    category: 'virtualization',
    label: 'VM dispatcher, handler, or bytecode interpreter indicators',
    confidence: nodesByTag('vm_dispatcher_candidate').length ? 'medium' : 'low',
    evidence: [...nodesByTag('vm_dispatcher_candidate'), ...nodesByTag('handler_candidate'), ...nodesByTag('bytecode_candidate')].flatMap((node) => node.evidence).slice(0, 30),
    relatedNodes: [...nodesByTag('vm_dispatcher_candidate'), ...nodesByTag('handler_candidate'), ...nodesByTag('bytecode_candidate')].map((node) => node.id)
  })
  addFinding(findings, {
    category: 'anti_analysis',
    label: 'Anti-debug or anti-VM indicators',
    confidence: nodesByTag('anti_debug').length || nodesByTag('anti_vm').length ? 'medium' : 'low',
    evidence: [...nodesByTag('anti_debug'), ...nodesByTag('anti_vm')].flatMap((node) => node.evidence).slice(0, 20),
    relatedNodes: [...nodesByTag('anti_debug'), ...nodesByTag('anti_vm')].map((node) => node.id)
  })
  addFinding(findings, {
    category: 'indirect_control_flow',
    label: 'Indirect control flow indicators',
    confidence: nodesByTag('indirect_control_flow').length ? 'medium' : 'low',
    evidence: nodesByTag('indirect_control_flow').flatMap((node) => node.evidence).slice(0, 20),
    relatedNodes: nodesByTag('indirect_control_flow').map((node) => node.id)
  })
  return findings.filter((finding) => finding.evidence.length || finding.relatedNodes.length)
}

function addFinding(findings: ReProtectionFinding[], finding: ReProtectionFinding): void {
  if (finding.evidence.length || finding.relatedNodes.length) findings.push(finding)
}

function inferStages(graph: ReBehaviorGraph): ReBehaviorStage[] {
  const stage1 = graph.nodes.filter((node) =>
    node.tags.some((tag) => ['packer_indicator', 'memory_permission', 'rwx_or_write_exec'].includes(tag))
  ).map((node) => node.id)
  const stage2 = graph.nodes.filter((node) =>
    node.tags.some((tag) => ['decode_loop_candidate', 'decode_input_candidate', 'encoded_blob', 'dynamic_api_resolution'].includes(tag))
  ).map((node) => node.id)
  const stage3 = graph.nodes.filter((node) =>
    node.type === 'capability' || node.tags.includes('consumer') || node.tags.includes('capability')
  ).map((node) => node.id)
  const stages: ReBehaviorStage[] = []
  if (stage1.length) stages.push({ id: 'stage_1', label: 'possible_unpacking_or_loader_stage', confidence: 'medium', nodes: stage1, evidence: ['packer/memory permission indicators'] })
  if (stage2.length) stages.push({ id: 'stage_2', label: 'possible_decode_or_api_resolution_stage', confidence: 'medium', nodes: stage2, evidence: ['decode/API-resolution indicators'] })
  if (stage3.length) stages.push({ id: 'stage_3', label: 'possible_behavior_execution_stage', confidence: 'low', nodes: stage3, evidence: ['capability and consumer indicators'] })
  return stages
}

function targetReasons(node: ReBehaviorGraphNode, graph: ReBehaviorGraph): string[] {
  const reasons: string[] = []
  if (node.tags.includes('high_entropy')) reasons.push('high entropy region or blob')
  if (node.tags.includes('decode_loop_candidate')) reasons.push('contains decode/decrypt loop evidence')
  if (node.tags.includes('dynamic_api_resolution')) reasons.push('dynamic API resolution evidence')
  if (node.tags.includes('memory_permission')) reasons.push('suspicious memory permission transition evidence')
  if (node.tags.includes('vm_dispatcher_candidate')) reasons.push('VM dispatcher or bytecode interpreter evidence')
  if (node.tags.includes('handler_candidate')) reasons.push('possible VM handler cluster member')
  if (node.tags.includes('indirect_control_flow')) reasons.push('indirect control flow evidence')
  if (node.tags.includes('anti_debug')) reasons.push('anti-debug evidence')
  if (node.tags.includes('anti_vm')) reasons.push('anti-VM evidence')
  if (node.tags.includes('api_hash_hint')) reasons.push('import hashing or hash-constant hint')
  const incoming = graph.edges.filter((edge) => edge.to === node.id).length
  const outgoing = graph.edges.filter((edge) => edge.from === node.id).length
  if (incoming + outgoing >= 5) reasons.push('high graph connectivity')
  if (node.source.includes('ghidra-mcp')) reasons.push('Ghidra MCP function-level evidence')
  if (node.evidence.some((item) => /xref/i.test(item))) reasons.push('Ghidra xref evidence')
  return unique(reasons)
}

function scoreNode(node: ReBehaviorGraphNode, graph: ReBehaviorGraph, reasons: string[]): number {
  let score = 0
  score += confidenceScore(node.confidence)
  score += reasons.length * 8
  score += node.source.includes('ghidra-mcp') ? 12 : 0
  score += Math.min(20, graph.edges.filter((edge) => edge.from === node.id || edge.to === node.id).length * 3)
  if (node.type === 'function') score += 15
  if (node.tags.includes('decode_loop_candidate')) score += 18
  if (node.tags.includes('vm_dispatcher_candidate')) score += 20
  if (node.tags.includes('dynamic_api_resolution')) score += 14
  if (node.tags.includes('high_entropy')) score += 10
  return Math.min(100, score)
}

function recommendedAction(node: ReBehaviorGraphNode, reasons: string[]): string {
  if (node.tags.includes('vm_dispatcher_candidate')) {
    return 'Use Ghidra MCP to pull decompiler, disassembly, callers/callees, xrefs, and nearby handler-table references; map dispatcher -> handlers -> bytecode.'
  }
  if (node.tags.includes('decode_loop_candidate') || node.tags.includes('high_entropy')) {
    return 'Trace xrefs from high-entropy inputs into decoder candidates, then trace output buffers to consumers and decoded artifacts.'
  }
  if (node.tags.includes('dynamic_api_resolution')) {
    return 'Inspect export-table walking/hash loops, recover hash algorithm/constants, and connect resolved function pointers to capability nodes.'
  }
  if (reasons.some((reason) => /Ghidra/.test(reason))) {
    return 'Pull the smallest relevant Ghidra context pack and save normalized function summary/comments if supported.'
  }
  return 'Inspect xrefs, callers/callees, strings, imports, and section context; update the behavior graph with confirmed relationships.'
}

function scoreProtection(findings: ReProtectionFinding[], graph: ReBehaviorGraph): number {
  let score = 0
  for (const finding of findings) {
    score += confidenceScore(finding.confidence)
    score += Math.min(20, finding.evidence.length * 3)
  }
  score += graph.nodes.some((node) => node.tags.includes('vm_dispatcher_candidate')) ? 20 : 0
  score += graph.nodes.some((node) => node.tags.includes('dynamic_api_resolution')) ? 12 : 0
  score += graph.nodes.some((node) => node.tags.includes('decode_loop_candidate')) ? 14 : 0
  return Math.min(100, score)
}

function summarizeProtection(findings: ReProtectionFinding[], graph: ReBehaviorGraph, score: number): string {
  const top = findings.slice(0, 5).map((finding) => `${finding.label} (${finding.confidence})`).join('; ')
  const ghidra = graph.nodes.some((node) => node.source.includes('ghidra-mcp')) ? ' Ghidra MCP evidence is included.' : ' No Ghidra MCP function-level evidence is included.'
  return `Protection score ${score}/100. ${top || 'No strong protected-binary indicators were confirmed by the current heuristics.'}${ghidra}`
}

function recommendProtectedNextActions(input: {
  ghidraEvidence?: GhidraEvidencePack
  dispatcherVmCandidates: ReTargetRank[]
  decryptDecodeCandidates: ReTargetRank[]
  dynamicApiResolution: ReProtectionFinding[]
  highEntropyRegions: ReBehaviorGraphNode[]
}): string[] {
  const actions: string[] = []
  if (!input.ghidraEvidence) {
    actions.push('If Ghidra MCP is connected, run re_ghidra_status and pull xrefs/decompiler context for top-ranked targets.')
  }
  if (input.highEntropyRegions.length) {
    actions.push('Trace readers of high-entropy regions and connect decoder outputs to consumers.')
  }
  if (input.decryptDecodeCandidates.length) {
    actions.push('Decompile top decode candidates and search for XOR/add/sub/rol/ror loops and output buffer consumers.')
  }
  if (input.dispatcherVmCandidates.length) {
    actions.push('Map dispatcher candidates to handler-like callees, handler tables, bytecode buffers, and indirect branches.')
  }
  if (input.dynamicApiResolution.length) {
    actions.push('Recover API resolver/hash logic and connect resolved APIs to capability categories.')
  }
  actions.push('Update .re-mode/behavior-graph.json as relationships are confirmed or disproven.')
  return unique(actions)
}

function knownUnknowns(graph: ReBehaviorGraph, ghidraEvidence?: GhidraEvidencePack): string[] {
  const unknowns: string[] = []
  if (!ghidraEvidence) {
    unknowns.push('Function-level decompiler/xref/call graph evidence is unavailable until Ghidra MCP or equivalent context is provided.')
  }
  if (!graph.edges.some((edge) => edge.relationship === 'decodes_to')) {
    unknowns.push('No decoder output-to-consumer relationship has been confirmed yet.')
  }
  if (graph.nodes.some((node) => node.tags.includes('high_entropy')) && !graph.edges.some((edge) => edge.relationship === 'read_by')) {
    unknowns.push('High-entropy regions need reader xrefs to confirm decoder candidates.')
  }
  return unknowns
}

function mergeBehaviorGraph(base: ReBehaviorGraph, patch: ReBehaviorGraph): ReBehaviorGraph {
  const nodes = new Map<string, ReBehaviorGraphNode>()
  for (const nodeItem of [...base.nodes, ...patch.nodes]) {
    const existing = nodes.get(nodeItem.id)
    nodes.set(nodeItem.id, existing ? mergeNode(existing, nodeItem) : nodeItem)
  }
  const edgeKeys = new Set<string>()
  const edges: ReBehaviorGraphEdge[] = []
  for (const edge of [...base.edges, ...patch.edges]) {
    const key = `${edge.from}|${edge.relationship}|${edge.to}`
    if (edgeKeys.has(key)) continue
    edgeKeys.add(key)
    edges.push(edge)
  }
  const stages = mergeStages([...base.stages, ...patch.stages])
  return normalizeBehaviorGraph({
    version: 1,
    sample: patch.sample ?? base.sample,
    updatedAt: new Date().toISOString(),
    nodes: [...nodes.values()],
    edges,
    stages,
    targets: patch.targets.length ? patch.targets : base.targets,
    knownUnknowns: unique([...(base.knownUnknowns ?? []), ...(patch.knownUnknowns ?? [])])
  })
}

function mergeNode(a: ReBehaviorGraphNode, b: ReBehaviorGraphNode): ReBehaviorGraphNode {
  return {
    ...a,
    ...b,
    confidence: confidenceRank(b.confidence) >= confidenceRank(a.confidence) ? b.confidence : a.confidence,
    source: unique([...a.source, ...b.source]),
    evidence: unique([...a.evidence, ...b.evidence]).slice(0, 100),
    tags: unique([...a.tags, ...b.tags]),
    metadata: { ...(a.metadata ?? {}), ...(b.metadata ?? {}) }
  }
}

function mergeStages(stages: ReBehaviorStage[]): ReBehaviorStage[] {
  const map = new Map<string, ReBehaviorStage>()
  for (const stage of stages) {
    const existing = map.get(stage.id)
    map.set(stage.id, existing ? {
      ...existing,
      ...stage,
      nodes: unique([...existing.nodes, ...stage.nodes]),
      evidence: unique([...(existing.evidence ?? []), ...(stage.evidence ?? [])]),
      confidence: confidenceRank(stage.confidence) >= confidenceRank(existing.confidence) ? stage.confidence : existing.confidence
    } : stage)
  }
  return [...map.values()]
}

function compactGraphForModel(graph: ReBehaviorGraph): ReBehaviorGraph {
  const nodeIds = new Set(graph.targets.slice(0, 40).map((target) => target.id))
  for (const stage of graph.stages) {
    for (const id of stage.nodes.slice(0, 20)) nodeIds.add(id)
  }
  const nodes = graph.nodes.filter((nodeItem) => nodeIds.has(nodeItem.id)).slice(0, 80)
  const ids = new Set(nodes.map((nodeItem) => nodeItem.id))
  return {
    ...graph,
    nodes,
    edges: graph.edges.filter((edge) => ids.has(edge.from) && ids.has(edge.to)).slice(0, 120),
    targets: graph.targets.slice(0, 30),
    knownUnknowns: graph.knownUnknowns.slice(0, 20)
  }
}

function normalizeBehaviorGraph(raw: unknown): ReBehaviorGraph {
  if (!raw || typeof raw !== 'object') return emptyBehaviorGraph()
  const input = raw as Partial<ReBehaviorGraph>
  return {
    version: 1,
    ...(typeof input.sample === 'string' ? { sample: input.sample } : {}),
    updatedAt: typeof input.updatedAt === 'string' ? input.updatedAt : new Date().toISOString(),
    nodes: Array.isArray(input.nodes) ? input.nodes.map(normalizeNode).filter(Boolean) as ReBehaviorGraphNode[] : [],
    edges: Array.isArray(input.edges) ? input.edges.map(normalizeEdge).filter(Boolean) as ReBehaviorGraphEdge[] : [],
    stages: Array.isArray(input.stages) ? input.stages.map(normalizeStage).filter(Boolean) as ReBehaviorStage[] : [],
    targets: Array.isArray(input.targets) ? input.targets.map(normalizeTarget).filter(Boolean) as ReTargetRank[] : [],
    knownUnknowns: Array.isArray(input.knownUnknowns) ? input.knownUnknowns.filter((item): item is string => typeof item === 'string') : []
  }
}

function normalizeNode(raw: unknown): ReBehaviorGraphNode | null {
  if (!raw || typeof raw !== 'object') return null
  const input = raw as Partial<ReBehaviorGraphNode>
  if (!input.id || !input.label) return null
  return node({
    id: input.id,
    type: input.type ?? 'unknown',
    label: input.label,
    confidence: normalizeConfidence(input.confidence),
    source: Array.isArray(input.source) ? input.source.filter((item): item is string => typeof item === 'string') : ['local-re'],
    evidence: Array.isArray(input.evidence) ? input.evidence.filter((item): item is string => typeof item === 'string') : [],
    tags: Array.isArray(input.tags) ? input.tags.filter((item): item is string => typeof item === 'string') : [],
    ...(typeof input.score === 'number' ? { score: input.score } : {}),
    ...(input.metadata && typeof input.metadata === 'object' ? { metadata: input.metadata } : {})
  })
}

function normalizeEdge(raw: unknown): ReBehaviorGraphEdge | null {
  if (!raw || typeof raw !== 'object') return null
  const input = raw as Partial<ReBehaviorGraphEdge>
  if (!input.from || !input.to || !input.relationship) return null
  return {
    from: input.from,
    to: input.to,
    relationship: input.relationship,
    ...(Array.isArray(input.evidence) ? { evidence: input.evidence.filter((item): item is string => typeof item === 'string') } : {}),
    ...(input.confidence ? { confidence: normalizeConfidence(input.confidence) } : {})
  }
}

function normalizeStage(raw: unknown): ReBehaviorStage | null {
  if (!raw || typeof raw !== 'object') return null
  const input = raw as Partial<ReBehaviorStage>
  if (!input.id || !input.label) return null
  return {
    id: input.id,
    label: input.label,
    confidence: normalizeConfidence(input.confidence),
    nodes: Array.isArray(input.nodes) ? input.nodes.filter((item): item is string => typeof item === 'string') : [],
    ...(Array.isArray(input.evidence) ? { evidence: input.evidence.filter((item): item is string => typeof item === 'string') } : {})
  }
}

function normalizeTarget(raw: unknown): ReTargetRank | null {
  if (!raw || typeof raw !== 'object') return null
  const input = raw as Partial<ReTargetRank>
  if (!input.id || !input.label) return null
  return {
    id: input.id,
    rank: Number(input.rank ?? 0),
    label: input.label,
    confidence: normalizeConfidence(input.confidence),
    score: Number(input.score ?? 0),
    sources: Array.isArray(input.sources) ? input.sources.filter((item): item is string => typeof item === 'string') : [],
    reasons: Array.isArray(input.reasons) ? input.reasons.filter((item): item is string => typeof item === 'string') : [],
    recommendedAction: input.recommendedAction ?? ''
  }
}

function node(input: Omit<ReBehaviorGraphNode, 'source'> & { source?: string[] }): ReBehaviorGraphNode {
  return {
    ...input,
    source: input.source?.length ? unique(input.source) : ['local-re'],
    evidence: unique(input.evidence).slice(0, 100),
    tags: unique(input.tags)
  }
}

function apiEvidence(importName: string): string {
  if (/VirtualProtect|NtProtectVirtualMemory|VirtualAlloc/i.test(importName)) return 'memory permission or allocation API'
  if (/LoadLibrary|GetProcAddress|LdrGetProcedureAddress/i.test(importName)) return 'dynamic API resolution API'
  if (/IsDebuggerPresent|NtQueryInformationProcess|CheckRemoteDebuggerPresent/i.test(importName)) return 'anti-debug API'
  if (/WriteProcessMemory|CreateRemoteThread/i.test(importName)) return 'injection or unpacking-related API'
  return 'suspicious protected-binary API'
}

function apiTags(importName: string): string[] {
  const tags = ['api']
  if (/VirtualProtect|NtProtectVirtualMemory|VirtualAlloc/i.test(importName)) tags.push('memory_permission', 'self_modifying_candidate')
  if (/LoadLibrary|GetProcAddress|LdrGetProcedureAddress/i.test(importName)) tags.push('dynamic_api_resolution')
  if (/IsDebuggerPresent|NtQueryInformationProcess|CheckRemoteDebuggerPresent|OutputDebugString/i.test(importName)) tags.push('anti_debug')
  if (/WriteProcessMemory|CreateRemoteThread/i.test(importName)) tags.push('injection', 'unpacking_candidate')
  return tags
}

function stringProtectionTags(value: string): string[] {
  const tags: string[] = []
  if (BASE64_LIKE.test(value) || HEX_LIKE.test(value)) tags.push('encoded_blob', 'decoded_artifact_candidate')
  if (/UPX|VMProtect|Themida|Enigma|ASProtect|MPress|Obsidium/i.test(value)) tags.push('packer_marker')
  if (/GetProcAddress|LoadLibrary|LdrGetProcedureAddress|PEB|TEB|Export Directory/i.test(value)) tags.push('dynamic_api_resolution')
  if (/IsDebuggerPresent|NtQueryInformationProcess|CheckRemoteDebuggerPresent|debugger|ptrace/i.test(value)) tags.push('anti_debug')
  if (/VirtualBox|VMware|QEMU|sandbox|vbox/i.test(value)) tags.push('anti_vm')
  if (/opcode|dispatch|handler|bytecode|vm_/i.test(value)) tags.push('bytecode_candidate', 'vm_dispatcher_candidate')
  return tags
}

function functionTagsFromText(text: string, fn: NonNullable<GhidraEvidencePack['functions']>[number]): string[] {
  const tags: string[] = ['function']
  if (/xor|rol|ror|\^|<<|>>|rotate|decode|decrypt|base64|inflate|deflate/i.test(text)) tags.push('decode_loop_candidate')
  if (/switch|case|opcode|dispatch|handler|bytecode|while\s*\(|for\s*\(/i.test(text) && /goto|switch|case|\*\w+|indirect|computed/i.test(text)) {
    tags.push('vm_dispatcher_candidate', 'indirect_control_flow')
  }
  if (/GetProcAddress|LoadLibrary|LdrGetProcedureAddress|IMAGE_EXPORT_DIRECTORY|AddressOfNames|AddressOfFunctions|PEB|TEB/i.test(text)) {
    tags.push('dynamic_api_resolution', 'import_hashing_candidate')
  }
  if (/VirtualProtect|NtProtectVirtualMemory|VirtualAlloc|PAGE_EXECUTE|PAGE_READWRITE/i.test(text)) tags.push('memory_permission', 'self_modifying_candidate')
  if (/IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|rdtsc|QueryPerformanceCounter/i.test(text)) tags.push('anti_debug')
  if ((fn.callees?.length ?? 0) > 20 || (fn.callers?.length ?? 0) > 20) tags.push('callgraph_hub')
  if ((fn.size ?? 0) > 1200 && tags.includes('indirect_control_flow')) tags.push('control_flow_flattening_candidate')
  return tags
}

function patternEvidenceFromText(text: string): string[] {
  const evidence: string[] = []
  if (/xor|\^/i.test(text)) evidence.push('xor-like operation present')
  if (/rol|ror|rotate|<<|>>/i.test(text)) evidence.push('rotate/shift-like operation present')
  if (/switch|case|opcode/i.test(text)) evidence.push('switch/opcode-like dispatch present')
  if (/goto|indirect|\*\w+/i.test(text)) evidence.push('indirect control-flow hint present')
  if (/GetProcAddress|LoadLibrary|LdrGetProcedureAddress/i.test(text)) evidence.push('dynamic API resolution call present')
  if (/IMAGE_EXPORT_DIRECTORY|AddressOfNames|AddressOfFunctions/i.test(text)) evidence.push('export table walking evidence')
  if (/VirtualProtect|NtProtectVirtualMemory|VirtualAlloc/i.test(text)) evidence.push('memory permission/allocation API present')
  return evidence
}

function summarizeGhidraEvidence(evidence: GhidraEvidencePack | undefined): string[] {
  if (!evidence) return ['Ghidra MCP evidence unavailable.']
  const out = [
    `Ghidra evidence source: ${evidence.source ?? 'ghidra-mcp'}`,
    `Functions summarized: ${evidence.functions?.length ?? 0}`,
    `Xrefs summarized: ${evidence.xrefs?.length ?? 0}`
  ]
  out.push(...(evidence.notes ?? []).slice(0, 20))
  return out
}

function normalizeArtifactId(value: string): string {
  const trimmed = value.trim()
  if (/^func:/i.test(trimmed) || /^blob:/i.test(trimmed) || /^section:/i.test(trimmed) || /^import:/i.test(trimmed)) return trimmed
  if (/^0x[0-9a-f]+$/i.test(trimmed)) return `artifact:${trimmed}`
  return `artifact:${slug(trimmed)}`
}

function functionId(value: string): string {
  const trimmed = value.trim()
  return /^func:/i.test(trimmed) ? trimmed : `func:${trimmed}`
}

function confidenceScore(value: ReConfidence): number {
  return value === 'high' ? 30 : value === 'medium' ? 18 : 8
}

function confidenceRank(value: ReConfidence): number {
  return value === 'high' ? 3 : value === 'medium' ? 2 : 1
}

function normalizeConfidence(value: unknown): ReConfidence {
  return value === 'high' || value === 'medium' || value === 'low' ? value : 'low'
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.trim()).map((value) => value.trim()))]
}

function slug(value: string): string {
  return value.trim().toLowerCase().replace(/[^a-z0-9_.:-]+/g, '_').replace(/^_+|_+$/g, '') || 'unknown'
}

function sanitizeFileName(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 120)
}

function normalizePath(value: string): string {
  return value.replaceAll('\\', '/')
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function hex(value: number): string {
  return `0x${Math.max(0, Math.floor(value)).toString(16)}`
}

const UNUSUAL_SECTION_NAME = /UPX|vmp|themida|aspack|mpress|petite|enigma|\.packed|\.adata|\.ndata/i
const SUSPICIOUS_PROTECTION_API = /VirtualProtect|NtProtectVirtualMemory|VirtualAlloc|LoadLibrary|GetProcAddress|LdrGetProcedureAddress|WriteProcessMemory|CreateRemoteThread|IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugString/i
const BASE64_LIKE = /^[A-Za-z0-9+/]{32,}={0,2}$/
const HEX_LIKE = /^(?:0x)?[A-Fa-f0-9]{40,}$/
