# Reverse Engineering Mode

[English](./re-mode.md) | 中文

Reverse Engineering Mode（RE Mode）把 Kun 扩展为面向二进制分析的工作台。它不是单纯的提示词模式，而是包含专用 prompt、RE 工具、`.re-mode/` 工作区产物、受保护二进制启发式分析和可选 Ghidra MCP 工作流的独立模式。

RE Mode 的目标是先做快速 triage，再进入函数级分析。它会把大体量原始输出保存在磁盘上，只把高价值摘要、地址、哈希、字符串、IOC、证据关系和候选目标交给模型。

## 启用 RE Mode

在工作区模式切换器中打开 **Reverse Engineering**。从该入口创建的新会话会使用 `re` 模式，Kun 会暴露 RE 专用工具并注入 RE Mode 指令。

右侧 RE 面板提供常用入口：

- Binary triage
- Protected analysis
- Crypto / decoders
- IOC extraction
- Patch diff
- Report generation

## 支持的本地分析

内置 helper 不依赖外部工具即可完成 MVP 级分析：

- PE、ELF、Mach-O、ZIP、APK、raw、unknown 文件识别
- 文件元数据与哈希
- PE 节区、导入、导出
- ELF 节区、导入、导出
- Mach-O segment / section 摘要
- APK / ZIP entry 摘要
- ASCII 与 UTF-16LE 字符串
- 总体熵与滚动窗口熵
- IOC 提取
- 能力分类
- 加壳与混淆线索
- 受保护二进制证据图
- Markdown 报告生成

这些分析是启发式的，输出应被视为 confidence-rated findings，而不是自动完成脱壳、反虚拟化或完整语义恢复。

## 可选外部工具

在 RE Mode 中运行 `re_tool_availability` 可以查看本机可用工具。当前会检测：

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

缺失工具不会阻塞 RE Mode。系统会降级到本地 helper、已保存的 `.re-mode/` 产物、通用 MCP 工具或用户提供的反编译/反汇编片段。

## Ghidra MCP-aware 工作流

RE Mode 是 Ghidra MCP-aware 的，但不强依赖 Ghidra。

如果连接了可信 Ghidra MCP server，RE Mode 可以把它作为高保真后端，用于：

- 当前打开的 program / project
- program metadata
- 函数列表与函数签名
- 反编译伪代码
- 反汇编
- callers / callees
- 地址、字符串、数据、函数的 xrefs
- symbols、labels、namespaces、imports、exports
- memory blocks / sections
- 字符串与数据引用
- 支持时进行 rename、comment、navigate
- call graph 与 data-flow hints

如果 Ghidra MCP 不可用，RE Mode 仍然可以用本地 helper 和 `.re-mode/` 产物完成 triage、IOC、entropy、capability、behavior graph、报告等工作，并会明确说明函数级能力的限制。

## `.re-mode/` 工作区产物

RE Mode 在当前工作区写入 sidecar 状态：

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

职责：

- `analysis.json`：当前样本、格式、哈希、节区、导入导出、字符串、熵、能力、加壳线索和建议目标。
- `symbols.json`：函数重命名、变量重命名、地址标签、符号置信度和函数备注。
- `iocs.json`：URL、domain、IP、email、注册表键、路径、命令、encoded blob、crypto constants 和 suspicious APIs。
- `notes.md`：人工可读分析笔记。
- `report.md`：生成的 Markdown 逆向分析报告。
- `behavior-graph.json`：用于保护/混淆分析的证据图。
- `raw/`：保留在磁盘上的原始工具输出。
- `raw/ghidra/`：Ghidra MCP 原始响应。
- `functions/`：标准化函数摘要。
- `diffs/`：二进制 diff 输出。

## 受保护 / 混淆二进制分析

示例 prompt：

```text
Analyze protection/obfuscation for this binary.
Find virtualization indicators and rank likely dispatcher candidates.
Build a behavior graph linking high-entropy blobs, decoders, and consumers.
Find dynamic API resolution and connect resolved APIs to capabilities.
Find staged unpacking/decryption flow.
Rank the top 10 functions to reverse first.
```

RE Mode 会寻找并关联这些候选证据：

- 高熵 section、segment、overlay、blob
- executable/writeable 或 RWX 权限
- 异常 section 名称
- 很小的导入表但行为线索丰富
- entrypoint stub 与 staged transition
- 可疑内存权限 API
- self-modifying / unpacking-like 行为
- decrypt / decode loop
- 运行时字符串、配置或代码解密
- dynamic API resolution
- import hashing
- export table walking
- PEB / TEB 访问
- anti-debug / anti-VM
- indirect calls / jumps
- control-flow flattening
- opaque predicates
- VM dispatcher
- VM handler cluster
- bytecode buffer

核心模型是行为/证据图：

```text
high_entropy_blob -> decoder_function -> decoded_artifact -> consumer_function -> capability
entrypoint_stub -> unpacking_region -> memory_permission_change -> transferred_execution
dispatcher -> handlers -> bytecode_blob -> virtualized_behavior_candidates
api_hash_loop -> resolved_function_table -> capability_cluster
```

证据图保存在 `.re-mode/behavior-graph.json`，包括 nodes、edges、stages、ranked targets 和 known unknowns。

## 函数级工作流

示例 prompt：

```text
Use Ghidra to explain function 0x1400129A0.
Use Ghidra xrefs to trace consumers of this decoded string.
Pull the decompiled code for this candidate dispatcher.
Suggest better names for this decompiled function.
Use Ghidra MCP to rename likely config decoder functions.
Save this analysis as Ghidra comments if supported.
```

当 Ghidra MCP 可用时，RE Mode 应只拉取当前问题需要的最小上下文：

- 函数 metadata
- signature
- 反编译摘要
- 反汇编摘要
- callers / callees
- xrefs
- imports used
- strings referenced
- constants

标准化函数摘要会保存到 `.re-mode/functions/`。

## 报告生成

示例 prompt：

```text
Generate RE report.
```

报告保存到 `.re-mode/report.md`，包含样本元数据、哈希、格式架构、静态分析摘要、节区与熵、导入导出、字符串、能力、IOC、函数分析、保护/混淆发现、假设、置信度、限制和下一步建议。

## 限制

- 本地 helper 是启发式实现，不会自动完成完整脱壳、反虚拟化或仿真。
- PE / ELF / Mach-O 解析是 MVP 级实现，可继续接入 LIEF、rizin、radare2 或 Ghidra 后端增强。
- 没有 Ghidra MCP、其他反编译后端或用户提供片段时，函数级分析能力有限。
- 保护/混淆标签是候选判断，需要人工复核。
