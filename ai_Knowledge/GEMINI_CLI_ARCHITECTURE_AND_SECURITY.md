# Gemini CLI (CodeAgent) 技术架构与安全指南

本指南基于对 Gemini CLI 源代码的逆向工程分析，旨在深度解析其核心运行机制、安全策略及用户配置系统。

## 1. 运行模式深度解析 (Modes & Implementation)

Gemini CLI 的安全核心在于其 **Policy Engine (策略引擎)**，该引擎通过加载不同模式的 TOML 配置文件来决定工具调用的权限。

核心枚举 `ApprovalMode` 定义了四种基础模式：
- 代码定义：[types.ts](packages/core/src/policy/types.ts#L44)

### 1.1 模式实现原理与策略映射

| 模式 (Mode) | 描述 | 核心策略文件 | 实现机制 |
| :--- | :--- | :--- | :--- |
| **Plan Mode**<br>(规划模式) | **只读安全模式**。<br>用于纯粹的代码阅读和任务规划，禁止任何副作用。 | [plan.toml](packages/core/src/policy/policies/plan.toml) | **Deny All Write**: 设置了优先级为 20 的全局 `DENY` 规则。<br>**Allow Read**: 显式允许 `glob`, `read_file`, `search_file_content` 等读取工具 (Priority 50)。<br>代码逻辑：`modes = ["plan"]` 标签激活这些规则。 |
| **Default Mode**<br>(默认模式) | **人机协作模式**。<br>默认启动模式，强调“最小权限”和“用户确认”。 | [write.toml](packages/core/src/policy/policies/write.toml) | **Ask User**: 敏感操作如 `write_file`, `run_shell_command`, `replace` 默认为 `ask_user` (Priority 10)。<br>这意味着任何修改都需要用户在 UI 上点击确认。 |
| **AutoEdit Mode**<br>(自动编辑模式) | **高效编码模式**。<br>允许 AI 自动修改文件，适用于重构或代码生成场景。 | [write.toml](packages/core/src/policy/policies/write.toml) | **Auto Allow**: 在 `write.toml` 中，针对 `replace` 和 `write_file` 工具定义了特定规则：<br>`decision = "allow"`<br>`priority = 15`<br>`modes = ["autoEdit"]`<br>当此模式激活时，Priority 15 的规则会覆盖 Default 的 Priority 10 规则。 |
| **Yolo Mode**<br>(狂飙模式) | **全自动模式**。<br>用于 CI/CD 或受信任环境，极少干预。 | [yolo.toml](packages/core/src/policy/policies/yolo.toml) | **Global Allow**: 定义了一个极其激进的规则：<br>`decision = "allow"`<br>`priority = 999`<br>`modes = ["yolo"]`<br>此高优先级规则几乎覆盖所有限制，除了系统级强制黑名单。 |

### 1.2 Shell Mode (命令行交互模式)

**Shell Mode** 并非一个独立的 `ApprovalMode`，而是一种 **UI 交互状态**。

- **触发方式**：用户输入以 `!` 开头，或在 UI 切换到 Shell 模式。
- **底层实现**：输入被解析后，实际上是调用了 `run_shell_command` 工具。
- **权限控制**：它完全受当前激活的 `ApprovalMode` (如 Default 或 Yolo) 约束。
  - 在 **Default Mode** 下，Shell 命令会触发 `ASK_USER`。
  - 在 **Yolo Mode** 下，Shell 命令通常会自动执行。
- **代码证据**：
  - Shell 处理器：[shellProcessor.test.ts](packages/cli/src/services/prompt-processors/shellProcessor.test.ts#L231)
  - 策略检查：[policy-engine.ts](packages/core/src/policy/policy-engine.ts#L132) (专门的 `checkShellCommand` 方法)

### 1.3 策略加载机制

`loadPoliciesFromToml` 函数负责从文件系统加载策略，并根据当前的模式筛选规则。
- 代码入口：[toml-loader.ts](packages/core/src/policy/toml-loader.ts#L203)
- 关键逻辑：它会扫描 `policies/` 目录下的所有 `.toml` 文件，解析其中的 `modes` 字段。如果规则没有指定 `modes`，则对所有模式生效；如果指定了，则仅在当前模式匹配时生效。

## 2. 命令执行与权限控制 (Command Execution)

Gemini CLI 对命令执行（`run_shell_command`）实施了细粒度的控制。

### 2.1 黑/白名单机制

策略引擎不仅仅基于工具名称 (`toolName`)，还支持基于参数的正则匹配 (`argsPattern`)。

- **白名单 (Allow List)**：
  - 在 `AutoEdit` 或 `Yolo` 模式下，特定的工具被显式允许。
  - 例如 `replace` 工具在 `autoEdit` 模式下被允许：[write.toml](packages/core/src/policy/policies/write.toml#L33)
- **黑名单 (Deny List)**：
  - 系统支持通过 `decision = "deny"` 显式禁止特定命令。
  - 即使在 Yolo 模式下，用户配置的 `exclude` 工具也会被强制拒绝（代码逻辑在 `config.ts` 的优先级处理中体现）。
- **询问 (Ask User)**：
  - 大多数敏感操作的默认状态。
  - 发现的新工具（`discovered_tool_*`）默认被视为潜在危险，强制询问：[discovered.toml](packages/core/src/policy/policies/discovered.toml#L1)

### 2.2 Bash/Shell 命令拦截逻辑

`PolicyEngine` 包含专门针对 Shell 命令的解析逻辑：

1. **命令拆分**：`checkShellCommand` 会尝试解析复杂的 Shell 命令行（如 `echo hello && rm -rf /`）。
2. **逐个检查**：它将命令行拆分为子命令，并对每个子命令进行策略匹配。
3. **最严策略原则**：
   - 如果任意子命令匹配到 `DENY`，整体 **DENY**。
   - 如果任意子命令匹配到 `ASK_USER`（且无更高优先级的 ALLOW），整体 **ASK_USER**。
   - 只有所有子命令都被 `ALLOW`，整体才 **ALLOW**。

代码参考：[policy-engine.ts](packages/core/src/policy/policy-engine.ts#L213) (`checkShellCommand` 方法)

## 3. 文件系统沙箱机制 (File System Sandbox)

为了防止 AI 意外或恶意访问敏感文件，Gemini CLI 实施了严格的文件系统沙箱。

### 3.1 核心原理：Allowed-Path Safety Checker

这是一个 `in-process` (进程内) 的安全检查器，名为 `allowed-path`。

- **代码实现**：[built-in.ts](packages/core/src/safety/built-in.ts#L20) (`AllowedPathChecker` 类)
- **工作机制**：
  1. **上下文获取**：从 `context.environment` 获取当前工作目录 (`cwd`) 和显式添加的工作区 (`workspaces`)。
  2. **路径解析**：使用 `path.resolve` 处理所有输入路径，解析 `..` 等相对路径，防御 **路径遍历 (Path Traversal)** 攻击。
  3. **前缀匹配**：检查目标路径是否位于允许的目录列表中。
  4. **决策**：如果路径在沙箱外，直接返回 `DENY`，并附带拒绝原因。

### 3.2 策略集成

该检查器被显式绑定到写操作工具上。例如在 `write.toml` 中：

```toml
[[rule]]
toolName = "write_file"
decision = "allow"
priority = 15
modes = ["autoEdit"]

[rule.safety_checker]
type = "in-process"
name = "allowed-path"
required_context = ["environment"]
```

这意味着，即使在 **AutoEdit Mode** 下允许了 `write_file`，它**必须**先通过 `allowed-path` 检查，否则会被拦截。这构成了纵深防御的关键一环。

## 4. 用户配置与扩展 (Configuration)

Gemini CLI 提供了灵活的三层配置系统，遵循 **Admin > User > Default** 的优先级。

### 4.1 配置入口

1. **CLI 参数** (运行时临时配置):
   - `--approval-mode <mode>`: 覆盖模式。
   - `--yolo`: 开启狂飙模式。
   - `--sandbox`: 强化沙箱。
   - 代码参考：[config.ts](packages/cli/src/config/config.ts#L138)

2. **配置文件** (持久化配置):
   - 用户策略目录：`~/.gemini/policies/*.toml`
   - 默认策略目录：`packages/core/src/policy/policies/*.toml`

3. **UI 交互** (动态配置):
   - 用户在 UI 弹窗中选择 "Always Allow" 会创建动态的高优先级规则。

### 4.2 优先级逻辑 (Priority Bands)

`config.ts` 中定义了复杂的优先级计算逻辑，确保层级压制：

- **Admin Policies (Tier 3)**: 基础分 `3.000` + TOML Priority / 1000
- **User Policies (Tier 2)**: 基础分 `2.000` + TOML Priority / 1000
- **Default Policies (Tier 1)**: 基础分 `1.000` + TOML Priority / 1000

**特殊的高优先级规则 (User Tier 2.x)**:
- `2.95`: UI 中 "Always Allow" 的工具。
- `2.9`: MCP Server 黑名单。
- `2.4`: CLI `--exclude-tools` 参数。
- `1.999`: YOLO Mode 的 Allow All 规则 (位于 Default Tier 的顶端)。

代码参考：[config.ts](packages/core/src/policy/config.ts#L99) (getPolicyTier)

## 5. 架构设计哲学 (Design Philosophy)

Gemini CLI 的设计哲学是在赋能 AI 与保护用户之间寻找平衡。

### 5.1 核心原则

1.  **纵深防御 (Defense in Depth)**:
    - 第一道防线：**Policy Engine** (规则拦截)。
    - 第二道防线：**Safety Checkers** (运行时路径/逻辑检查)。
    - 第三道防线：**OS Permissions** (文件系统 ACLs，如 `security.ts` 中的检查)。
    - 代码参考：[security.ts](packages/core/src/utils/security.ts#L17)

2.  **最小权限原则 (Least Privilege)**:
    - 默认模式 (`Default`) 对所有副作用操作（写、运行）保持 `ASK_USER` 状态。
    - `Plan Mode` 更是直接剥夺了写权限，仅保留读权限。

3.  **透明度与人机回环 (Transparency & Human-in-the-loop)**:
    - 系统不会“静默”执行危险操作。
    - 即使在允许模式下，通过 `allowed-path` 等机制确保 AI 不会越界操作非工作区文件。

### 5.2 灵活性与安全性的平衡

- **灵活性**：通过 `AutoEdit` 和 `Yolo` 模式，允许高级用户在受控环境下释放 AI 的全部能力，无需频繁点击确认。
- **安全性**：通过强制的 `Safety Checker` 和不可覆盖的 Admin 策略，确保即使在“狂飙”模式下，AI 也无法突破物理文件系统的沙箱限制（如读取 `/etc/passwd` 或修改项目外文件）。

## 总结对比表格

| 特性 | Plan Mode | Default Mode | AutoEdit Mode | Yolo Mode |
| :--- | :--- | :--- | :--- | :--- |
| **文件读取** | ✅ 允许 (Priority 50) | ✅ 允许 (通常) | ✅ 允许 | ✅ 允许 |
| **文件写入** | ❌ 拒绝 (Global Deny) | ⚠️ 询问用户 (Priority 10) | ✅ 自动允许 (Priority 15) | ✅ 自动允许 (Priority 999) |
| **Shell 执行** | ❌ 拒绝 | ⚠️ 询问用户 | ⚠️ 询问用户 | ✅ 自动允许 |
| **路径限制** | 严格限制 | 严格限制 (Checker) | 严格限制 (Checker) | 严格限制 (Checker) |
| **适用场景** | 代码阅读、架构分析 | 日常辅助、结对编程 | 快速重构、单元测试生成 | 自动化脚本、CI/CD 流水线 |
