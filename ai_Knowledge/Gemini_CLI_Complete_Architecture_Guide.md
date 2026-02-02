# Gemini CLI 全方位技术架构与安全机制指南

本文档综合了官方技术文档与底层源码分析，旨在为开发者提供一份关于 Gemini CLI 架构、权限控制、安全模式及配置管理的完整技术指南。

---

## 1. 核心架构设计逻辑

Gemini CLI 的设计遵循 **"纵深防御 (Defense in Depth)"** 原则，通过多层拦截机制确保 AI 操作的安全性。

### 1.1 系统分层模型
当 AI 尝试执行一个工具（如写文件或运行命令）时，请求需依次通过以下四道防线：

1.  **信任层 (Trusted Folders)**: 决定是否加载当前项目的自定义配置。
2.  **策略层 (Policy Engine)**: 基于规则（Rules）和模式（Modes）的逻辑判断（Allow/Deny/Ask）。
3.  **安全检查层 (Safety Checkers)**: 针对参数的深度验证（如路径越权检查、Shell AST分析）。
4.  **隔离层 (Sandboxing)**: OS 级别的环境隔离（Docker/Seatbelt）。

### 1.2 关键组件源码映射
- **策略引擎**: `packages/core/src/policy/` - 处理 TOML 规则加载与优先级计算。
- **安全检查器**: `packages/core/src/safety/` - 实现 `AllowedPathChecker` 等逻辑。
- **配置管理**: `packages/cli/src/config/` - 处理 `settings.json` 与 CLI 参数。
- **工具实现**: `packages/core/src/tools/` - 包含 `fs`, `shell` 等具体工具逻辑。

---

## 2. 五大模式详解：策略与实现原理

Gemini CLI 通过 `ApprovalMode` 枚举定义了四种基础模式，而 "Shell Mode" 实际上是命令执行工具的一种特殊运行状态。

### 2.1 模式定义与权限矩阵

| 模式 (Mode) | 核心逻辑 | 文件读取 | 文件修改 | Shell执行 | 适用场景 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Plan** | **只读安全** | ✅ 允许 | ❌ 拒绝* | ❌ 拒绝 | 纯规划、代码审查 |
| **Default** | **交互确认** | ✅ 允许 | ❓ 询问用户 | ❓ 询问用户 | 日常编码，兼顾安全与效率 |
| **AutoEdit** | **信任编辑** | ✅ 允许 | ✅ 允许 | ❓ 询问用户 | 快速重构、批量修改代码 |
| **Yolo** | **全自动** | ✅ 允许 | ✅ 允许 | ✅ 允许 | 演示、高信任环境 |
| **Shell** | **命令交互** | - | - | 需视主模式而定 | 执行系统级操作 |

*\*注：Plan 模式允许在 `.gemini/tmp/plans/` 目录下写入 Markdown 文件。*

### 2.2 深入实现原理

#### Plan Mode (计划模式)
- **原理**: 基于 **Deny-All (默认拒绝)** 策略，仅通过白名单放行只读工具。
- **源码**: `packages/core/src/policy/policies/plan.toml`
- **关键规则**:
  ```toml
  [[rule]]
  decision = "deny"
  priority = 20
  modes = ["plan"]
  ```

#### Default Mode (默认模式)
- **原理**: 若无更高优先级规则覆盖，系统回退到默认策略。写操作在 `write.toml` 中被标记为 `ask_user` (优先级 10)。
- **行为**: 读取操作（Tier 1 默认允许）直接通过；写操作/命令执行命中 `ask_user` 规则，触发用户交互。

#### AutoEdit Mode (自动编辑模式)
- **原理**: 在 `write.toml` 中为编辑工具（`write_file`, `replace`）定义了特定规则，仅在 `modes = ["autoEdit"]` 时生效，且优先级 (15) 高于默认规则 (10)。
- **安全边界**: 仅放宽了文件系统的写权限，**未放宽** Shell 命令执行权限，防止 AI 误删文件或执行恶意脚本。

#### Yolo Mode (激进模式)
- **原理**: 加载 `yolo.toml`，包含一条优先级极高 (999) 的通用允许规则。
- **源码**:
  ```toml
  [[rule]]
  decision = "allow"
  priority = 999
  modes = ["yolo"]
  ```

#### Shell Execution (Shell 执行机制)
- **实现**: 通过 `run_shell_command` 工具实现。
- **交互式 Shell**: 若配置 `tools.shell.enableInteractiveShell = true`，CLI 会启动 `node-pty` 伪终端，支持 `vim`, `nano`, `htop` 等交互式命令。
- **防护**:
  - **AST 解析**: 使用 `web-tree-sitter` 解析命令结构，防止通过 `&&` 或 `;` 拼接恶意命令。
  - **前缀匹配**: 支持配置 `tools.core` (白名单) 和 `tools.exclude` (黑名单)。

---

## 3. 权限控制体系：文件与命令

### 3.1 文件系统权限 (File System Permissions)

#### 目录限制机制 (Root Directory Confinement)
- **原理**: 所有文件操作工具（`read_file`, `write_file` 等）强制限制在 `rootDirectory`（通常是启动目录）及其子目录中。
- **源码逻辑**:
  使用 `fs.realpathSync` 解析用户路径和允许的根目录，检查 `resolvedPath.startsWith(allowedRoot)`。这能有效防御 `../../etc/passwd` 类型的路径遍历攻击。

#### 扩展工作区
用户可通过 `--include-directories` 或配置 `context.includeDirectories` 添加额外的允许路径。

### 3.2 命令执行权限 (Command Execution Permissions)

#### 启动目录限制 (CWD Confinement)
- **原理**: `run_shell_command` 工具强制要求 `directory` 参数必须在当前工作区 (Workspace) 内。
- **源码**: `packages/core/src/tools/shell.ts` 中的 `validatePathAccess(cwd)`。
- **效果**: 防止攻击者在 `/tmp` 或敏感系统目录下启动恶意脚本。

#### 深度分析：能否操作启动目录外的文件？
**用户提问**: "能否通过命令执行操作启动目录外的文件？"
**技术结论**: **可以** (如果未开启沙盒)。

虽然 CLI 限制了 Shell 进程的**启动目录 (CWD)**，但**并未**限制 Shell 命令参数中引用的文件路径。

- **原理缺失**: `packages/core/src/services/shellExecutionService.ts` 直接将命令字符串传递给 `node-pty` 或 `child_process.spawn`。系统**没有**实现对 Shell 命令参数的 AST 深度路径审计（这在技术上极难做到完美，因为 Shell 语法过于灵活，且存在变量扩展等动态特性）。
- **风险演示**:
  假设工作区为 `/projects/my-app`，策略允许执行 Shell。
  - ✅ **被阻止**: 尝试将 `directory` 参数设为 `/etc/` -> 报错 `Path not in workspace`。
  - ⚠️ **可执行**: 在 `/projects/my-app` 下执行命令 `cat /etc/passwd` (Linux) 或 `type C:\Windows\System32\drivers\etc\hosts` (Windows) -> **CLI 默认层级无法拦截**。因为命令是在允许的目录下启动的，但操作对象指向了系统敏感文件。

#### 防护措施 (Mitigation)
由于静态分析无法完全解决此问题，Gemini CLI 采用以下分层防御：

1.  **审批模式 (Default/AutoEdit)**:
    - 依赖 `ask_user` 策略。用户必须人工审核每一条 Shell 命令。这是最基础的防御。

2.  **沙盒隔离 (Sandboxing) - 强烈推荐**:
    - **Docker**: 推荐在 Docker 容器中运行 CLI。CLI 会自动将当前工作目录挂载到容器内。即使 AI 执行 `rm -rf /`，也只能删除容器内的文件，无法影响宿主机。
    - **macOS Seatbelt**: 使用 `gemini --sandbox` 启动，利用 macOS 内核级沙盒限制文件读写范围。

3.  **黑名单 (Limited Defense)**:
    - 可配置 `tools.exclude` 禁用高危命令 (如 `rm`, `sudo`)，但这容易被混淆绕过 (e.g. `echo cm0= | base64 -d | sh`)，仅作为辅助手段。

---

## 4. 用户配置指南 (User Configuration)

### 4.1 配置文件位置
Gemini CLI 支持多级配置，优先级由高到低：

1.  **命令行参数**: `gemini --approval-mode=yolo`
2.  **工作区设置**: `<project_root>/.gemini/settings.json` (需通过 Trusted Folder 检查)
3.  **用户全局设置**:
    - **Windows**: `%APPDATA%\gemini-cli\settings.json`
    - **macOS**: `~/Library/Application Support/GeminiCli/settings.json`
    - **Linux**: `~/.config/gemini-cli/settings.json`
4.  **系统默认设置**: 安装目录下的 `system-defaults.json`

### 4.2 策略文件 (Policy TOML)
除了 `settings.json`，高级权限控制通过 TOML 策略文件管理。

- **用户策略**: `~/.gemini/policies/*.toml` (Tier 2)
- **管理员策略**: (Tier 3，强制覆盖)
    - **Linux**: `/etc/gemini-cli/policies/`
    - **Windows**: `C:\ProgramData\gemini-cli\policies\`
    - **macOS**: `/Library/Application Support/GeminiCli/policies/`

### 4.3 常用配置示例

**场景：开启自动编辑，但禁止 YOLO**
`settings.json`:
```json
{
  "tools": {
    "approvalMode": "auto_edit"
  },
  "security": {
    "disableYoloMode": true
  }
}
```

**场景：禁止所有 Shell 命令 (通过策略)**
`~/.gemini/policies/no-shell.toml`:
```toml
[[rule]]
toolName = "run_shell_command"
decision = "deny"
priority = 100
deny_message = "Shell commands are disabled by user policy."
```

---

## 5. 隔离层：Sandboxing (沙盒)

对于高风险任务，Gemini CLI 支持 OS 级别的隔离。

### 5.1 启用方式
- **CLI Flag**: `gemini --sandbox`
- **Env Var**: `GEMINI_SANDBOX=true`

### 5.2 实现方式
- **macOS**: 使用系统内置的 `sandbox-exec` (Seatbelt)，配置文件限制了网络和文件写入权限。
- **Linux/Windows**: 推荐使用 **Docker** 或 **Podman**。CLI 会自动挂载当前工作目录到容器内，确保 AI 只能修改项目文件，无法触及宿主机系统。

---

## 6. 优先级系统详解 (Priority System)

策略引擎的核心是分层优先级算法，确保企业管控 > 用户自定义 > 默认行为。

**计算公式**:
`Final Priority = Tier Base + (Rule Priority / 1000)`

| 层级 (Tier) | 基数 (Base) | 来源 | 说明 |
| :--- | :--- | :--- | :--- |
| **Admin** | 3.000 | `/etc/gemini-cli/policies` | 管理员强制策略，无法被用户覆盖 |
| **User** | 2.000 | `~/.gemini/policies` | 用户自定义策略 |
| **Default** | 1.000 | 内置 TOML 文件 | 默认出厂设置 |

**示例**:
- 用户定义了一个优先级 `100` 的允许规则 -> 分值 `2.100`。
- 管理员定义了一个优先级 `10` 的拒绝规则 -> 分值 `3.010`。
- 结果：**拒绝** (3.010 > 2.100)。

---

## 7. 总结

Gemini CLI 提供了一个灵活且强大的安全框架：
1.  **初学者**: 可以直接使用 `--approval-mode` (Default/AutoEdit) 快速切换工作流。
2.  **进阶用户**: 可以通过 `settings.json` 微调工具行为（如禁用交互式 Shell）。
3.  **企业/极客**: 可以利用 TOML 策略引擎和 Admin Tier 实现细粒度的权限管控（如正则匹配参数、针对特定 MCP Server 的规则）。
4.  **高危操作**: 建议配合 `--sandbox` 使用 Docker 隔离环境。
