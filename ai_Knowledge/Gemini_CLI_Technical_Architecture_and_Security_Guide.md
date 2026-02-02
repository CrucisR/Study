# Gemini CLI 技术架构与安全机制深度解析指南

本文档专为希望深入理解 Gemini CLI 实现原理的开发者编写，涵盖核心架构、五大模式（含Shell执行机制）的实现原理、权限控制策略及源码级解析。

---

## 1. 整体设计逻辑与架构

Gemini CLI 的核心设计理念是 **"基于策略引擎（Policy Engine）的工具调用控制"**。

### 1.1 核心组件
1.  **Policy Engine (策略引擎)**: 系统的"大脑"，负责拦截所有工具调用（Tool Calls），根据预定义的规则（Rules）决定是否放行。
2.  **Approval Modes (审批模式)**: 定义了当前会话的安全基线。
3.  **Safety Checkers (安全检查器)**: 针对特定参数（如文件路径）的深度检查逻辑。
4.  **Tiered Priority System (分层优先级系统)**: 确保管理员策略 > 用户策略 > 默认策略。

### 1.2 源码目录结构
- `packages/core/src/policy/`: 策略引擎核心代码。
- `packages/core/src/policy/policies/`: 默认 TOML 策略文件（`plan.toml`, `write.toml`, `yolo.toml` 等）。
- `packages/core/src/safety/`: 安全检查器实现（如路径检查、AST解析）。
- `packages/cli/src/config/`: 配置加载与命令行参数解析。

---

## 2. 五大模式详解：策略与实现

Gemini CLI 实际上定义了 **四种** `ApprovalMode`（审批模式），通常所说的 "Shell Mode" 实为 **Shell 命令执行机制**，本节将一并详细解析。

**源码枚举定义** (`packages/core/src/policy/types.ts`):
```typescript
export enum ApprovalMode {
  DEFAULT = 'default',
  AUTO_EDIT = 'autoEdit',
  YOLO = 'yolo',
  PLAN = 'plan',
}
```

### 2.1 Plan Mode (计划模式)
- **核心逻辑**: **只读安全 (Read-Only Safe)**。
- **权限策略**:
  - **默认**: 拒绝所有操作 (`decision = "deny"`).
  - **例外**: 允许读取文件 (`read_file`)、列出目录 (`list_directory`)、搜索 (`search_file_content`)。
  - **特殊写权限**: 仅允许在 `.gemini/tmp/.../plans/` 目录下写入 `.md` 格式的计划文件。
- **源码映射 (`packages/core/src/policy/policies/plan.toml`)**:
  ```toml
  # 优先级 20，覆盖默认写规则
  [[rule]]
  decision = "deny"
  priority = 20
  modes = ["plan"]

  # 显式允许只读工具
  [[rule]]
  toolName = "read_file"
  decision = "allow"
  priority = 50
  modes = ["plan"]
  ```

### 2.2 Default Mode (默认模式)
- **核心逻辑**: **交互式确认 (Ask User)**。
- **权限策略**:
  - **读取**: 自动允许 (Allow)。
  - **写入/修改**: 需要用户确认 (Ask User)。
  - **Shell命令**: 需要用户确认 (Ask User)。
- **实现原理**:
  - 在 `write.toml` 中，写操作（`write_file`, `replace_in_file`）默认被配置为 `ask_user`，优先级为 10。
  - 由于没有更高优先级的规则覆盖（除非开启其他模式），系统回退到此默认行为。

### 2.3 AutoEdit Mode (自动编辑模式)
- **核心逻辑**: **信任代码修改 (Trust Code Edits)**。
- **权限策略**:
  - **文件修改**: 自动允许 (`write_file`, `replace_in_file` 等)。
  - **Shell命令**: 依然需要用户确认 (Ask User)，防止执行危险系统命令。
- **源码映射 (`packages/core/src/policy/policies/write.toml`)**:
  ```toml
  # 针对 auto_edit 模式，提升写操作优先级并设为 allow
  [[rule]]
  toolName = ["write_file", "replace_in_file", "apply_diff"]
  decision = "allow"
  priority = 15  # 高于默认的 10
  modes = ["autoEdit"]
  ```

### 2.4 Yolo Mode (激进模式)
- **核心逻辑**: **全自动 (Trust All)**。
- **权限策略**:
  - 允许所有工具调用，包括文件读写和 Shell 命令执行。
- **源码映射 (`packages/core/src/policy/policies/yolo.toml`)**:
  ```toml
  # 极高优先级，允许所有工具
  [[rule]]
  decision = "allow"
  priority = 999
  modes = ["yolo"]
  ```

### 2.5 Shell Execution Mechanism (Shell 执行机制)
虽然不是独立的 `ApprovalMode`，但在用户语境中常被称为 "Shell Mode"。
- **风险**: Shell 命令可能通过 `rm -rf /` 或反弹 Shell 危害系统。
- **防护措施**:
  1.  **AST 解析**: 使用 `web-tree-sitter` 解析 Shell 命令语法树，识别复合命令（`&&`, `|`, `;`）。
  2.  **黑/白名单**: 可配置禁止特定命令（如 `rm`, `sudo`）。
  3.  **审批控制**: 在 Default/AutoEdit 模式下，默认需要用户明确批准 (`ask_user`)。
- **源码位置**: `packages/core/src/policy/policies/write.toml` 中定义了 `run_shell_command` 的规则。

---

## 3. 文件系统权限控制详解

### 3.1 目录越权防护 (Path Traversal Prevention)
Gemini CLI 实现了严格的 **Workspace Confinement (工作区限制)**，防止 AI 访问项目之外的文件（如 `/etc/passwd` 或 `C:\Windows`）。

**实现类**: `AllowedPathChecker`
**源码位置**: `packages/core/src/safety/built-in.ts`

**核心代码逻辑**:
```typescript
// 1. 获取允许的根目录（CWD 和 Workspaces）
const allowedDirs = [context.environment.cwd, ...context.environment.workspaces];

// 2. 路径解析与规范化 (Resolve & Realpath)
// 使用 realpathSync 解析符号链接，防止软链绕过
const resolvedPath = fs.realpathSync(path.resolve(cwd, inputPath));

// 3. 检查前缀 (Prefix Check)
const isAllowed = allowedDirs.some(dir => {
    const resolvedDir = fs.realpathSync(dir);
    // 检查 resolvedPath 是否以 resolvedDir 开头
    return resolvedPath.startsWith(resolvedDir);
});
```

### 3.2 权限控制配置位置
用户可以通过修改配置文件或 TOML 策略来调整文件权限。
- **系统级配置**: `config.ts` 中的 `AllowedPathConfig`。
- **策略文件**: TOML 文件中的 `safety_checker` 字段（**注意：当前版本存在 Schema 解析 Bug，需修复 `toml-loader.ts` 才能生效**）。

---

## 4. 命令执行权限控制 (Command Execution)

### 4.1 黑白名单机制
- **白名单 (Allowlist)**: 默认仅允许特定的安全命令（如果配置了 strict 模式）。
- **黑名单 (Blocklist)**: 在策略中明确 `deny` 危险命令。

### 4.2 设置方法
用户可以在自定义策略文件中配置命令规则。

**示例配置 (禁止 `rm` 命令)**:
```toml
[[rule]]
toolName = "run_shell_command"
decision = "deny"
priority = 100
commandRegex = "^rm\\s+.*"
deny_message = "Deleting files via shell is not allowed."
```

---

## 5. 用户配置指南 (User Configuration)

用户可以通过多种方式自定义 Gemini CLI 的行为。

### 5.1 配置文件位置
1.  **全局设置 (User Settings)**:
    - **Windows**: `%APPDATA%\gemini-cli\settings.json` (通常在 `C:\Users\Name\AppData\Roaming\...`)
    - **macOS**: `~/Library/Application Support/GeminiCli/settings.json`
    - **Linux**: `~/.config/gemini-cli/settings.json`
2.  **项目级设置**: `.gemini/config.toml` (如果支持项目级覆盖)。

### 5.2 常用设置项
- **Allowed Tools**: `gemini --allowed-tools=run_shell_command` (临时允许)
- **Approval Mode**: `gemini --approval-mode=auto_edit`
- **Include Directories**: `gemini --include-directories=/extra/path` (扩展工作区)

### 5.3 环境变量
- `GEMINI_CLI_SYSTEM_SETTINGS_PATH`: 覆盖系统设置路径。
- `GEMINI_CLI_SYSTEM_DEFAULTS_PATH`: 覆盖默认设置路径。

---

## 6. 优先级系统 (Priority System)

Gemini CLI 使用 **Tiered Priority (分层优先级)** 确保安全策略不被轻易覆盖。

**优先级计算公式**:
- **Default Tier (1.x)**: `1 + priority / 1000` (内置 TOML)
- **User Tier (2.x)**: `2 + priority / 1000` (用户配置)
- **Admin Tier (3.x)**: `3 + priority / 1000` (管理员强制策略)

**含义**:
管理员配置的 `priority=1` (Result: 3.001) 永远高于 默认配置的 `priority=999` (Result: 1.999)。这保证了企业级安全管控的强制性。

---

## 7. 总结：各模式权限矩阵

| 特性 | Plan Mode | Default Mode | AutoEdit Mode | Yolo Mode |
| :--- | :--- | :--- | :--- | :--- |
| **读文件** | ✅ 允许 | ✅ 允许 | ✅ 允许 | ✅ 允许 |
| **写文件** | ❌ 拒绝 (仅限计划) | ❓ 询问用户 | ✅ 允许 | ✅ 允许 |
| **Shell命令** | ❌ 拒绝 | ❓ 询问用户 | ❓ 询问用户 | ✅ 允许 |
| **越权访问** | 🛡️ 拦截 | �️ 拦截 | �️ 拦截 | 🛡️ 拦截 |

*注：越权访问（访问工作区外文件）由底层 `AllowedPathChecker` 强制拦截，不受模式影响，除非用户显式添加 `--include-directories`。*

---

**附：已知问题说明**
在源码分析中发现 `packages/core/src/policy/toml-loader.ts` 中的 `PolicyRuleSchema` 缺少 `safety_checker` 字段定义。这意味着目前 TOML 文件中嵌套的 `safety_checker` 配置可能在加载时被忽略。建议开发者在调试时注意此问题。
