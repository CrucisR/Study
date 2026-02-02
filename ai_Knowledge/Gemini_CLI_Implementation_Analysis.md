# Gemini CLI 技术实现与安全机制全指南

## 1. 核心架构概述

Gemini CLI 的安全模型基于一个多层级的**策略引擎 (Policy Engine)**。所有的工具调用（Tool Calls），包括文件读写、命令执行等，都必须经过策略引擎的审查。

### 1.1 策略分层体系 (Policy Tiers)
系统将权限策略分为三个层级，优先级从高到低：
1.  **Admin Tier (3.x)**: 管理员强制策略（最高优先级）。
2.  **User Tier (2.x)**: 用户自定义设置（包括配置文件、CLI 参数）。
3.  **Default Tier (1.x)**: 系统内置默认策略（TOML 文件）。

**源码原理**:
在 `packages/core/src/policy/toml-loader.ts` 中，优先级被转换为浮点数。例如，TOML 中定义的 priority 10 在 Default Tier 变为 `1.010`，在 User Tier 变为 `2.010`。这确保了用户的明确设置永远覆盖系统默认值。

---

## 2. 五种模式详解与实现原理

Gemini CLI 实际上主要定义了四种核心审批模式 (`ApprovalMode`)。用户提到的 "Shell Mode" 在代码中并非独立模式，而是指 Shell 命令执行工具 (`run_shell_command`) 在各模式下的权限表现。

### 2.1 模式定义与映射
源码位置：`packages/core/src/policy/types.ts` 定义了 `ApprovalMode` 枚举：
- `DEFAULT` ("default")
- `AUTO_EDIT` ("autoEdit")
- `YOLO` ("yolo")
- `PLAN` ("plan")

### 2.2 模式详细对比

#### (1) Plan Mode (计划模式)
*   **设计目标**: 仅用于生成计划文档，禁止产生实际副作用。
*   **策略文件**: `packages/core/src/policy/policies/plan.toml`
*   **权限实现**:
    *   **Deny All**: 设置了优先级为 20 的全局 `deny` 规则。
    *   **Allow Read**: 显式允许 `read_file`, `glob`, `search_file_content` (优先级 50)。
    *   **Limited Write**: 仅允许向 `.gemini/tmp/.../plans/*.md` 写入文件 (通过 `argsPattern` 正则匹配实现)。
    *   **Shell**: 禁止 (Deny)。

#### (2) Default Mode (默认模式)
*   **设计目标**: 安全的交互式编程，敏感操作需用户确认。
*   **策略文件**: `read-only.toml`, `write.toml`
*   **权限实现**:
    *   **Read**: 允许 (优先级 50)。
    *   **Write**: 询问用户 (`ask_user`, 优先级 10)。
    *   **Shell**: 询问用户 (`ask_user`, 优先级 10)。

#### (3) AutoEdit Mode (自动编辑模式)
*   **设计目标**: 允许 Agent 自动修改代码，但保持一定限制。
*   **策略文件**: `write.toml`
*   **权限实现**:
    *   **Write**: 针对 `write_file`, `replace` 等工具，在 `modes = ["autoEdit"]` 下设置为 `allow` (优先级 15)。
    *   **Shell**: 依然保持 `ask_user` (未覆盖默认规则)。
    *   **安全检查 (Bug)**: 配置文件试图加载 `allowed-path` 检查器来限制写操作在工作区内，但由于加载器 Bug (见下文) 目前可能未生效。

#### (4) Yolo Mode (全自动模式)
*   **设计目标**: 完全信任，无人值守执行。
*   **策略文件**: `yolo.toml`
*   **权限实现**:
    *   **Allow All**: 设置了优先级 999 的全局 `allow` 规则。
    *   **Redirection**: 允许输入/输出重定向 (`allow_redirection = true`)。
    *   **Shell**: 自动允许。

#### (5) Shell Execution (所谓 "Shell Mode")
*   这不是一个独立状态，而是指 `run_shell_command` 工具的调用。
*   **防护机制**:
    *   **AST 解析**: 使用 `web-tree-sitter` 将复杂的 Shell 脚本拆解为单个命令。
    *   **黑白名单**: 拆解后的每个子命令都会独立经过策略引擎检查。

---

## 3. 文件目录权限控制机制

Gemini CLI 设计了 `AllowedPathChecker` 来防止 Agent 越权访问工作区以外的文件（Sandbox Escape）。

### 3.1 实现原理 (`AllowedPathChecker`)
源码位置：`packages/core/src/safety/built-in.ts`
1.  **路径解析**: 使用 `path.resolve` 获取绝对路径。
2.  **符号链接防护**: 使用 `fs.realpathSync` 解析每一级父目录，确保路径没有通过软链接跳出工作区。
3.  **包含/排除规则**: 检查路径是否在 `context.environment.cwd` 或 `workspaces` 列表中。

### 3.2 严重发现：安全检查器失效 (Critical Bug)
经过逆向分析发现，尽管 `write.toml` 中配置了 `[rule.safety_checker]`，但在 `toml-loader.ts` 的 Zod Schema 定义中：
```typescript
const PolicyRuleSchema = z.object({
  // ... 缺少 safety_checker 字段
});
```
这意味着 **AutoEdit 模式下的路径限制目前是失效的**。Agent 可能在 AutoEdit 模式下写入系统任意位置的文件（只要进程有权限），而不会触发拦截。

---

## 4. 命令执行权限控制

### 4.1 黑白名单机制
*   目前主要依赖 **工具名称 (Tool Name)** 和 **命令前缀 (Command Prefix)** 进行控制。
*   例如，可以允许 `git status` 但禁止 `git push`，通过在策略中配置 `argsPattern` 或 `commandPrefix`。

### 4.2 用户配置方法
用户可以通过以下方式自定义权限：

1.  **CLI 参数**:
    *   `--auto-edit`: 开启自动编辑。
    *   `--yolo`: 开启全自动模式。
    *   `--plan`: 进入计划模式。

2.  **配置文件 (User Tier)**:
    *   用户可以在 `~/.gemini/config` (具体路径视实现而定) 中定义自己的 `.toml` 策略文件。
    *   用户定义的规则优先级会自动加上 `2000`，从而覆盖系统默认规则。

---

## 5. 总结

| 模式 | 文件读取 | 文件写入 | Shell 执行 | 安全限制 |
| :--- | :--- | :--- | :--- | :--- |
| **Default** | 自动允许 | 需确认 | 需确认 | 默认询问 |
| **AutoEdit** | 自动允许 | **自动允许** | 需确认 | *原设计限制目录(Bug失效)* |
| **Plan** | 自动允许 | **禁止*** | 禁止 | 仅允许写特定计划文件 |
| **Yolo** | 自动允许 | 自动允许 | 自动允许 | **无限制** |

**建议**:
*   对于敏感任务，请始终使用 **Default Mode**。
*   在修复 `toml-loader.ts` 之前，使用 **AutoEdit Mode** 需谨慎，因为它目前可能允许修改工作区外的文件。
