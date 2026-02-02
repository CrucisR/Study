# Gemini CLI (CodeAgent) 核心原理与安全配置完全指南

这份指南专为希望深入了解 Gemini CLI 内部机制的开发者和高级用户编写。我们将从基础概念出发，逐步剖析其运行模式、权限控制、沙箱机制以及底层代码实现。

---

## 1. 核心设计逻辑 (Core Design Philosophy)

> "Gemini CLI 的安全不仅依赖配置文件，更通过代码逻辑进行双重锁定。"

### 1.1 纵深防御 (Defense in Depth)
Gemini CLI 不仅仅依赖一道防线，而是构建了多层防御体系：
1.  **静态策略 (Static Policies)**: `policies/*.toml` 文件定义了基本的 Allow/Deny 规则。
2.  **动态检查 (Dynamic Checkers)**: 代码中内置了 `Allowed-Path Checker`，在运行时动态检查文件路径是否越界。
3.  **硬编码逻辑 (Hardcoded Logic)**: 针对特定模式（如 Plan Mode），代码中直接写死了“停止执行”的逻辑，防止配置被绕过。

### 1.2 最小权限 (Least Privilege)
默认情况下，Gemini CLI 处于 **Default Mode**，这是一种“零信任”状态。
- 任何具有副作用的操作（写文件、执行命令）都需要您明确批准。
- 即使是“自动编辑”模式，也仅放开了文件编辑，Shell 命令依然受到严格限制。

---

## 2. 深度剖析：代码级决策逻辑 (Deep Dive: Code-Level Decisions)

**这是本文档最核心的进阶部分。** 除了能看到的 TOML 配置文件外，Gemini CLI 在 TypeScript 代码内部还隐藏了一套不可修改的决策逻辑。

### 2.1 运行模式的硬编码行为 (Hardcoded Mode Behaviors)

| 模式 | 关键代码逻辑 | 解释 | 代码位置 |
| :--- | :--- | :--- | :--- |
| **Default** | `shouldDowngradeForRedirection` | 如果命令包含 `>` 或 `\|` (重定向/管道)，即使该命令在白名单中，也会强制降级为 **需审批**。 | `core/policy/policy-engine.ts` |
| **Plan** | `PLAN_MODE_TOOLS` 白名单 | 代码中写死了一份允许工具列表：`GLOB`, `GREP`, `READ`, `LS`, `WEB_SEARCH`。任何其他工具调用都会直接报错。 | `core/tools/tool-names.ts` |
| **Plan** | `STOP_EXECUTION` 错误 | 如果 AI 试图调用非法工具，系统会返回 `ToolErrorType.STOP_EXECUTION`，强制终止当前 Agent 的思考循环，而不仅仅是返回“拒绝”。 | `core/coreToolScheduler.ts` |
| **AutoEdit** | `autoEditExcludes` | 在非交互模式 (Headless) 下，系统会强制排除 `run_shell_command`，只保留编辑工具。 | `cli/config/config.ts` |
| **Yolo** | `disableYoloMode` | 每次尝试进入 Yolo 模式（包括使用 `--yolo` 参数），代码都会检查 `secureModeEnabled` (Admin配置)。如果开启，程序会直接报错退出。 | `cli/config/config.ts` |

### 2.2 非交互模式下的“隐形黑名单”
当您使用 `gemini -p "fix this"` (非交互模式) 运行时，系统会根据模式激活一份**隐形黑名单**，防止 AI 在后台静默执行危险操作：

*   **Default Mode 黑名单**: `[SHELL, EDIT, WRITE_FILE, WEB_FETCH]` (几乎全禁)
*   **AutoEdit Mode 黑名单**: `[SHELL]` (只禁 Shell)
*   **Yolo Mode**: 无黑名单

> **代码证据**: 位于 `packages/cli/src/config/config.ts` 中的 `defaultExcludes` 和 `autoEditExcludes` 定义。

---

## 3. 运行模式深度解析 (Modes & Implementation)

Gemini CLI 通过 `Policy Engine` 加载不同的 TOML 策略文件来切换模式。

### 2.1 Plan Mode (规划模式)
* **场景**：阅读代码、分析架构、生成开发计划。
* **原理**：**只读**。禁止一切副作用。
* **策略实现**：
  - **位置**：`packages/core/src/policy/policies/plan.toml`
  - **关键代码**：
    ```toml
    [[rule]]
    decision = "deny"   # 拒绝所有操作
    priority = 20       # 优先级高于默认的 10
    modes = ["plan"]    # 仅在 plan 模式激活
    ```
    随后显式允许 `read_file`, `glob` 等工具 (Priority 50)。
* **权限**：
  - ✅ **读文件**：允许
  - ❌ **写文件**：拒绝
  - ❌ **执行命令**：拒绝

### 2.2 Default Mode (默认模式)
* **场景**：日常辅助开发、结对编程。
* **原理**：**询问**。敏感操作默认挂起，等待用户确认。
* **策略实现**：
  - **位置**：`packages/core/src/policy/policies/write.toml`
  - **关键代码**：
    ```toml
    [[rule]]
    toolName = "write_file"
    decision = "ask_user"  # 询问用户
    priority = 10
    ```
* **权限**：
  - ✅ **读文件**：允许
  - ⚠️ **写文件**：询问用户
  - ⚠️ **执行命令**：询问用户

### 2.3 AutoEdit Mode (自动编辑模式)
* **场景**：快速重构、单元测试生成、批量修改。
* **原理**：**有限自动**。自动批准文件修改，但仍拦截 Shell 命令。
* **策略实现**：
  - **位置**：`packages/core/src/policy/policies/write.toml`
  - **关键代码**：
    ```toml
    [[rule]]
    toolName = "write_file"
    decision = "allow"     # 自动允许
    priority = 15          # 优先级 (15) > Default (10)
    modes = ["autoEdit"]
    ```
* **权限**：
  - ✅ **读文件**：允许
  - ✅ **写文件**：自动允许（受沙箱限制）
  - ⚠️ **执行命令**：询问用户

### 2.4 Yolo Mode (狂飙模式)
* **场景**：CI/CD 流水线、全自动化脚本执行、可信环境。
* **原理**：**全自动**。几乎允许所有操作。
* **策略实现**：
  - **位置**：`packages/core/src/policy/policies/yolo.toml`
  - **关键代码**：
    ```toml
    [[rule]]
    decision = "allow"     # 全局允许
    priority = 999         # 极高优先级
    modes = ["yolo"]
    ```
* **权限**：
  - ✅ **读文件**：自动允许
  - ✅ **写文件**：自动允许
  - ✅ **执行命令**：自动允许（受黑名单限制）

### 2.5 Shell Mode (UI 交互模式)
* **注意**：这不是一个独立的 Policy Mode，而是一个 **UI 状态**。
* **原理**：
  - 当你在交互界面输入 `!` 开头的命令时，或者进入 Shell 模式界面时。
  - 系统底层调用 `run_shell_command` 工具。
  - 该调用**受限于当前激活的 Approval Mode**（如 Default 或 Yolo）。
* **代码实现**：
  - 位于 `packages/cli/src/services/prompt-processors/shellProcessor.ts`。
  - 它只是将用户输入包装成工具调用，并不绕过 Policy Engine。

---

## 3. 命令执行与权限控制

Gemini CLI 对 `run_shell_command` 实施了特别的管控。

### 3.1 拦截机制
* **代码位置**：`packages/core/src/policy/policy-engine.ts` -> `checkShellCommand`
* **逻辑**：
  1. **命令拆分**：将 `echo hello && rm -rf /` 拆分为 `echo` 和 `rm`。
  2. **逐个审查**：每个子命令必须通过策略检查。
  3. **一票否决**：只要有一个子命令被 Deny，整体拒绝。

### 3.2 黑/白名单
* **黑名单 (Deny List)**：
  - 系统内置或用户配置的禁止命令。
  - 即使在 Yolo 模式下，如果配置了 `tools.exclude`，该命令依然会被拒绝。
* **白名单 (Allow List)**：
  - 可以通过 `commandPrefix` (前缀匹配) 或 `commandRegex` (正则匹配) 在 TOML 中定义允许的命令。
  - 例如，只允许 `git status` 而不允许 `git push`。

---

## 4. 文件系统沙箱 (File System Sandbox)

这是防止 AI "越狱" 的核心机制。

### 4.1 Allowed-Path Safety Checker
* **类型**：`in-process` (进程内检查器)。
* **代码位置**：`packages/core/src/safety/built-in.ts`
* **工作原理**：
  1. **获取白名单**：收集当前工作目录 (`cwd`) 和所有已添加的工作区 (`workspaces`)。
  2. **路径规范化**：使用 `path.resolve` 解析输入路径，消除 `..` 等相对路径符号。
  3. **包含性检查**：验证解析后的路径是否以白名单目录为前缀。
* **关联**：
  - 在 `write.toml` 中，`write_file` 工具被强制绑定了 `allowed-path` 检查器。
  - 这意味着：**即使策略允许写入，如果路径在工作区之外，操作也会失败。**

---

## 5. MCP (Model Context Protocol) 集成与权限

Gemini CLI 支持 MCP 协议，允许连接外部工具服务。

### 5.1 命名与通配符
* MCP 工具在内部被命名为 `serverName__toolName`。
* 策略支持通配符 `serverName__*`，可一次性控制某服务器下的所有工具。

### 5.2 信任分级
* **Proceed Once**：仅允许本次调用。
* **Proceed Always (Session)**：本次会话内允许该工具或服务器。
* **Proceed Always (Persist)**：永久允许，并将规则写入用户策略文件。

---

## 6. 用户配置指南 (Configuration)

你可以通过三层配置来定制 Gemini CLI。

### 6.1 配置优先级 (由高到低)
1.  **Admin Policies (Tier 3)**：
    - 系统管理员设置，普通用户无法覆盖。
    - 路径：依赖操作系统（通常在系统级配置目录）。
2.  **User Policies (Tier 2)**：
    - 用户自定义设置。
    - 路径：`~/.gemini/policies/*.toml`。
    - **技巧**：在这里创建 `my-rules.toml`，可以覆盖默认行为。
3.  **Default Policies (Tier 1)**：
    - 也就是上文提到的内置 `plan.toml`, `write.toml` 等。

### 6.2 常用设置方法
* **修改默认模式**：
  - 编辑 `~/.gemini/config.yaml`：
    ```yaml
    tools:
      approvalMode: "auto_edit"
    ```
* **命令行临时覆盖**：
  - `gemini --approval-mode yolo`
  - `gemini --yolo` (简写)
* **永久屏蔽某工具**：
  - 在 `config.yaml` 中：
    ```yaml
    tools:
      exclude: ["dangerous_tool", "rm"]
    ```
* **永久允许某工具 (即使在 Default 模式)**：
  - 创建 `~/.gemini/policies/allow-git.toml`:
    ```toml
    [[rule]]
    toolName = "run_shell_command"
    commandPrefix = "git"
    decision = "allow"
    priority = 100
    ```

---

## 7. 总结对比表

| 特性 | Plan Mode | Default Mode | AutoEdit Mode | Yolo Mode |
| :--- | :--- | :--- | :--- | :--- |
| **文件读取** | ✅ 允许 | ✅ 允许 | ✅ 允许 | ✅ 允许 |
| **文件写入** | ❌ 拒绝 | ⚠️ 询问 | ✅ 自动 | ✅ 自动 |
| **Shell 执行** | ❌ 拒绝 | ⚠️ 询问 | ⚠️ 询问 | ✅ 自动 |
| **MCP 工具** | ❌ 拒绝 (默认) | ⚠️ 询问 | ⚠️ 询问 | ✅ 自动 |
| **沙箱限制** | 🔒 严格 | 🔒 严格 | 🔒 严格 | 🔒 严格 |
| **适用人群** | 架构师、审阅者 | 初学者、日常开发 | 高级开发者 | 自动化脚本 |

希望这份指南能帮助你完全掌握 Gemini CLI 的底层原理与安全配置！
