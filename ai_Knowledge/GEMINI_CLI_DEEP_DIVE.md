# Gemini CLI 深度技术架构与安全指南 (Deep Dive)

本文档基于对 Gemini CLI (`gemini-cli`) 源代码的逆向工程分析，深入揭示其核心运行机制、安全策略实现及代码级细节。

## 1. 核心架构：策略引擎 (Policy Engine)

Gemini CLI 的安全核心是 `PolicyEngine`，它决定了每一个工具调用（Tool Call）是被允许、拒绝还是需要用户审批。

### 1.1 决策流程
`PolicyEngine` 的决策基于以下要素：
1.  **当前模式 (ApprovalMode)**: `default`, `autoEdit`, `yolo`, `plan`。
2.  **策略规则 (Policy Rules)**: 来自 TOML 文件的静态规则。
3.  **动态检查器 (Safety Checkers)**: 运行时代码检查（如路径检查）。

### 1.2 优先级系统 (Priority System)
代码位置: `packages/core/src/policy/toml-loader.ts`

系统将策略分为三个层级 (Tier)，并计算最终优先级：
-   **Tier 1 (Default)**: 内置策略。
-   **Tier 2 (User)**: 用户配置文件 (`~/.gemini/config.toml`).
-   **Tier 3 (Admin)**: 系统级强制策略。

**优先级计算公式**:
```typescript
// transformPriority function
return tier + priority / 1000;
```
例如，用户定义的优先级 `10` 会变成 `2.010`，高于内置的优先级 `999` (即 `1.999`)。这确保了用户配置永远覆盖内置默认值。

---

## 2. 运行模式深度解析 (Modes Implementation)

Gemini CLI 的“模式”本质上是一组预定义的策略规则集合。以下是各模式的代码级实现。

### 2.1 Plan Mode (计划模式)
**核心逻辑**: 极其严格的白名单机制，仅允许读取和思考，禁止副作用（除了在特定目录写计划）。

-   **策略文件**: `packages/core/src/policy/policies/plan.toml`
-   **关键代码段**:

```toml
# 1. 默认拒绝所有操作 (Catch-All Deny)
[[rule]]
decision = "deny"
priority = 20
modes = ["plan"]

# 2. 白名单允许只读工具 (Read-Only Whitelist)
[[rule]]
toolName = "read_file" # 以及 glob, search_file_content 等
decision = "allow"
priority = 50
modes = ["plan"]

# 3. 特殊例外：允许在临时目录写计划文件
[[rule]]
toolName = "write_file"
decision = "allow"
priority = 50
modes = ["plan"]
argsPattern = "\"file_path\":\"[^\"]+/\\.gemini/tmp/[a-f0-9]{64}/plans/[a-zA-Z0-9_-]+\\.md\""
```

此外，在 `packages/core/src/tools/tool-names.ts` 中还定义了硬编码的工具列表 `PLAN_MODE_TOOLS`，在系统初始化层面就限制了加载的工具。

### 2.2 Default Mode (默认模式)
**核心逻辑**: “只读操作自动允许，写操作/Shell操作需询问”。

这是通过组合 `read-only.toml` (无模式限制，全局生效) 和 `write.toml` (无模式限制，全局生效) 实现的。

-   **策略文件**: `packages/core/src/policy/policies/read-only.toml` (Allow) + `write.toml` (Ask User)
-   **关键代码段 (write.toml)**:

```toml
# 敏感操作默认为 "ask_user"
[[rule]]
toolName = "run_shell_command"
decision = "ask_user"
priority = 10

[[rule]]
toolName = "write_file"
decision = "ask_user"
priority = 10
```

### 2.3 AutoEdit Mode (自动编辑模式)
**核心逻辑**: 在默认模式基础上，对文件修改操作“开绿灯”，但仍保持 Shell 操作的询问机制。

-   **策略文件**: `packages/core/src/policy/policies/write.toml`
-   **关键代码段**:

```toml
# 针对 autoEdit 模式的特定覆盖规则
[[rule]]
toolName = "replace"
decision = "allow"     # 直接允许，不再询问
priority = 15          # 优先级 15 > 默认的 10
modes = ["autoEdit"]

[[rule]]
toolName = "write_file"
decision = "allow"
priority = 15
modes = ["autoEdit"]
```

### 2.4 Yolo Mode (激进模式)
**核心逻辑**: 允许一切，包括 Shell 重定向风险操作。

-   **策略文件**: `packages/core/src/policy/policies/yolo.toml`
-   **关键代码段**:

```toml
[[rule]]
decision = "allow"
priority = 999        # 极高优先级 (在 Default Tier 中为 1.999)
modes = ["yolo"]
allow_redirection = true # 允许 Shell 重定向 (如 > 或 >>)
```

### 2.5 关于 "Shell Mode" 的说明
在代码库中**不存在**名为 `shell` 的 `ApprovalMode`。用户可能指的是：
1.  **交互式 Shell (REPL)**: 通过 `gemini shell` 启动。
2.  **Shell 命令执行权限**: 由 `run_shell_command` 工具控制。

在 Default/AutoEdit 模式下，`run_shell_command` 默认为 `ask_user`。只有在 `yolo` 模式下才会被自动允许。

---

## 3. 安全沙箱与防护机制 (Security & Sandboxing)

Gemini CLI 的沙箱并非 Docker 容器，而是基于**路径规范化与检查**的进程级防护。

### 3.1 文件系统沙箱 (Allowed Path Checker)
**代码位置**: `packages/core/src/safety/built-in.ts`

该检查器确保所有文件操作都限制在当前工作目录 (CWD) 或明确信任的目录中。

```typescript
// 伪代码逻辑还原
class AllowedPathChecker {
    isPathAllowed(targetPath: string, allowedDirs: string[]): boolean {
        const resolvedTarget = path.resolve(targetPath);
        
        for (const dir of allowedDirs) {
            const relative = path.relative(dir, resolvedTarget);
            // 检查路径是否在 allowedDirs 下 (即 relative 不以 .. 开头)
            if (!relative.startsWith('..') && !path.isAbsolute(relative)) {
                return true;
            }
        }
        return false;
    }
}
```

### 3.2 Shell 重定向防护 (Redirection Downgrade)
**代码位置**: `packages/core/src/policy/policy-engine.ts`

即使策略允许执行 Shell 命令，如果命令中包含危险的重定向符号（可能覆盖系统文件），系统会强制降级为“询问用户”。

```typescript
// packages/core/src/policy/policy-engine.ts
private shouldDowngradeForRedirection(command: string, rule: PolicyRule): boolean {
    if (rule.allow_redirection) return false; // Yolo 模式通常设为 true
    
    // 简单的正则检查，防止 > 或 >>
    return />{1,2}/.test(command);
}
```

---

## 4. 模式与权限映射表 (Permission Matrix)

| 功能/工具 | Plan Mode | Default Mode | AutoEdit Mode | Yolo Mode |
| :--- | :--- | :--- | :--- | :--- |
| **读取 (read_file)** | ✅ Allow | ✅ Allow | ✅ Allow | ✅ Allow |
| **搜索 (search)** | ✅ Allow | ✅ Allow | ✅ Allow | ✅ Allow |
| **写入 (write_file)** | ❌ Deny* | ⚠️ Ask User | ✅ Allow | ✅ Allow |
| **替换 (replace)** | ❌ Deny | ⚠️ Ask User | ✅ Allow | ✅ Allow |
| **Shell (run_shell)** | ❌ Deny | ⚠️ Ask User | ⚠️ Ask User | ✅ Allow |
| **Shell 重定向** | ❌ Deny | ⚠️ Ask User (强制) | ⚠️ Ask User (强制) | ✅ Allow |

*\*注: Plan Mode 仅允许写入 `.gemini/tmp/...` 下的计划文件。*

## 5. 用户配置加载机制

**代码位置**: `packages/cli/src/config/settings.ts`

配置加载遵循覆盖原则：
1.  **System Defaults**: 系统预设。
2.  **User Settings**: `~/.gemini/config.toml` (或 OS 对应位置)。
3.  **Workspace Settings**: 项目根目录 `.gemini/config.toml` (若信任)。

代码使用 `customDeepMerge` 函数合并这些配置，确保用户配置拥有更高优先级。
