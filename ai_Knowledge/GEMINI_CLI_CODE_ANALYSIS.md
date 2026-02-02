# Gemini CLI 核心模式与代码实现深度解析

本文档基于对 Gemini CLI 源码的逆向分析，详细解答关于 Plan、Default、AutoEdit、Yolo 及 "Shell" 模式的实现原理、策略映射及核心代码逻辑。

## 1. 核心结论：模式定义的真相

在代码库 (`packages/core/src/policy/types.ts`) 中，`ApprovalMode` 枚举**仅定义了 4 种模式**：

```typescript
export enum ApprovalMode {
  DEFAULT = 'default',
  AUTO_EDIT = 'autoEdit',
  YOLO = 'yolo',
  PLAN = 'plan',
}
```

**关于 "Shell Mode"**:
代码中**不存在**名为 `shell` 的独立运行模式。用户常提到的 "Shell Mode" 通常指代以下两种情况之一：
1.  **Shell 工具权限**: 指 `run_shell_command` 工具在当前模式下的执行权限（如在 Yolo 模式下自动允许）。
2.  **交互式 Shell**: 指通过 `gemini shell` 命令启动的 REPL 环境（这是 UI 交互方式，而非安全策略模式）。

---

## 2. 各模式深度解析 (实现原理与代码证据)

### 2.1 Plan Mode (计划模式)
**策略**: **“纯思考，零副作用”**。仅允许读取信息和生成思维链，严禁修改代码或执行命令（唯一的例外是写入生成的 Plan 文档）。

*   **实现原理**: 双重锁死机制。
    1.  **代码级硬编码白名单**: 在工具加载阶段就过滤掉危险工具。
    2.  **策略级默认拒绝**: 即使工具被加载，策略也默认 Deny。

*   **核心代码证据**:

    **A. 工具白名单 (`packages/core/src/tools/tool-names.ts`)**
    ```typescript
    export const PLAN_MODE_TOOLS = [
      'read_file',
      'search_file_content',
      'list_directory',
      'glob',
      'ask_user',
      // ... 注意：没有 run_shell_command 或 replace
    ];
    ```

    **B. 策略锁死 (`packages/core/src/policy/policies/plan.toml`)**
    ```toml
    # 1. Catch-All Deny (优先级 20)
    [[rule]]
    decision = "deny"
    priority = 20
    modes = ["plan"]

    # 2. 特殊例外：允许写入计划文件 (优先级 50 > 20)
    [[rule]]
    toolName = "write_file"
    decision = "allow"
    priority = 50
    modes = ["plan"]
    # 仅允许写入 .gemini/tmp 下的 .md 文件
    argsPattern = "\"file_path\":\"[^\"]+/\\.gemini/tmp/[a-f0-9]{64}/plans/[a-zA-Z0-9_-]+\\.md\""
    ```

### 2.2 Default Mode (默认模式)
**策略**: **“读操作放行，写/执行操作询问”**。这是最安全的日常开发模式。

*   **实现原理**: 组合策略。
    *   利用 `read-only.toml` 中的全局 Allow 规则（无模式限制，通用于所有模式）。
    *   利用 `write.toml` 中的全局 Ask User 规则。

*   **核心代码证据**:

    **A. 写操作拦截 (`packages/core/src/policy/policies/write.toml`)**
    ```toml
    # 没有指定 modes，因此适用于 Default 模式
    [[rule]]
    toolName = "write_file"
    decision = "ask_user"
    priority = 10

    [[rule]]
    toolName = "run_shell_command"
    decision = "ask_user"
    priority = 10
    ```

### 2.3 AutoEdit Mode (自动编辑模式)
**策略**: **“文件修改放行，Shell 执行仍需询问”**。适用于用户信任 AI 进行代码重构的场景。

*   **实现原理**: 局部覆盖 (Override)。
    *   在 `write.toml` 中，专门针对 `autoEdit` 模式定义了高优先级的 Allow 规则。

*   **核心代码证据**:

    **A. 覆盖写权限 (`packages/core/src/policy/policies/write.toml`)**
    ```toml
    # 针对 autoEdit 模式的特定规则 (优先级 15 > 默认的 10)
    [[rule]]
    toolName = "replace"
    decision = "allow"
    priority = 15
    modes = ["autoEdit"]

    [[rule]]
    toolName = "write_file"
    decision = "allow"
    priority = 15
    modes = ["autoEdit"]
    ```
    *注意：这里没有包含 `run_shell_command`，所以 Shell 操作回退到优先级 10 的 `ask_user`。*

### 2.4 Yolo Mode (激进模式)
**策略**: **“全权委托”**。允许一切操作，包括潜在危险的 Shell 重定向。

*   **实现原理**: 超高优先级允许 + 安全检查豁免。

*   **核心代码证据**:

    **A. 全局放行 (`packages/core/src/policy/policies/yolo.toml`)**
    ```toml
    [[rule]]
    decision = "allow"
    priority = 999  # 极高优先级，覆盖所有默认规则
    modes = ["yolo"]
    allow_redirection = true # 关键标志：允许 Shell 重定向
    ```

    **B. 豁免重定向检查 (`packages/core/src/policy/policy-engine.ts`)**
    ```typescript
    // 伪代码：在检查 Shell 命令时
    if (rule.allow_redirection) {
        // 如果是 Yolo 模式，跳过危险字符检查
        return PolicyDecision.ALLOW;
    }
    // 否则，如果包含 > 或 >>，强制降级为 ASK_USER
    if (hasRedirection(command)) {
        return PolicyDecision.ASK_USER;
    }
    ```

### 2.5 "Shell Mode" (Shell 权限深度分析)
虽然不是独立模式，但 Shell 权限是安全的核心。

*   **实现原理**:
    *   默认情况下，`run_shell_command` 总是 `ask_user`。
    *   即使策略允许，`PolicyEngine` 还会进行二次检查（Regex 检查）。

*   **核心代码证据 (`packages/core/src/policy/policy-engine.ts`)**:
    ```typescript
    private checkShellCommand(command: string, rule: PolicyRule): PolicyDecision {
        // 1. 检查是否包含危险的重定向符
        const hasDangerousRedirection = />{1,2}/.test(command);
        
        // 2. 如果包含重定向且规则不允许 (即非 Yolo)，强制降级
        if (hasDangerousRedirection && !rule.allow_redirection) {
            return PolicyDecision.ASK_USER;
        }
        
        return rule.decision;
    }
    ```

---

## 3. 模式与权限映射全景图

位置：`packages/core/src/policy/policies/*.toml` 文件的聚合结果。

| 权限 / 模式 | Plan Mode | Default Mode | AutoEdit Mode | Yolo Mode |
| :--- | :--- | :--- | :--- | :--- |
| **读文件 (Read)** | ✅ Allow | ✅ Allow | ✅ Allow | ✅ Allow |
| **搜索 (Search)** | ✅ Allow | ✅ Allow | ✅ Allow | ✅ Allow |
| **改代码 (Replace)** | ❌ Deny | ⚠️ Ask User | ✅ Allow | ✅ Allow |
| **写文件 (Write)** | ❌ Deny* | ⚠️ Ask User | ✅ Allow | ✅ Allow |
| **Shell 命令** | ❌ Deny | ⚠️ Ask User | ⚠️ Ask User | ✅ Allow |
| **Shell 重定向** | ❌ Deny | ⚠️ Ask User | ⚠️ Ask User | ✅ Allow |

*\*Plan Mode 仅允许写计划文件*

## 4. 安全沙箱实现原理 (Sandboxing)

用户关心的“沙箱”在代码中主要体现为 **`AllowedPathChecker`**。

*   **位置**: `packages/core/src/safety/built-in.ts`
*   **原理**: 它不是虚拟机，而是路径检查器。它确保所有文件操作的目标路径都位于 `cwd` (当前工作目录) 或用户明确信任的目录中。

*   **核心代码片段**:
    ```typescript
    // 简化的逻辑展示
    isPathAllowed(targetPath: string): boolean {
        const resolvedPath = path.resolve(targetPath);
        const allowedDirs = [process.cwd(), ...trustedDirs];
        
        return allowedDirs.some(dir => {
            const rel = path.relative(dir, resolvedPath);
            // 确保路径在 dir 内部 (不以 .. 开头，且非绝对路径)
            return !rel.startsWith('..') && !path.isAbsolute(rel);
        });
    }
    ```

## 5. 用户配置系统的代码实现

*   **位置**: `packages/cli/src/config/settings.ts`
*   **加载逻辑**:
    代码使用 `customDeepMerge` 函数，按照以下顺序合并配置（后覆盖前）：
    1.  Schema Defaults (代码内置默认值)
    2.  System Defaults (`system-defaults.json`)
    3.  User Settings (`~/.gemini/config.toml`)
    4.  Workspace Settings (`.gemini/config.toml`)

这确保了用户在项目级的配置拥有最高优先级。
