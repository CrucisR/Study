# Gemini CLI 技术架构与安全指南

> **文档说明**: 本指南基于对 Gemini CLI (CodeAgent) 源码的逆向工程分析，深入解析其运行模式、权限控制、沙箱机制及配置系统。
> **适用版本**: 基于当前代码库分析 (2026-01-31)

---

## 1. 运行模式深度解析 (Modes & Implementation)

Gemini CLI 的核心安全逻辑由 **策略引擎 (Policy Engine)** 驱动，通过加载不同的 `.toml` 策略文件来定义 Agent 的行为边界。

### 1.1 模式概览与代码映射

| 模式名称 | CLI 参数 | 核心特征 | 对应策略文件 (TOML) |
| :--- | :--- | :--- | :--- |
| **Plan Mode** | `--approval-mode=plan` / `--plan` | **只读/规划**。仅允许读取和生成计划，严禁修改代码或执行 Shell。 | `policies/plan.toml` |
| **Default Mode** | (默认) / `--approval-mode=default` | **人机协作**。读操作自动允许，写操作和 Shell 需人工审批。 | `policies/read-only.toml`<br>`policies/write.toml` |
| **AutoEdit Mode** | `--approval-mode=auto_edit` / `--auto-edit` | **受限自动**。允许自动修改文件，但 Shell 执行仍需审批。 | `policies/write.toml` (带 `modes=["autoEdit"]` 覆盖) |
| **Yolo Mode** | `--approval-mode=yolo` / `--yolo` | **全自动 (高危)**。允许所有操作，包括 Shell 重定向和系统级修改。 | `policies/yolo.toml` |
| **Shell Mode*** | (非独立模式) | 指 Shell 工具 (`run_shell_command`) 在上述各模式下的表现。 | N/A (由各模式策略共同决定) |

### 1.2 实现原理深度剖析

#### 代码入口与参数解析
*   **入口文件**: `packages/cli/src/config/config.ts`
*   **逻辑**: 使用 `yargs` 解析命令行参数。`--yolo` 是 `--approval-mode=yolo` 的快捷方式。
    ```typescript
    // packages/cli/src/config/config.ts
    .option('approval-mode', {
      choices: ['default', 'auto_edit', 'yolo', 'plan'],
      description: 'Set the approval mode...'
    })
    ```

#### 策略加载机制
*   **加载器**: `packages/core/src/policy/toml-loader.ts`
*   **引擎**: `packages/core/src/policy/policy-engine.ts`
*   **原理**: 系统启动时，会加载 `packages/core/src/policy/policies/` 下的所有 TOML 文件。每个规则都有 `priority` (优先级) 和 `modes` (适用模式)。
    *   **Priority Tier**: Admin (3.x) > User (2.x) > Default (1.x)。
    *   **Mode Matching**: 引擎在检查工具调用时，会过滤出 `modes` 包含当前运行模式的规则。

---

## 2. 命令执行与权限控制 (Command Execution)

Gemini CLI 没有传统的“命令黑白名单”，而是采用 **基于工具 (Tool-Based) 的权限控制**。Shell 命令被视为一个特殊的工具 `run_shell_command`。

### 2.1 权限矩阵

| 模式 | Shell 执行权限 | 关键代码证据 |
| :--- | :--- | :--- |
| **Plan** | ⛔ **DENY (禁止)** | `plan.toml`: `[[rule]] decision = "deny" priority = 20` |
| **Default** | 👤 **ASK_USER (询问)** | `write.toml`: `[[rule]] toolName = "run_shell_command" decision = "ask_user"` |
| **AutoEdit** | 👤 **ASK_USER (询问)** | (同上，AutoEdit 仅覆盖了 `write_file`，未覆盖 Shell) |
| **Yolo** | ✅ **ALLOW (允许)** | `yolo.toml`: `[[rule]] decision = "allow" priority = 999` |

### 2.2 Shell 深度防护机制
*   **AST 解析**: `packages/core/src/utils/shell-utils.ts` 使用 `web-tree-sitter` 将复合命令（如 `git add . && git commit`）拆解为独立子命令。
*   **递归检查**: 每个拆解后的子命令都会重新经过策略引擎检查。只要有一个子命令被拒绝或需要询问，整个命令链都会被阻断。
*   **重定向降级**: 在非 Yolo 模式下，如果检测到输出重定向 (`>`), 即使命令本身被允许，引擎也会强制降级为 `ASK_USER` 以防止文件覆盖攻击。

---

## 3. 文件系统沙箱机制 (File System Sandbox)

文件安全依靠 **策略规则** 和 **安全检查器 (Safety Checker)** 双重保障。

### 3.1 核心组件：AllowedPathChecker
*   **源码位置**: `packages/core/src/safety/built-in.ts`
*   **实现逻辑**:
    1.  解析目标路径为绝对路径 (`path.resolve`)。
    2.  **防逃逸**: 使用 `fs.realpathSync` 逐级解析父目录，检测并还原符号链接，防止通过软链跳出工作区。
    3.  比对: 检查规范化后的路径是否以 `workspace` 或 `cwd` 开头。

### 3.2 模式差异与安全隐患 (Critical)

| 模式 | 读权限 (`read_file`) | 写权限 (`write_file`) | 沙箱状态 |
| :--- | :--- | :--- | :--- |
| **Plan** | ✅ 允许 | ⚠️ **仅限计划文件** | **安全** (正则白名单硬编码) |
| **Default** | ✅ 允许 (无限制) | 👤 **询问用户** | **依赖人工** (CLI 提示路径) |
| **AutoEdit** | ✅ 允许 | ✅ **自动允许** | ❌ **失效 (Bug)** |
| **Yolo** | ✅ 允许 | ✅ **自动允许** | ❌ **无沙箱** |

> **⚠️ 安全警示**: 分析发现 `toml-loader.ts` 的 Zod Schema 定义缺失 `safety_checker` 字段，导致 `AutoEdit` 模式下的路径检查器未被加载。这意味着目前 AutoEdit 模式下 Agent 可以写入系统任意文件（如 `/etc/hosts`），这是极高风险点。

---

## 4. 用户配置与扩展 (Configuration)

用户可以通过三层配置体系来定制 Gemini CLI 的行为，优先级从高到低：

### 4.1 配置优先级
1.  **CLI 参数** (最高优先级): 运行时指定的 flag，如 `--yolo`。
2.  **用户配置文件**: `~/.gemini/settings.json`。
3.  **系统默认配置**: 内置的 defaults。

### 4.2 关键配置项
用户可以在 `~/.gemini/settings.json` 中配置以下内容：

```json
{
  "tools": {
    "allowedTools": ["read_file", "list_directory"], // 始终允许的工具
    "enableHooks": true // 启用钩子脚本
  },
  "mcp": {
    "servers": { ... } // 配置 MCP 服务器
  },
  "sandbox": {
    "mode": "auto" // 沙箱隔离级别
  }
}
```

### 4.3 自定义策略 (User Policy)
用户还可以在 `~/.gemini/policies/` 目录下创建自定义 `.toml` 文件。这些规则会被加载到 **User Tier (2.x)**，其优先级高于系统内置规则 (Default Tier 1.x)，但低于 CLI 参数。

---

## 5. 架构设计哲学 (Design Philosophy)

### 5.1 纵深防御 (Defense in Depth)
Gemini CLI 不依赖单一防线：
1.  **第一道防线 (Policy)**: 粗粒度的 TOML 规则（允许/禁止/询问）。
2.  **第二道防线 (Safety Checker)**: 细粒度的参数检查（路径是否在工作区？）。
3.  **第三道防线 (Human-in-the-loop)**: 关键操作（Shell/Write）默认回退到 `ASK_USER`，强制人工介入。

### 5.2 灵活性与安全的平衡
*   **Plan Mode** 展示了“最小权限原则”的极致：只读，仅允许输出特定格式的计划。
*   **Default Mode** 是平衡点：读取方便（利于分析），写入谨慎（防止破坏）。
*   **Yolo Mode** 则是为受信任环境（如容器化沙箱）设计的完全放权模式。

---

## 总结对比表格

| 特性 | Plan Mode | Default Mode | AutoEdit Mode | Yolo Mode |
| :--- | :--- | :--- | :--- | :--- |
| **适用场景** | 需求分析、代码阅读 | 日常开发、结对编程 | 快速迭代、重构 | 容器内运行、CI/CD |
| **文件读取** | ✅ 允许 | ✅ 允许 | ✅ 允许 | ✅ 允许 |
| **文件写入** | ⚠️ 受限 (仅Plan文件) | 👤 需批准 | ⚠️ **自动允许 (有越权风险)** | ✅ 允许 |
| **Shell执行**| ⛔ 禁止 | 👤 需批准 | 👤 需批准 | ✅ 允许 |
| **联网请求** | ⛔ 禁止 | 👤 需批准 | 👤 需批准 | ✅ 允许 |
| **推荐指数** | ⭐⭐⭐⭐⭐ (安全) | ⭐⭐⭐⭐⭐ (推荐) | ⭐⭐ (慎用) | ⭐ (仅限沙箱) |
