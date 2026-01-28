# 🛡️ 分技术栈攻击面与代码审计指南

本指南基于 Node.js ≥ 20.0.0, React 19 + Ink, @google/genai 等技术栈，以函数库/组件为分类依据，详细列出潜在攻击面、漏洞类型及代码审计关键字。

## 1. 运行时与核心环境 (Node.js ≥ 20.0.0)

| 攻击面/漏洞类型 | 详细说明 | 代码审计关键字 (Regex/String) |
| :--- | :--- | :--- |
| **命令注入 (Command Injection)** | 如果直接将用户输入拼接进系统命令，可能导致任意代码执行。 | `exec(`, `execSync(`, `spawn(`, `spawnSync(`, `fork(`, `execFile` |
| **路径遍历 (Path Traversal)** | 未验证的文件路径可能允许攻击者访问项目目录之外的文件（如 `/etc/passwd`）。 | `fs.readFile`, `fs.createReadStream`, `path.join`, `path.resolve` (关注变量输入) |
| **原型链污染 (Prototype Pollution)** | 修改 `Object.prototype` 可能导致逻辑绕过或 RCE。Node 20+ 有些许缓解但第三方库仍有风险。 | `__proto__`, `constructor`, `prototype`, `_.merge`, `Object.assign` |
| **动态代码执行** | 极其危险，直接执行字符串形式的代码。 | `eval(`, `new Function(`, `vm.runInContext`, `vm.runInNewContext` |
| **环境变量泄露** | 错误地将 `.env` 或 `process.env` 输出到日志或前端。 | `process.env`, `console.log(process.env)` |

## 2. 前端与终端 UI (React 19 + Ink)

虽然 Ink 是终端渲染，但 React 逻辑依然存在风险。

| 攻击面/漏洞类型 | 详细说明 | 代码审计关键字 |
| :--- | :--- | :--- |
| **ANSI 转义序列注入** | 类似 XSS。如果用户输入包含恶意 ANSI 码，可能破坏终端显示、隐藏命令或欺骗用户。 | `<Text>`, `console.log` (直接输出用户输入) |
| **组件注入** | 如果根据用户输入动态选择渲染组件，可能导致非预期的组件加载。 | `React.createElement`, 动态组件名 `<Component />` |
| **状态逻辑漏洞** | React 19 的 Hooks 使用不当可能导致竞态条件或逻辑错误。 | `useActionState`, `useOptimistic`, `useEffect` (依赖项检查) |

## 3. AI 集成 (@google/genai)

这是现代应用的新型攻击面。

| 攻击面/漏洞类型 | 详细说明 | 代码审计关键字 |
| :--- | :--- | :--- |
| **提示词注入 (Prompt Injection)** | 用户通过精心构造的输入，诱导 AI 忽略系统指令，输出敏感信息或执行恶意操作。 | `generateContent`, `sendMessage`, `systemInstruction` |
| **间接提示词注入** | AI 读取了包含恶意指令的外部内容（如网页、邮件），导致 AI 被控制。 | AI 读取外部数据的逻辑入口 |
| **模型拒绝服务 (DoS)** | 构造超长或极其复杂的 Token 序列，消耗 API 配额或导致超时。 | `maxOutputTokens`, 输入长度验证逻辑 |
| **敏感数据泄露** | 将 PII（个人敏感信息）或密钥发送给 AI 模型进行处理。 | 发送给 API 的 payload 审查 |

## 4. 网络请求 (Axios, Undici)

| 攻击面/漏洞类型 | 详细说明 | 代码审计关键字 |
| :--- | :--- | :--- |
| **服务端请求伪造 (SSRF)** | 攻击者控制请求的目标 URL，使服务器攻击内网资源（如 AWS Metadata, 本地 Redis）。 | `axios.get`, `axios.post`, `undici.request`, `fetch` (检查 URL 来源) |
| **HTTP 头注入 (CRLF Injection)** | 用户输入未经过滤直接写入 HTTP 头，可能导致响应拆分或会话固定。 | `headers:`, `setHeader` |
| **不安全的 SSL/TLS** | 开发过程中禁用了证书验证。 | `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED` |

## 5. 文件与数据处理 (Glob, Fzf, Marked, Date-fns)

| 攻击面/漏洞类型 | 详细说明 | 代码审计关键字 |
| :--- | :--- | :--- |
| **正则拒绝服务 (ReDoS)** | `glob` 或 `marked` 在处理极其复杂的嵌套模式时，可能导致 CPU 100% 卡死。 | `glob(`, `marked.parse`, 复杂的 Regex |
| **Markdown XSS (或终端渲染)** | `marked` 默认可能不过滤 HTML。在 Web 是 XSS，在终端可能配合特殊字符造成混淆。 | `marked(`, `sanitize: false`, `dangerouslySetInnerHTML` |
| **参数注入** | 如果 `fzf` 是通过 shell 调用的，可能存在参数注入。 | `fzf` 调用相关的封装函数 |
