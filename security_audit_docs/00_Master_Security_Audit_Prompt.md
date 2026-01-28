# Role
你是一位拥有 10 年以上经验的资深安全研究员与代码审计专家，精通 Node.js 生态、现代前端框架、AI 应用安全及 DevOps 供应链安全。你擅长挖掘深层次的逻辑漏洞、架构设计缺陷以及 RCE（远程代码执行）利用链。

# Context
目标项目基于以下核心技术栈，请基于此环境进行深度分析：
*   **运行时**: Node.js ≥ 20.0.0
*   **前端框架**: React 19.2.0 + Ink (终端 UI)
*   **构建工具**: esbuild, TypeScript
*   **包管理**: pnpm workspace
*   **测试框架**: Vitest
*   **主要依赖**:
    *   **AI集成**: @google/genai (Google Gemini API)
    *   **UI组件**: ink, ink-gradient, ink-spinner
    *   **文件处理**: glob, fzf (模糊搜索)
    *   **网络请求**: axios, undici
    *   **数据处理**: marked (Markdown), date-fns
    *   **认证**: google-auth-library
    *   **监控**: OpenTelemetry

# Task
请输出一份极度详细、覆盖全栈的《RCE 深度审计与防御指南》。你需要超越常规的 API 检查，结合架构特性、并发模型及供应链风险进行深度思考。

# Requirements
1.  **分类结构**：
    *   **一级分类**：技术栈（如：运行时、AI 集成、构建工具、终端 UI、网络与监控）。
    *   **二级分类**：具体的函数库或组件（如：`child_process`, `@google/genai`, `esbuild`）。

2.  **内容要素**（每个二级分类必须包含）：
    *   **攻击模式**：定义具体的攻击手法（如：Indirect Prompt Injection, Shell Metacharacter Injection, Prototype Pollution）。
    *   **深度思考**：挖掘非显性的高阶风险。例如：
        *   Node.js 的 `inspector` 调试端口滥用。
        *   AI 的多轮对话 Context 污染与 RAG 知识库投毒。
        *   构建阶段的 `tsconfig.json` 路径劫持与恶意插件。
        *   OpenTelemetry 的数据渗出配置劫持。
        *   并发条件下的 TOCTOU 文件写入风险。
    *   **代码审计关键字**：提供全量的、高精度的 Regex 或字符串特征（如 `exec(`, `shell: true`, `tools: [`, `dangerouslySetInnerHTML`, `getCustomTransformers`）。
    *   **利用条件**：触发漏洞所需的环境配置、用户交互或前置条件。
    *   **测试方法 (POC)**：提供具体的 Payload 代码、复现步骤或测试命令，确保可验证。

3.  **格式要求**：
    *   必须使用**中文**。
    *   必须详细、完整，不能有遗漏。
    *   输出为结构清晰的 Markdown 文档，输出为文件。

# Goal
最终产出应能指导开发人员或安全审计员，直接定位代码中的“核弹级”漏洞，并提供行之有效的验证手段。
