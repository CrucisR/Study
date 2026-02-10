# Django 开发安全与 Python 审计指南

本文档涵盖 Django 项目的安全开发规范、常见风险、Python 代码审计关键字，以及 Python 与 Java 在攻击 Payload 上的核心差异。

---

## 1. Django 安全开发指南 (Secure Development)

### 1.1 核心配置安全
Django 提供了强大的内置保护，但配置错误会导致失效。

-   **Debug 模式**: 生产环境必须设置 `DEBUG = False`。开启时会泄露环境变量、代码片段和数据库配置。
-   **ALLOWED_HOSTS**: 必须显式指定允许的域名，防止 HTTP Host 头攻击。
-   **SECRET_KEY**: 必须保密且随机。泄露会导致 Session 劫持、密码重置令牌伪造。
-   **CSRF/XSS**: 
    -   确保 `CsrfViewMiddleware` 开启。
    -   模板中尽量不使用 `|safe` 过滤器，除非非常确定内容安全。

### 1.2 数据交互安全
-   **ORM vs Raw SQL**: 尽量使用 Django ORM (`Model.objects.filter(...)`)，它自动转义参数防止 SQL 注入。
    -   *危险操作*: `Model.objects.raw("SELECT * FROM table WHERE id = %s" % user_input)` (直接拼接字符串)。
-   **文件上传**: 
    -   不要信任用户上传的文件名。
    -   验证文件内容（不仅仅是扩展名）。
    -   使用云存储（S3/OSS）而非本地文件系统存储用户上传，避免 webshell 风险。

### 1.3 部署检查
在部署前，务必运行 Django 自带的安全检查工具：
```bash
python manage.py check --deploy
```

---

## 2. Python 代码审计关键字 (Audit Keywords)

在审计 Python 代码时，全局搜索以下关键字可以快速定位高危点。

| 类别 | 关键字/函数 | 风险描述 |
| :--- | :--- | :--- |
| **命令执行** | `os.system` | 直接执行系统命令，易受注入。 |
| | `os.popen` | 同上。 |
| | `subprocess.call` | 如果 `shell=True`，存在命令注入风险。 |
| | `subprocess.Popen` | 如果 `shell=True`，存在命令注入风险。 |
| | `commands.*` | 旧版本 Python 的命令执行库。 |
| **代码执行** | `eval()` | 执行字符串形式的 Python 代码 (极度危险)。 |
| | `exec()` | 同上。 |
| | `execfile()` | Python 2.x 执行文件。 |
| **反序列化** | `pickle.load` / `pickle.loads` | Python 的序列化库，反序列化恶意数据可直接 RCE。 |
| | `yaml.load` | PyYAML < 5.1 默认不安全，可执行任意代码。应使用 `safe_load`。 |
| | `marshal.load` | 类似 pickle。 |
| **SQL 注入** | `.raw(` | Django ORM 执行原生 SQL。 |
| | `.extra(` | Django ORM 允许注入原生 SQL 片段 (旧版)。 |
| | `execute(` | 直接调用数据库游标时，若使用 f-string 或 format 拼接 SQL。 |
| **XML 攻击** | `xml.etree` | 检查 `Expat` 解析器配置 (DoS)。 |
| | `lxml` | 检查 `resolve_entities=True`, `huge_tree=True` (XXE/DoS)。 |
| | `xml.dom.minidom` | 同样存在实体展开风险。 |
| **其他** | `input()` | Python 2.x 中 `input()` 等同于 `eval()`。 |
| | `mark_safe` | Django 标记字符串为安全，绕过 XSS 过滤。 |
| | `tarfile` / `zipfile` | 解压文件时未检查路径，导致 Zip Slip (文件覆盖)。 |

---

## 3. 常见攻击 Payload：Python vs Java

虽然攻击原理（如 SQL注入、RCE）是通用的，但由于语言特性和底层库的不同，Payload 的构造有很大区别。

### 3.1 模板注入 (SSTI)

*   **原理**: 用户输入被当作模板代码执行。
*   **Python (Jinja2 / Django Templates)**:
    *   利用 Python 的内省机制 (`__class__`, `__mro__`, `__subclasses__`) 寻找可利用的类（如 `subprocess.Popen` 或 `os`）。
    *   **Payload 示例**:
        ```python
        {{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
        {{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}
        ```
*   **Java (Thymeleaf / JSP / Velocity)**:
    *   利用 OGNL 表达式或 EL 表达式调用 Java 静态方法或 Bean。
    *   **Payload 示例 (Thymeleaf)**:
        ```java
        __${T(java.lang.Runtime).getRuntime().exec("calc")}__::.x
        ```
    *   **Payload 示例 (JSP EL)**:
        ```jsp
        ${pageContext.request.getSession().setAttribute("a",Runtime.getRuntime().exec("calc"))}
        ```

### 3.2 反序列化 (Deserialization)

*   **原理**: 还原对象时触发恶意代码。
*   **Python (Pickle)**:
    *   利用 `__reduce__` 魔术方法。当 `pickle.load` 解析时，如果发现 `__reduce__`，会执行其返回的函数。
    *   **Payload 特征**: 通常以 `cos\nsystem\n...` 或 `cposix\nsystem\n` 开头（文本协议），或者是二进制流。
    *   **Payload 示例**:
        ```python
        import pickle, os
        class Evil(object):
            def __reduce__(self):
                return (os.system, ('whoami',))
        payload = pickle.dumps(Evil())
        ```
*   **Java (ObjectInputStream)**:
    *   利用 "Gadget Chains"（利用链）。Java 反序列化不直接执行代码，而是还原对象属性。攻击者构造复杂的对象图，触发常见库（如 CommonsCollections, Spring）中的反射调用链。
    *   **Payload 特征**: 二进制数据以 `AC ED 00 05` (Hex) 开头。
    *   **工具**: `ysoserial`。

### 3.3 命令注入 (Command Injection)

*   **原理**: 在系统 shell 中执行命令。
*   **Python**:
    *   通常注入到 `os.system()` 或 `subprocess.Popen(shell=True)`。
    *   **Payload**: `; ls -la` 或 `$(whoami)` (Linux), `& dir` (Windows)。
    *   *区别点*: Python 的 `subprocess.call(['ls', input])` (列表形式) 默认是安全的，因为它不经过 shell。
*   **Java**:
    *   `Runtime.getRuntime().exec()`。
    *   *区别点*: Java 的 `Runtime.exec` **默认不经过 Shell**。它直接 fork 进程。因此，像 `|`, `&&`, `;` 这种 shell 操作符在 Java `Runtime.exec` 中通常**无效**，除非显式调用 `/bin/sh -c "..."`。
    *   这使得 Java 的命令注入通常比 Python 更难利用（只能执行单一命令，无法轻松管道连接）。

### 3.4 XML 外部实体 (XXE)

*   **Python**:
    *   取决于解析器。`lxml` 默认可能开启，但现代 `xml.etree` (Expat) 默认关闭外部实体。
    *   **Payload**: 标准 XML 实体。
*   **Java**:
    *   历史上 Java 的 `DocumentBuilderFactory` 默认开启外部实体解析（XXE）。
    *   支持更多协议：除了 `http://`, `file://`，Java 还支持 `jar://`, `netdoc://` 等伪协议，攻击面更广。

---

## 4. 总结

| 攻击面 | Python 关注点 | Java 关注点 |
| :--- | :--- | :--- |
| **SSTI** | `__class__`, `__mro__` 魔法方法链 | OGNL, SpEL, EL 表达式 |
| **反序列化** | `pickle`, `yaml`, `__reduce__` | `readObject`, `ysoserial`, `AC ED 00 05` |
| **命令注入** | `os.system`, `shell=True` (容易注入) | `Runtime.exec` (无 Shell 环境，注入难) |
| **Web 框架** | Django/Flask Debug 模式, Secret Key | Spring Actuator, Shiro 反序列化, Fastjson |
