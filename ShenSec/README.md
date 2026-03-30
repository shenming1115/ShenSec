<div align="center">
  <img src="./docs/logo_placeholder.png" alt="ShenSec Logo" width="150" onerror="this.style.display='none'">
  
  <h1>🛡️ ShenSec</h1>
  <p><b>A Modern Python-based Web Security Auditor / 现代 Python Web 安全审计工具</b></p>

  <p>
    <a href="https://pypi.org/project/shensec/"><img src="https://img.shields.io/pypi/v/shensec.svg" alt="PyPI Version"></a>
    <a href="https://pypi.org/project/shensec/"><img src="https://img.shields.io/pypi/pyversions/shensec.svg" alt="Python Versions"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
    <img src="https://img.shields.io/badge/GUI-PySide6-brightgreen" alt="GUI: PySide6">
  </p>

  <p>
    <a href="#english">English</a> | <a href="#中文">中文</a>
  </p>
</div>

---

<h2 id="english">🇬🇧 English</h2>

**ShenSec** is a Python-based package designed to help developers perform basic web security auditing and generate useful analytical reports. Instead of acting as an offensive hacking tool, the package focuses on defensive auditing, allowing users to inspect their own websites or APIs and identify common weaknesses in a structured way.

### 💡 Why ShenSec?
ShenSec is designed for developers who want a fast, no-noise security audit without running heavy enterprise scanners.
- **Lightweight**: Minimal dependencies, runs in seconds.
- **Developer-friendly**: Easy to integrate into your existing Python scripts.
- **No offensive payloads**: Strictly defensive. Safe to run on production.
- **Clear risk summarization**: Generates HTML/Markdown/JSON reports instantly.

### 🖥️ Preview

**Graphical Interface (GUI)**

![ShenSec GUI Dashboard](./docs/gui_dashboard.png)
*(Note: Please run `shensec gui` locally, take a screenshot, and upload it as `docs/gui_dashboard.png`)*

**CLI Output**
```text
Risk Rating: HIGH

Findings:
- Critical: Missing Strict-Transport-Security (HSTS)
- High: Cookie without HttpOnly flag
```

### ✨ Features
- **Security Headers**: Check for missing or misconfigured security headers (HSTS, CSP, X-Frame-Options).
- **Cookies**: Audit cookie flags for security (Secure, HttpOnly, SameSite).
- **JWT Inspection**: Validate JWT structure and identify weak algorithms like `alg: none`.
- **Reporting**: Generate easily readable reports in format of your choice, including `markdown`, `json`, and `html`.
- **Modern UI**: Intuitive Typer CLI and an optional rich graphical interface using PySide6.

### 📦 Installation

**For Users (via pip)**
```bash
pip install shensec
```

**GUI Support**  
If you wish to use the graphical user interface, make sure to install the optional `gui` dependencies:
```bash
pip install "shensec[gui]"
```

**For Contributors (via uv)**
```bash
git clone https://github.com/shenming1115/Web-Security-Test-.git
cd Web-Security-Test-/ShenSec
uv sync
uv build
```

### 🚀 Quick Start

**Using the Graphical Dashboard (GUI)**
```bash
shensec gui
```
> *(The GUI allows interactive filtering, result sorting, and one-click markdown exports)*

**CLI Core Scans**
Run a quick security audit against a host and output a markdown report on the terminal:
```bash
shensec scan https://example.com
```

Save the output as a fully styled HTML file:
```bash
shensec scan https://example.com --format html -o result.html
```

Analyze a JWT locally alongside a target check:
```bash
shensec scan https://example.com --jwt "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ."
```

### 💻 Library Usage

You can also import ShenSec into your own Python tools or scripts:

```python
import httpx
from shensec import scan_target, analyze_response, analyze_jwt, generate_report

# 1. Direct scanning
result = scan_target("https://example.com", timeout=5.0)

# Output the findings
print(f"Risk Rating: {result.risk_rating.value}")
print(generate_report(result, "markdown"))
```

### 🛣️ Roadmap
- [x] Basic security header detection
- [x] JWT inspection module
- [x] Terminal CLI and JSON/HTML reporting
- [x] PySide6 Graphical Dashboard with interactive filtering
- [ ] Multi-endpoint scanning (crawler)
- [ ] Advanced JWT analysis
- [ ] Export directly to PDF

### ⚠️ Disclaimer & Non-goals
ShenSec is designed **strictly for defensive auditing and quick security posture checks**. 
- It is **not** an enterprise DAST/SAST scanner and does not send offensive payloads or execute SQL injection/Cross-Site Scripting attacks.
- It focuses on **"Low Hanging Fruit"**: HTTP Header configurations, flag correctness on Cookies, and glaring configuration issues in JWT tokens.

---

<h2 id="中文">🇨🇳 中文</h2>

**ShenSec** 是一个基于 Python 的 Web 安全审计工具，旨在帮助开发者进行基础架构级安全扫描，并生成清晰的分析报告。ShenSec 并非攻击性的黑客工具，而是专注于防守型审计，协助用户以结构化的方式检查自己的网站或 API 以识别常见的错误配置。

### 💡 为什么选择 ShenSec?
ShenSec 专为希望获得快速、无干扰体验的开发者设计，避免了运行笨重企业级扫描器的繁琐。
- **极致轻量**: 极少的依赖，秒级启动与扫描。
- **开发者友好**: 可以无缝集成到你的 Python 自动化脚本中。
- **无攻击性**: 绝对防守型，不会发送恶意 payload，可安全用于生产环境。
- **清晰的风险报告**: 瞬间生成 HTML、Markdown 或 JSON 格式的审计报告。

### 🖥️ 运行效果展示

**图形化界面 (GUI)**

![ShenSec GUI Dashboard](./docs/gui_dashboard.png)
*(注：这里预留了截图位置，请在本地运行 `shensec gui` 并截图保存至项目 `docs/gui_dashboard.png`)*

**命令行输出 (CLI)**
```text
风险评级: HIGH

发现安全问题:
- 严重 (Critical): 缺少 Strict-Transport-Security (HSTS)
- 高危 (High): Cookie 缺少 HttpOnly 属性
```

### ✨ 核心特性
- **安全响应头 (Security Headers)**: 检查是否缺失或错误配置安全响应头（例如 HSTS, CSP, X-Frame-Options）。
- **Cookie 安全**: 审计 Cookie 标记的安全性（例如 Secure, HttpOnly, SameSite 属性）。
- **JWT 检查**: 验证 JWT 结构并识别诸如 `alg: none` 的弱加密算法风险。
- **丰富的报告生成**: 支持生成多种格式的报告，包含 `markdown`, `json`, 以及 `html`。
- **现代化界面**: 底层由 Typer 驱动的强大命令行界面（CLI），并提供基于 PySide6 的图形用户界面（GUI）。

### 📦 安装指南

**普通用户推荐 (使用 pip)**
```bash
pip install shensec
```

**通过带界面的版本安装（GUI 支持）**  
如果您希望使用图形界面来查看扫描结果：
```bash
pip install "shensec[gui]"
```

**开发者/贡献者推荐 (使用 uv)**
```bash
git clone https://github.com/shenming1115/Web-Security-Test-.git
cd Web-Security-Test-/ShenSec
uv sync
uv build
```

### 🚀 快速开始

**启动图形界面控制台 (GUI)**
```bash
shensec gui
```
> *(图形界面支持交互式筛选、结果排序及一键导出分析报告)*

**使用命令行 (CLI) 快速扫描**  
对目标站点进行安全审查，并在终端输出 markdown 格式的报告：
```bash
shensec scan https://example.com
```

将扫描报告导出为样式精美的 HTML 文件：
```bash
shensec scan https://example.com --format html -o result.html
```

在扫描网站的同时分析本地 JWT 令牌：
```bash
shensec scan https://example.com --jwt "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ."
```

### 💻 作为开发库使用 (SDK)

您也可以把 ShenSec 作为一个依赖库，导入到自己的 Python 脚本或自动化工具中：

```python
import httpx
from shensec import scan_target, analyze_response, analyze_jwt, generate_report

# 1. 发起扫描请求
result = scan_target("https://example.com", timeout=5.0)

# 输出风险评级及报告
print(f"风险评级: {result.risk_rating.value}")
print(generate_report(result, "markdown"))
```

### 🛣️ 演进路线图 (Roadmap)
- [x] 基础安全响应头检测
- [x] JWT 令牌安全分析
- [x] 命令行接口 (CLI) 与多格式报告输出
- [x] 基于 PySide6 的图形化仪表盘与数据筛选
- [ ] 多端点深度扫描 (爬虫集成)
- [ ] 更高级的 JWT 分析机制
- [ ] 直接导出 PDF 报告功能

### ⚠️ 免责声明及限制
ShenSec 被设计为 **严格用于防御性审计与快速安全态势检查**。
- 它 **不是** 替代企业级的 DAST/SAST 商业工具，不会发送恶意 payload、进行模糊测试(Fuzzing)、或是执行 SQL 注入和 XSS 攻击。
- 工具的主要重心在于 **基础配置纠错**：如 HTTP Header 配置失误、Cookie 属性不当，以及 JWT 令牌等常见安全漏洞。

<br/>

<div align="center">
  <i>Developed with ❤️ for Open Source Security.</i>
</div>
