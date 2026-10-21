# Windows 桌面使用教程

ShenSec 0.5.0b1 · Windows 10/11 x64。桌面程序自带 Python 和 Qt，不需要 uv、命令行或管理员权限。界面目前为英文，本文提供对应按钮名称。

## 下载、打开与升级

从 [官方 Releases](https://github.com/shenming1115/ShenSec/releases/tag/v0.5.0b1) 下载：

| 文件 | 操作 | 适用场景 |
| --- | --- | --- |
| `ShenSec-0.5.0b1-windows-x64.exe` | 下载后直接双击 | 想要单个文件；启动时需解包运行库 |
| `ShenSec-0.5.0b1-windows-x64-portable.zip` | 完整解压，再打开 `ShenSec.exe` | 日常启动更快；保留 `_internal` 文件夹 |
| `SHA256SUMS.txt` | 与下载文件的 SHA-256 比对 | 确认下载文件完整性 |

不要直接在 ZIP 预览中启动 exe。此测试版未代码签名，系统可能显示未知发布者提示；确认官方来源和校验值后，按设备或组织策略处理。不要关闭系统安全功能。

顶部 **User guide** 打开离线教程，**Open history folder** 打开数据目录。升级时退出程序，替换 exe 或解压新版本即可；用户目录中的历史会保留。

## 五分钟演示

1. 点击 **Try local demo**。界面保持响应，准备完成后打开独立演示窗口。
2. **Permission matrix** 展示 4 个角色 × 2 个接口的 8 项预期。最新扫描应为 PASSED，3 项已修复，4 次会话续期。
3. 左侧 **SCAN HISTORY** 选择较早的记录，查看修复前的红色格子。点击格子，详情显示实际状态、允许／拒绝预期、资源成功断言与证据。
4. 选择最新记录，在 **Sessions** 查看身份登录与刷新次数；在 **Findings & changes** 筛选变化。
5. 点击 **Export report** 保存离线 HTML、JSON、Markdown 或 SARIF。可重新审计演示项目。
6. 关闭演示窗口会停止 127.0.0.1 测试服务并删除演示数据；日常项目在原主窗口中。

![修复前的权限矩阵：3 项超出预期的访问](permissions-workbench.png)

演示应用刻意使用本机 HTTP，所以仍会出现传输相关观察。矩阵是明确配置的权限预期验证，不会自动发现业务的全部授权规则。

## 创建日常项目

1. 在主窗口点击 **+ New**，填写项目名。
2. **Targets** 每行粘贴一个完整 URL，或 **Import URLs…** 导入列表。OpenAPI JSON 可从 **API requests** 导入，检查参数绑定和跳过原因。
3. 设置线程数、超时和风险门槛。在 **Speed & reliability** 控制每个来源的速率与安全请求重试。
4. 点击 **Save project**。以后从左侧项目列表打开即可。

## 使用现有登录会话

打开 **Credentials**，填写来源范围，例如 `https://staging.example.com`，然后临时粘贴 Bearer 或 Cookie。自定义 Header 使用 `Header-Name=ENV_VARIABLE` 环境变量引用。准确设置验证 URL 与成功断言可以区分真实接口响应和登录页。

临时凭据只留在当前进程内存。切换项目、清除会话或退出后需要重新输入。配置导出保留环境变量名；不要把凭据值填入标题、URL、描述或其他非凭据字段。响应中的未知敏感业务字段仍需人工检查，工具并非通用数据脱敏器。

## 自动登录与会话续期

1. **Auto login** 填写登录 URL，选择 JSON 或 form 模式。
2. 字段映射填写服务端实际接受的字段，例如 `username=APP_USER`、`password=APP_PASSWORD`。可在界面输入临时用户名、密码；变量名用于可分享的配置。
3. Bearer 模式配置访问 Token 的 JSON Pointer，例如 `/access_token`；Cookie 模式按服务端返回的 Cookie 建立会话。
4. 按应用需要配置 CSRF 获取地址与字段；填写会话验证 URL 和身份成功断言，例如 `/role="admin"` 或约定成功响应头。自动登录要求正向身份验证。
5. 需要刷新时设置 Refresh URL、刷新 Token 路径和到期秒数字段。刷新失败会受控重新登录；每轮有续期预算。
6. 点击 **Test sign-in · Ctrl+L**。确认验证通过后 **Start audit**。

![自动登录编辑器](login-workbench.png)

安全方法在 401 后最多恢复重放一次；写请求不会自动重放。浏览器 JavaScript、验证码、MFA 和交互式 OAuth/PKCE 不自动完成，可先人工登录后粘贴会话。详细模型和 Cookie/CSRF 示例见[身份工作流](identity-workflows.md)。

## 多角色权限对比

1. **Roles & access** 添加管理员、资源所有者、其他用户、匿名身份等角色。
2. 认证角色配置独立身份验证与临时凭据，可以复制主身份的设置再调整账号；匿名角色明确选择匿名。
3. 添加 GET/HEAD 权限用例；URL 必须已在 Targets 中。为每个参与角色设置 allow 或 deny。
4. 为成功响应设置 Header 或 JSON 标量断言，例如 `/record/id=42`，证明获取到了目标资源。拒绝通常是 401/403，明确配置时可接受 404。
5. 审计完成后检查 **Permission matrix**。意外允许为 HIGH，意外拒绝为 MEDIUM；总体门槛由项目策略决定。

拒绝响应会重新验证已登录身份，避免会话过期被误认作正确拒绝。无法验证的身份或覆盖属于执行问题，不能被视为通过。

![每个身份的会话活动](sessions-workbench.png)

## 历史、基线和报告

审核一轮完整结果后，点击 **Accept selected run as baseline**。后续扫描比较新增、现存、严重度上升、已修复和未能复查的观察。筛选器和搜索可以按目标、规则、证据和修复建议定位。

认证身份、目标、请求或检查覆盖变化会影响可比性；缺失目标、失败扫描和跳过检查不会自动当作修复。记录保留当时的结果，接受例外后需重新扫描才会应用。**Rule exceptions** 支持到期日期与原因。

**Export report** 可以从当前选中的历史记录导出报告。HTML 可直接离线查看，SARIF 用于 CI 与 Code Scanning；命令行和 CI 的高级说明见 [ci.md](ci.md)。

## 数据、备份与快捷键

默认目录：`%USERPROFILE%\.shensec`；数据库：`workspace.sqlite3`。关闭全部 ShenSec 窗口后，复制整个目录可备份。恢复时同样先退出程序再还原。程序解压目录和历史目录分离，移动程序不会移动历史。

| 快捷键 | 操作 |
| --- | --- |
| Ctrl+S | 保存项目 |
| Ctrl+Enter | 开始审计 |
| Ctrl+L | 测试登录 |
| Ctrl+F | 搜索结果 |

## 故障处理

| 现象 | 检查方法 |
| --- | --- |
| 提示缺少 DLL / 无法打开 | 确认 Windows x64；ZIP 完整解压，`_internal` 在 exe 旁边 |
| 单文件启动较慢 | 启动时会解包；改用便携 ZIP |
| 启动失败 | 查看数据目录的 `startup-error.log`；日志只记录异常类型与代码位置 |
| 认证失败 | 检查字段名、来源、验证 URL、断言与临时凭据；先点 Test sign-in |
| 导入后字段缺失 | 只支持离线 OpenAPI 3.0/3.1 JSON；查看跳过原因与参数绑定 |
| 发现问题但门禁通过 | 检查严重度阈值、only-new 和到期例外，不要只看一个总状态 |
| 无法复查旧问题 | 查看 Target status 和 UNVERIFIED；先修复连接或认证再扫描 |

提交问题时说明程序版本、Windows 版本、复现步骤与经过人工脱敏的日志，不附上账号密码、Token 或私有业务响应。通过[GitHub Issues](https://github.com/shenming1115/ShenSec/issues)反馈。
