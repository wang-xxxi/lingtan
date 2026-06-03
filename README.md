# 灵探

接口发现与安全分析系统 — 自动发现、智能分析、安全检测，一站式 API 资产管理平台

---

> **免责声明**
>
> 本项目仅供 **授权安全测试**、**安全研究学习** 和 **企业内部资产自查** 使用。
>
> 使用本工具前，请确保你已获得目标系统所有者的 **书面授权**。未经授权对他人系统进行扫描、探测、测试，可能违反《中华人民共和国网络安全法》、《刑法》等相关法律法规，使用者需自行承担一切法律责任。
>
> 本项目开发者不对任何滥用行为承担责任。

---

## 这是什么

灵探 是一个 **Web API 接口自动发现与安全分析平台**。你只需要提供一个网站地址，它就能：

- 自动从网页的 HTML 和 JavaScript 代码中发现隐藏的 API 接口
- 对发现的接口进行安全漏洞检测（SQL 注入、XSS、SSRF、命令注入等）
- 智能识别 WAF 类型并自动选择最优绕过策略
- 爬取整站结构，精确识别技术栈和版本号
- 通过代理模式抓包分析请求中的敏感数据
- 将结果导出为 JSON / CSV / Markdown / Postman / OpenAPI / SARIF 等多种格式
- 通过命令行集成到 CI/CD 流水线，实现自动化安全卡点

## 适用场景

| 场景 | 具体说明 |
|------|---------|
| **企业安全自查** | 企业安全部门对自有业务系统进行 API 资产盘点，发现未登记的影子接口 |
| **渗透测试辅助** | 授权渗透测试中快速发现目标的 API 攻击面、识别 WAF、选择绕过策略 |
| **开发自测** | 后端开发者在上线前扫描自己的接口，检查是否存在安全头缺失、参数泄露等问题 |
| **CI/CD 安全卡点** | 将 CLI 工具集成到流水线，每次发布前自动扫描，高危接口自动阻断发布 |
| **接口文档生成** | 从线上运行的站点反向提取接口信息，生成 OpenAPI 规范文档 |
| **威胁情报收集** | 通过 Shodan / Censys / FOFA 查询目标的资产暴露情况 |
| **安全培训教学** | 用于网络安全课程的教学演示，展示常见的 Web 安全问题 |

## 快速开始

### 方式一：直接运行源码（推荐）

**第一步：确认 Python 版本**

打开命令行（Windows 按 `Win+R`，输入 `cmd` 回车），输入：

```bash
python --version
```

需要 Python 3.8 或更高版本。如果没有安装，请前往 [python.org](https://www.python.org/downloads/) 下载安装，安装时记得勾选 **"Add Python to PATH"**。

**第二步：下载项目**

```bash
git clone https://github.com/你的用户名/LingTan.git
cd LingTan
```

或者直接在 GitHub 页面点击 "Code → Download ZIP"，解压到任意目录。

**第三步：安装依赖**

```bash
pip install -r requirements.txt
```

项目依赖 5 个第三方库，安装通常只需要十几秒：

| 依赖 | 用途 |
|------|------|
| `flask` | Web 服务框架，提供后台 API 和前端页面服务 |
| `requests` | HTTP 请求库，用于爬取网页和发送扫描请求 |
| `beautifulsoup4` | HTML 解析库，从网页中提取链接和接口信息 |
| `lxml` | XML/HTML 解析加速器，提升爬取和解析速度 |
| `playwright` | 提供 Chromium 浏览器引擎，用于登录会话捕获 |

**第四步：安装浏览器引擎**

登录会话功能需要 Chromium 浏览器。安装 Playwright 后执行：

```bash
playwright install chromium
```

这会下载一个精简版 Chromium 到本地（约 150 MB），不依赖系统安装的 Chrome。

**第五步：启动**

```bash
python run.py
```

启动后会自动打开浏览器，显示操作界面。如果没有自动打开，手动访问 `http://localhost:8888`。

按 `Ctrl+C` 可停止服务。

> **注意：** `playwright install chromium` 只需执行一次。如果跳过此步骤，登录会话功能将无法使用，其余功能不受影响。

### 方式二：打包为独立 exe（免装 Python）

如果你想把工具发给没有 Python 环境的同事：

```bash
# 先安装 PyInstaller
pip install pyinstaller

# 运行打包脚本
python build.py
```

打包完成后，在 `dist/` 目录下会生成 `LingTan.exe`，双击即可运行。打包后的 exe 会将数据保存在同目录的 `api_hunter_data/` 文件夹下。

## 功能详细说明

### 一、发现模块

发现模块是灵探的核心，负责从各种来源中自动提取 API 接口信息。

#### 网站扫描

**做什么：** 输入一个网站 URL，工具会自动爬取该网站的所有页面，从页面中提取 API 接口。

**能发现什么：**
- 页面 HTML 中 `<a>`、`<form>`、`<script>` 标签里引用的 API 路径
- JavaScript 代码中通过 `fetch()`、`axios`、`jQuery.ajax()` 等方式调用的接口
- 页面中隐藏的 API 端点（如管理后台、调试接口等）
- 每个接口的 HTTP 方法（GET/POST/PUT/DELETE）、参数名、风险等级

**使用方式：** 在「网站扫描」标签页输入目标 URL，选择扫描深度（浅层/普通/深度），点击开始。扫描会在后台运行，你可以在「任务队列」中查看进度。

**扫描深度说明：**
- `浅层` — 只分析首页及其直接引用的资源，速度快（约 30 秒）
- `普通` — 爬取首页链接到的前 3 层页面，适合大多数场景（约 2-5 分钟）
- `深度` — 爬取前 5 层页面，覆盖面最广但耗时较长（约 5-15 分钟）

#### URL 分析

**做什么：** 对单个网页进行深度分析，不进行页面跳转，只分析这一个页面的内容。

**能发现什么：**
- 该页面发起的所有 HTTP 请求（XHR、Fetch、图片加载等）
- 页面中嵌入的 JavaScript 代码里包含的 API 调用
- 表单的提交地址和参数
- 页面引用的外部 JS/CSS 资源

**使用方式：** 在「URL 分析」标签页输入一个具体的页面地址，点击分析。适合分析单个页面（如 SPA 应用的某个路由页面）。

#### JS 分析

**做什么：** 专门分析 JavaScript 文件，从中提取有价值的信息。

**能发现什么：**
- 所有 API 路径（如 `/api/v1/users`、`/admin/delete`）
- 硬编码的密钥、Token、密码（提醒开发者注意安全）
- 内部服务器地址、IP 地址
- WebSocket 连接地址
- GraphQL 端点
- 环境配置信息（如 `API_BASE_URL`、`DEBUG` 模式等）

**使用方式：** 在「JS 分析」标签页，可以输入 JS 文件的 URL，也可以直接粘贴 JS 代码内容。工具会用多种正则模式进行匹配提取。

#### 文件分析

**做什么：** 导入各种格式的文件进行分析，提取其中的 API 信息。

**支持的文件格式：**

| 格式 | 说明 | 提取内容 |
|------|------|---------|
| **APK** | Android 应用包 | 解包后分析其中的网络请求代码，提取 API 地址、密钥 |
| **IPA** | iOS 应用包 | 分析应用内的网络请求配置 |
| **小程序包** | 微信/支付宝小程序 | 提取小程序调用的后端接口 |
| **HAR** | HTTP Archive 文件 | 从浏览器导出的网络请求记录，提取所有 API 调用 |
| **Burp Suite XML** | Burp Suite 导出的扫描结果 | 导入 Burp 抓取的请求数据进行分析 |

**使用方式：** 在「文件分析」标签页点击上传，选择对应的文件类型，工具会自动解析并展示提取结果。

#### 全站爬取

**做什么：** 从首页开始，广度优先（BFS）爬取整站的所有页面，构建完整的站点画像。

**能发现什么：**
- 完整的站点页面结构（哪些页面存在，页面之间的链接关系）
- 网站使用的技术栈（前端框架：React / Vue / Angular / jQuery；后端：PHP / Java / Python / Node.js）
- 所有静态资源（CSS、JS、图片、字体文件）
- 站点地图（页面层级关系）
- 隐藏的管理页面、测试页面

**进阶能力：**
- **页面智能分类** — 自动识别页面类型（首页、文章列表、文章详情、登录页、API 端点、静态资源等）
- **结构化数据提取** — 自动提取页面中的表格、列表、表单等结构化数据
- **翻页检测** — 自动识别 URL 分页（`?page=2`）、路径分页（`/page/3`）和 "Load More" 按钮
- **SPA 适配** — 识别 React / Vue / Next.js / Nuxt.js 等 SPA 框架，分析路由和 API 调用
- **可配置爬取规则** — 自定义包含/排除路径模式、页面类型过滤、最大深度
- **断点续传** — 爬取中断后可从断点恢复，不丢失已扫描的进度
- **重复页面过滤** — 自动识别并过滤内容相同的页面，减少扫描噪音

**使用方式：** 在「全站爬取」标签页输入首页 URL，设置最大爬取页数（默认 100 页），点击开始。爬取过程中可以实时查看已发现的页面列表。

#### 规范导入

**做什么：** 导入 OpenAPI / Swagger 规范文件，自动解析其中定义的所有接口。

**能做什么：**
- 解析 OpenAPI 3.0 和 Swagger 2.0 规范文件（JSON 和 YAML 格式）
- 自动提取所有端点路径、HTTP 方法、参数定义
- 根据规范自动生成测试用例
- 将解析结果添加到接口列表中

**使用方式：** 在「工具箱」中选择规范导入，上传 `.json` 或 `.yaml` 格式的规范文件，或输入 Swagger UI 的 URL。

### 二、安全检测模块

> **重要提示：** 安全检测功能仅限对 **你有权测试的系统** 使用。对未授权系统进行漏洞扫描属于违法行为。

#### 安全检测（漏洞扫描）

**做什么：** 对发现的 API 接口进行常见 Web 漏洞检测。

**检测项目：**
- **SQL 注入检测** — 通过在参数中注入 SQL 特殊字符（`'`、`"`、`OR 1=1` 等），观察响应是否异常
- **XSS 检测** — 在参数中注入 `<script>` 标签等 XSS payload，检查响应中是否原样返回
- **路径遍历检测** — 尝试通过 `../` 等方式访问系统文件，检测目录穿越漏洞
- **命令注入检测** — 在参数中注入系统命令分隔符（`|`、`;` 等），检测命令执行风险
- **SSRF 检测** — 在参数中注入内网地址，检测服务端请求伪造风险

**使用方式：** 在「安全检测」标签页，选择要检测的接口，点击开始检测。检测结果会标注风险等级（高危/中危/低危）。

#### OAST 带外检测

**做什么：** 通过外部回调通道检测盲注类漏洞，弥补传统检测无法发现的盲点。

**检测类型：**
- **盲注 SQL 注入** — 注入延时 payload 后通过回调确认
- **盲 XSS** — 注入的 XSS payload 触发后回调通知
- **SSRF** — 通过回调 URL 确认服务端是否发起了请求
- **盲命令注入** — 通过 DNS/HTTP 回调确认命令是否执行

**使用方式：** 在「安全检测」标签页的 OAST 区域输入目标 URL 和参数名，点击扫描。工具会生成唯一的回调地址，等待目标服务器的回调请求。

#### WAF 检测

**做什么：** 在扫描前识别目标是否使用了 WAF（Web 应用防火墙），并输出 WAF 类型和厂商。

**检测方法：**
1. 发送正常请求建立基线
2. 发送渐进式恶意 payload（SQL 注入、XSS、路径遍历）
3. 对比响应差异（状态码、响应头、响应体、响应时间）
4. 根据差异模式匹配已知 WAF 特征

**支持识别的 WAF（30+ 种）：** Cloudflare、AWS WAF、ModSecurity、Wordfence、阿里云 WAF、腾讯云 WAF、长亭雷池、Imperva、Akamai、F5 BIG-IP ASM、FortiWeb 等。

**使用方式：** 在「安全检测」标签页的 WAF 检测区域输入目标 URL，点击检测。

#### Payload 绕过引擎

**做什么：** 对安全测试的 payload 进行编码/变换，绕过 WAF/IDS/IPS 的拦截。

**支持的变换策略（15 种）：**

| 策略 | 原理 | 适用场景 |
|------|------|---------|
| URL 编码 | `%27` 替代 `'` | 通用 |
| 双重 URL 编码 | `%2527` 替代 `'` | 一层解码的 WAF |
| 大小写混淆 | `SeLeCt` 替代 `SELECT` | 关键词黑名单匹配 |
| 注释插入 | `SEL/**/ECT` 替代 `SELECT` | 简单关键字过滤 |
| 空白符替换 | 用 Tab/换行替代空格 | 空格敏感的规则 |
| Unicode 编码 | `'` 替代 `'` | 支持 Unicode 的应用 |
| HTML 实体 | `&#x27;` 替代 `'` | HTML 上下文 |
| 十六进制 | `0x27` 替代 `'` | SQL 注入 |
| 空字节插入 | `%00` 前缀 | 旧版 WAF |
| 参数污染 | 重复参数名 | 简单参数检查 |
| 路径混淆 | `/./`、`/../`、尾部斜杠 | 路径匹配规则 |
| 分块传输 | 分段传输 | Content-Length 检查 |
| 混合编码 | 组合以上多种 | 高级 WAF |
| Case + 注释 | 组合变换 | 多层防护 |
| UTF-8 超长编码 | 多字节编码利用 | 中文环境 |

**智能绕过：** 检测到 WAF 后，引擎会根据 WAF 类型自动选择最优绕过策略组合。

**使用方式：** 在「安全检测」标签页的绕过测试区域输入 payload，查看各种编码效果。检测到 WAF 时自动启用。

#### YAML 模板引擎

**做什么：** 使用内置的 YAML 检测模板对目标进行快速技术识别和安全检测。

**内置模板（8 个）：**

| 模板 | 检测目标 |
|------|---------|
| Spring Boot Actuator | Spring Boot Actuator 端点暴露 |
| Swagger UI | Swagger / OpenAPI 文档暴露 |
| Git 信息泄露 | `.git/HEAD`、`.git/config` 等 |
| 数据库管理面板 | phpMyAdmin、Adminer 等 |
| 管理后台检测 | 常见管理后台路径 |
| GraphQL 内省 | GraphQL introspection 开启检测 |
| DNS 重绑定 | DNS 重绑定漏洞检测 |
| HTTP 走私 | HTTP 请求走私漏洞检测 |

**自定义模板：** 支持编写自定义 YAML 模板，定义检测规则（匹配状态码、关键词、正则、响应时间）。

**使用方式：** 在「安全检测」标签页的模板检测区域选择模板，点击执行。也可通过 API 添加自定义模板。

#### 认证检测

**做什么：** 检测网站的认证和授权机制是否存在安全问题。

**检测项目：**
- **JWT 令牌分析** — 检查是否使用 `none` 算法、是否设置过期时间、签名算法是否安全
- **IDOR 越权检测** — 尝试修改请求中的 ID 参数，检测是否能访问其他用户的数据
- **认证绕过测试** — 尝试不携带认证信息直接访问受保护的接口
- **会话安全** — 检查 Cookie 是否设置了 `HttpOnly`、`Secure`、`SameSite` 等安全属性

#### 安全头审计

**做什么：** 检查网站的 HTTP 响应头是否设置了安全相关的头部字段。

**检查项目：**

| 安全头 | 作用 | 缺失风险 |
|--------|------|---------|
| `Strict-Transport-Security` | 强制使用 HTTPS | 可能被降级为 HTTP |
| `Content-Security-Policy` | 限制资源加载来源 | 容易遭受 XSS 攻击 |
| `X-Frame-Options` | 防止页面被嵌入 iframe | 可能被 Clickjacking 攻击 |
| `X-Content-Type-Options` | 防止 MIME 类型嗅探 | 可能导致脚本注入 |
| `X-XSS-Protection` | 浏览器 XSS 过滤 | 旧版浏览器无防护 |
| `Referrer-Policy` | 控制 Referer 泄露 | 可能泄露敏感 URL |
| `Permissions-Policy` | 限制浏览器功能 | 过度授权风险 |

**输出结果：** 给出 0-100 的安全评分，列出缺失的安全头和改进建议。

#### 子域名枚举

**做什么：** 通过多个公开数据源并发查询目标域名的子域名。

**查询方式：**
- **证书透明度日志** — 查询 crt.sh、CertSpotter、Google Transparency Log
- **威胁情报** — 查询 AlienVault OTX 社区情报
- **DNS 记录查询** — 通过 DNS 解析发现子域名

**能发现什么：** 测试环境（`test.example.com`）、管理后台（`admin.example.com`）、API 服务（`api.example.com`）等。

#### 参数挖掘

**做什么：** 从 JavaScript 代码和已有接口中挖掘可能存在的隐藏参数。

**能做什么：**
- 分析 JS 代码中出现的所有参数名（如 `page`、`limit`、`token`、`debug` 等）
- 从已有接口 URL 中提取参数模式
- 发现未在文档中公开的隐藏参数
- 提供常见参数名列表作为字典

#### 备份文件探测

**做什么：** 自动探测目标网站是否存在敏感的备份文件和配置泄露。

**检测路径（50+ 种）：**
- Git / SVN 版本控制泄露（`.git/HEAD`、`.svn/entries`）
- 环境变量文件（`.env`、`.env.local`、`.env.production`）
- 编辑器残留（`.swp`、`.bak`、`~` 后缀）
- 常见备份文件（`backup.zip`、`db.sql`、`dump.sql`）
- 配置文件（`config.json`、`web.config`、`wp-config.php.bak`）

#### 云存储泄露检测

**做什么：** 检测网站前端代码和响应中是否泄露了云存储的访问地址。

**支持的云平台：**
- AWS S3（检测 Bucket URL 和访问密钥）
- Google Cloud Storage / Firebase
- 阿里云 OSS
- 腾讯云 COS
- Azure Blob Storage

#### Favicon 指纹识别

**做什么：** 通过网站 Favicon 图标的 MurmurHash3 哈希值识别已知的 Web 应用和服务。

**支持识别：** Jenkins、Grafana、Zabbix、Jira、Confluence、GitLab、Harbor、WordPress、Spring Boot、Nacos、Druid、Elasticsearch 等 20+ 种常见应用。

#### 403/401 绕过测试

**做什么：** 当目标返回 403 Forbidden 或 401 Unauthorized 时，自动尝试各种绕过技巧。

**绕过策略（20+ 种）：**
- **Header 欺骗** — `X-Forwarded-For`、`X-Original-URL`、`X-Rewrite-URL` 等
- **HTTP 方法覆盖** — `HEAD`、`OPTIONS`、`PATCH`、`PUT` 替代 `GET`
- **路径变换** — 尾部斜杠、双斜杠、大小写混合、反斜杠、目录回溯、URL 编码

#### Wayback Machine 历史接口

**做什么：** 查询 Wayback Machine 存档，发现目标网站历史上的 API 接口和敏感路径。

**能发现什么：**
- 已下线但仍有风险的 API 接口
- 历史上暴露过的敏感路径（管理后台、调试端点）
- 接口路径的演变历史

#### 404 页面学习

**做什么：** 自动学习目标网站的自定义 404 页面特征，在扫描中准确区分"真实页面"和"伪装的 404"。

**检测方法：**
- 发送多个不存在的路径，采样 404 响应
- 分析响应状态码、内容长度、内容哈希
- 识别返回 200 但实际是 404 的"软 404"页面
- 计算可靠性评分

### 三、指纹识别模块

#### 技术栈指纹

**做什么：** 精确识别网站使用的框架、CMS、库及其版本号。

**四维指纹识别：**
- HTTP 响应头（`Server`、`X-Powered-By`、`Set-Cookie`）
- HTML 内容（meta generator、class 命名、特征标签）
- JavaScript 全局变量（`window.__NEXT_DATA__`、`window.__NUXT__` 等）
- 文件路径特征（`/wp-content/`、`/static/js/` 等）

**内置规则（100+ 条）：** 覆盖前端框架、CSS 框架、后端语言、Web 服务器、CMS、数据库、CDN/云、JS 库、监控/分析工具等。

**使用方式：** 在「全站爬取」结果中自动展示识别到的技术栈，也可通过 API 对单个 URL 进行快速检测。

#### JARM TLS 指纹

**做什么：** 通过 TLS 层的 Client Hello 特征识别服务器软件类型，即使 HTTP 层被伪装也能检测。

**工作原理：** 发送 3 种不同配置的 TLS Client Hello（TLS 1.0/1.2/1.3），记录服务端的响应特征，组合计算 JARM 哈希值，与已知服务的哈希库比对。

**支持识别：** Google、Cloudflare、Akamai、Amazon ALB、Nginx、Apache、IIS 等。

**使用方式：** 在「安全检测」标签页的 JARM 区域输入目标主机和端口，点击指纹计算。

### 四、情报收集模块

#### 外部威胁情报

**做什么：** 通过外部情报源查询目标域名/IP 的资产暴露情况。

**支持的数据源：**

| 来源 | 查询内容 | 是否需要 API Key |
|------|---------|----------------|
| **Shodan** | IP 的开放端口、服务指纹、地理位置 | 可选（免费 DNS 查询 + API 查询） |
| **Censys** | SSL/TLS 证书信息、主机详情 | 可选（证书搜索 + API 查询） |
| **FOFA** | 资产测绘、端口服务、域名关联 | 需要 API Key |

**使用方式：** 在「安全检测」标签页的威胁情报区域输入目标域名，可选填 API Key，点击查询。

### 五、数据模块

数据模块用于查看和管理所有已发现的数据。

#### 接口列表

**做什么：** 将所有扫描、爬取、分析发现的 API 接口集中展示在一个列表中。

**能做什么：**
- 按 HTTP 方法筛选（GET / POST / PUT / DELETE 等）
- 按风险等级筛选（高危 / 中危 / 低危 / 信息）
- 按来源筛选（网站扫描 / URL 分析 / JS 分析等）
- 按分类筛选（用户管理 / 文件操作 / 数据查询等）
- 收藏常用接口（点击星标按钮）
- 查看接口详情（URL、方法、参数、来源页面）
- 直接对接口发起请求测试（点击「测试」按钮跳转到请求构造器）

#### 接口依赖图

**做什么：** 以力导向图（Force-Directed Graph）方式展示页面与 API 接口之间的调用关系。

**能看到什么：**
- 哪些页面调用了哪些 API（页面节点 → 接口节点的连线）
- 哪些接口被多个页面共用（被多条连线指向的节点）
- 接口之间的依赖关系

**交互操作：**
- 节点可拖拽调整位置
- 鼠标悬停查看节点详情（URL、类型、来源）
- 力导向布局自动优化节点分布，避免重叠

#### 站点地图

**做什么：** 将爬取到的页面以树形结构可视化展示。

**能看到什么：**
- 网站的页面层级（首页 → 分类页 → 详情页）
- 每个页面包含的 API 接口数量
- 每个页面检测到的技术栈
- 支持搜索过滤，快速定位目标页面

#### 资源清单

**做什么：** 列出网站使用的所有静态资源文件。

**能做什么：**
- 查看所有 CSS 文件、JS 文件、图片、字体
- 按资源类型筛选
- 批量下载资源文件
- 发现未使用的废弃资源

### 六、流量分析模块

#### 流量代理

**做什么：** 启动一个 HTTP 代理服务器，所有通过该代理的请求都会被记录和分析。

**能做什么：**
- 实时抓取和显示所有 HTTP/HTTPS 请求
- 自动分析请求和响应中是否包含敏感数据：
  - 身份证号码
  - 手机号码
  - 邮箱地址
  - API Key / Token
  - 内部 IP 地址
  - 密码字段
- 统计请求方法分布、状态码分布
- 查看请求和响应的完整内容（Header + Body）

**使用方式：** 在「流量代理」标签页点击「启动代理」，工具会告诉你代理地址（如 `127.0.0.1:8080`）。将你的浏览器或手机的 HTTP 代理设置为该地址，所有流量就会被记录。

#### 流量分析

**做什么：** 对捕获的流量进行深度分析，自动提取有价值的信息。

**分析内容：**
- 识别流量中的 API 端点
- 提取认证令牌（JWT、Bearer Token、API Key）
- 检测敏感数据泄露
- 统计主机和路径分布

#### GraphQL 分析

**做什么：** 自动检测目标网站是否存在 GraphQL 端点，并尝试获取其 Schema。

**能做什么：**
- 自动探测常见的 GraphQL 端点路径（`/graphql`、`/api/graphql`、`/query` 等）
- 尝试发送内省查询（Introspection），获取完整的 Schema 定义
- 列出所有可用的 Query 和 Mutation
- 生成对应的 cURL 测试命令

#### WebSocket 检测

**做什么：** 从网站的 HTML 和 JavaScript 中检测 WebSocket 连接地址。

**能做什么：**
- 扫描页面中的 `ws://` 和 `wss://` 地址
- 检测 JavaScript 中通过 `new WebSocket()` 创建的连接
- 识别 WebSocket 使用的库（Socket.IO、SockJS 等）

### 七、输出模块

输出模块负责将分析结果以各种格式导出。

#### 数据导出

**做什么：** 将发现的接口数据导出为标准格式文件。

**支持的格式：**

| 格式 | 用途 |
|------|------|
| **JSON** | 结构化数据，适合程序处理和二次开发 |
| **CSV** | 表格格式，适合用 Excel 打开查看和统计 |
| **Markdown** | 文档格式，适合嵌入到项目文档中 |
| **Postman Collection** | 直接导入 Postman 使用，方便后续手动测试 |
| **OpenAPI 3.0** | 标准 API 规范文档，适合交给开发团队补充完善 |
| **SARIF 2.1.0** | 静态分析标准格式，可集成 GitHub / VS Code / Azure DevOps |

**SARIF 导出特性：**
- 符合 OASIS SARIF 2.1.0 标准规范
- 自动将漏洞类型映射为 SARIF 规则
- 支持严重程度分级（error / warning / note）
- 包含完整的漏洞描述、位置和修复建议
- 可直接在 VS Code 的 SARIF 扩展中查看

**使用方式：** 在「导出」标签页勾选要导出的接口，选择目标格式，点击导出。文件会自动下载到浏览器。

#### 脚本生成

**做什么：** 根据发现的接口信息，自动生成可运行的测试脚本。

**支持的脚本类型：**
- **Python requests** — 生成使用 `requests` 库的 Python 测试脚本
- **cURL** — 生成 cURL 命令，可在终端直接执行
- **Playwright** — 生成浏览器自动化测试脚本

**使用方式：** 在接口列表中点击某个接口，然后点击「生成脚本」，选择脚本类型即可。

#### 报告生成

**做什么：** 将一次完整的扫描结果生成为一个独立的 HTML 报告文件。

**报告内容包括：**
- 扫描概览（目标 URL、扫描时间、发现的接口数量）
- 接口列表（按风险等级排序）
- 安全检测结果
- 技术栈分析
- 安全头审计评分

**使用方式：** 在「报告」标签页选择一次扫描记录，点击「生成报告」。生成的 HTML 文件可以直接用浏览器打开查看。

#### SEO 分析

**做什么：** 分析网页的 SEO（搜索引擎优化）指标。

**检查项目：**
- 页面 `<title>` 是否存在、长度是否合适
- `<meta name="description">` 是否存在、内容是否合适
- 标题层级是否正确（H1 → H2 → H3 是否逐级递进）
- Open Graph 标签（社交媒体分享时显示的标题、描述、图片）
- 图片是否有 `alt` 属性
- 页面是否有 `<meta name="viewport">`（移动端适配）

### 八、工具模块

#### 请求构造器

**做什么：** 类似 Postman 的 HTTP 请求调试工具，内置在工具中。

**能做什么：**
- 自由构造 HTTP 请求（GET / POST / PUT / DELETE / PATCH）
- 自定义请求头（Header）和请求体（Body）
- 实时预览对应的 cURL 命令
- 自动记录请求历史，支持快速重放
- 收藏常用请求
- 自动携带已保存的登录会话 Cookie

#### 端口扫描

**做什么：** 快速扫描目标主机开放的常见 Web 端口。

**扫描范围：** 80、443、8080、8443、3000、5000、8000、8888、9000 等常见 Web 服务端口。

#### 接口对比

**做什么：** 对两次扫描的接口列表进行 Diff 对比，发现差异。

**能发现什么：**
- 新增的接口（本次扫描新发现的）
- 删除的接口（上次有但本次没有的）
- 修改的接口（参数或方法发生了变化）

#### 变更监控

**做什么：** 定期对接口列表进行快照，自动检测接口变更。

**使用方式：** 通过 API 创建快照，后续查询变更情况。适合在版本迭代前后监控接口变更。

#### 登录会话

**做什么：** 通过内置的 Chromium 浏览器窗口捕获网站的登录 Cookie，让后续的扫描可以访问需要登录才能看到的页面。

**工作原理：** 使用 Playwright 提供的 Chromium 引擎（非系统 Chrome），通过 Chrome DevTools Protocol (CDP) 与浏览器通信，同时使用 `document.cookie` 和 `Network.getCookiesForUrls` 两种方式捕获 Cookie，确保 HttpOnly 和非 HttpOnly 的 Cookie 都能获取到。

**工作流程：**
1. 在「登录会话」标签页输入需要登录的网站地址
2. 点击「打开登录窗口」，工具会启动一个独立的 Chromium 窗口
3. 在弹出的浏览器窗口中手动完成登录
4. 登录成功后，回到工具界面点击「捕获会话」
5. 工具会通过 CDP 自动读取浏览器中的 Cookie 并保存

> **前置条件：** 需要先执行 `playwright install chromium` 安装浏览器引擎。

#### 任务队列

**做什么：** 查看和管理所有正在后台运行的任务。

**能做什么：**
- 查看当前正在运行的任务（扫描、爬取、检测等）
- 查看任务的进度和状态
- 停止正在运行的任务
- 查看已完成任务的结果摘要

#### 插件管理

**做什么：** 允许用户编写自定义的扫描规则插件，扩展工具的检测能力。

**插件类型：**
- **技术指纹** — 自定义技术栈的识别规则
- **安全 Payload** — 自定义漏洞检测的测试载荷
- **分析规则** — 自定义的接口分析逻辑
- **敏感路径** — 自定义的敏感路径检测列表

**使用方式：** 在「插件」标签页，可以安装 JSON 格式的插件文件。工具自带一个示例插件，可以参考其格式编写自己的插件。

## 基本使用流程

```
启动 → 输入目标URL → 网站扫描 → 查看发现的接口 → 安全检测 → 导出结果
```

1. 打开浏览器进入 Dashboard（总览页面），可以查看整体统计数据
2. 在「网站扫描」页输入目标 URL，选择扫描深度，点击开始扫描
3. 扫描完成后，在「接口列表」查看发现的所有 API 端点
4. 切换到「漏洞扫描」对感兴趣的接口进行安全检测
5. 在「WAF 检测」中识别目标是否有 WAF 保护，必要时启用绕过引擎
6. 在「安全头审计」检查响应头配置
7. 在「威胁情报」中查询目标的外部资产暴露
8. 在「导出」页将结果导出为需要的格式
9. 如需深入测试，使用「请求构造」对接口进行手动调试

### 快捷流程

灵探内置了两个一键操作，自动串联多个检测步骤：

- **一键侦察** — 在「子域名枚举」页面点击，同时启动子域名枚举、威胁情报查询、历史接口扫描，结果自动合并
- **智能扫描** — 在「漏洞扫描」页面点击，自动执行 WAF 检测 → 根据 WAF 类型启用绕过策略 → 启动安全漏洞扫描

## 命令行工具 (CLI)

灵探 提供独立的命令行扫描工具，可直接集成到 CI/CD 流水线。

> **CLI 使用注意：** 命令行工具会直接对指定 URL 发起网络请求。请确保目标 URL 是你有权测试的系统。

### 基本用法

```bash
# 基础扫描（只发现接口，不做安全检测）
python cli_scan.py --url https://example.com

# 带安全检测
python cli_scan.py --url https://example.com --security

# 深度扫描 + 所有检测
python cli_scan.py --url https://example.com --all --depth deep

# 导入 OpenAPI 规范扫描
python cli_scan.py --spec swagger.json --url https://api.example.com

# 结果输出到文件
python cli_scan.py --url https://example.com --output results.json --json-only
```

### CI/CD 集成

CLI 工具设计了退出码机制，可以在 CI/CD 流水线中用作安全卡点：

```bash
# 发现 high 及以上风险时退出码为 1，可用于流水线卡点
python cli_scan.py --url https://api.example.com --security --fail-on high
```

退出码说明：
- `0` = 扫描通过，无高危发现
- `1` = 发现高危接口（CI 卡点触发）
- `2` = 扫描失败或参数错误

**Jenkins 示例：**

```groovy
pipeline {
    agent any
    environment {
        TARGET_URL = 'https://api.your-company.com'
    }
    stages {
        stage('API Security Scan') {
            steps {
                bat 'python cli_scan.py --url %TARGET_URL% --all --fail-on high --output scan_results.json'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'scan_results.json'
        }
        failure {
            echo '安全扫描发现高危接口，发布已阻断！'
        }
    }
}
```

**GitLab CI 示例：**

```yaml
api-security-scan:
  stage: test
  script:
    - pip install -r requirements.txt
    - python cli_scan.py --url $TARGET_URL --security --fail-on high --output results.json
  artifacts:
    paths:
      - results.json
    when: always
  allow_failure: false  # 发现高危时阻断流水线
```

**GitHub Actions 示例：**

```yaml
name: API Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: python cli_scan.py --url ${{ secrets.TARGET_URL }} --security --fail-on high --output results.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: scan-results
          path: results.json
```

### CLI 参数一览

| 参数 | 说明 |
|------|------|
| `--url, -u` | 扫描目标 URL |
| `--spec, -s` | OpenAPI/Swagger 规范文件路径或 URL |
| `--depth, -d` | 扫描深度：`shallow` / `normal`（默认）/ `deep` |
| `--max-pages, -p` | 最大扫描页面数（默认 100） |
| `--security` | 启用安全漏洞扫描 |
| `--auth-check` | 启用认证/授权检测 |
| `--header-audit` | 启用安全头审计 |
| `--all` | 启用所有检测 |
| `--fail-on` | CI 卡点阈值：`none` / `info` / `low` / `medium` / `high` / `critical` |
| `--output, -o` | 输出 JSON 结果到文件 |
| `--json-only` | 仅输出 JSON，不输出人类可读信息 |
| `--quiet, -q` | 静默模式 |

## 运行测试

```bash
python test_suite.py
```

测试覆盖所有核心模块，共 380 项测试，验证数据库 CRUD、各分析器功能、API 路由等。

## 项目结构

```
├── run.py                        # 主入口，启动 Web 服务
├── cli_scan.py                   # CLI 扫描工具（可独立运行）
├── build.py                      # PyInstaller 打包脚本
├── test_suite.py                 # 全量测试
├── requirements.txt              # Python 依赖（5 个）
│
├── core/                         # 后端核心模块（51 个 .py 文件）
│   ├── app.py                    # Flask 应用 + 所有 API 路由
│   ├── database.py               # SQLite 数据库（13 张表）
│   │
│   ├── # ── 发现模块 ──
│   ├── crawler.py                # Web 爬虫 + 单 URL 分析
│   ├── js_analyzer.py            # JavaScript 文件分析
│   ├── site_crawler.py           # 全站爬虫（BFS 广度优先）
│   ├── analyzer.py               # API 端点分析器
│   ├── spec_importer.py          # OpenAPI / Swagger 规范导入
│   ├── har_analyzer.py           # HAR / Burp XML 分析
│   ├── apk_analyzer.py           # APK / IPA / 小程序分析
│   │
│   ├── # ── 安全检测 ──
│   ├── fuzzer.py                 # 安全漏洞扫描（SQL 注入/XSS/SSRF 等）
│   ├── waf_detector.py           # WAF 检测（30+ 种 WAF 识别）
│   ├── payload_evasion.py        # Payload 绕过引擎（15 种编码策略）
│   ├── oast_detector.py          # OAST 带外检测（盲注/SSRF）
│   ├── template_engine.py        # YAML 模板引擎（8 个内置模板）
│   ├── auth_detector.py          # 认证检测（JWT/IDOR/绕过）
│   ├── header_auditor.py         # 安全响应头审计
│   ├── param_miner.py            # 参数挖掘 + Fuzz
│   ├── backup_scanner.py         # 备份文件探测（50+ 路径）
│   ├── cloud_storage_detector.py # 云存储泄露检测
│   ├── forbidden_bypass.py       # 403/401 绕过测试（20+ 策略）
│   ├── wayback_scanner.py        # Wayback Machine 历史接口
│   ├── error_page_detector.py    # 404 页面学习
│   │
│   ├── # ── 指纹识别 ──
│   ├── tech_fingerprint.py       # 技术栈指纹（100+ 规则，精确版本识别）
│   ├── favicon_fingerprint.py    # Favicon 哈希指纹（20+ 已知应用）
│   ├── jarm_fingerprint.py       # JARM TLS 指纹
│   │
│   ├── # ── 情报收集 ──
│   ├── subdomain_enum.py         # 子域名枚举（crt.sh/CertSpotter/AlienVault OTX）
│   ├── threat_intel.py           # 威胁情报（Shodan/Censys/FOFA）
│   │
│   ├── # ── 流量分析 ──
│   ├── traffic_analyzer.py       # 流量分析（敏感数据识别）
│   ├── proxy_server.py           # HTTP 代理服务
│   ├── graphql_analyzer.py       # GraphQL 分析
│   ├── websocket_detector.py     # WebSocket 检测
│   │
│   ├── # ── 智能分析 ──
│   ├── site_analyzer.py          # SEO / 性能分析
│   ├── page_classifier.py        # 页面类型智能分类
│   ├── data_extractor.py         # 结构化数据提取
│   ├── pagination_detector.py    # 翻页/加载更多检测
│   ├── spa_adapter.py            # SPA 站点适配
│   ├── deduplicator.py           # 重复页面过滤
│   ├── crawl_rules.py            # 用户可配置爬取规则
│   │
│   ├── # ── 输出模块 ──
│   ├── exporter.py               # 多格式数据导出（JSON/CSV/Markdown）
│   ├── sarif_exporter.py         # SARIF 2.1.0 导出（CI/CD 集成）
│   ├── spec_generator.py         # OpenAPI 规范 / cURL 生成
│   ├── script_generator.py       # 测试脚本自动生成（Python/Playwright/cURL）
│   ├── report_generator.py       # HTML 报告生成
│   │
│   ├── # ── 工具模块 ──
│   ├── scanner_utils.py          # 端口扫描 / Diff / 批量扫描 / 变更监控
│   ├── scan_checkpoint.py        # 扫描断点续传
│   ├── task_manager.py           # 后台任务管理
│   ├── plugin_manager.py         # 插件系统
│   ├── session_manager.py        # 登录会话捕获（Playwright Chromium + CDP）
│   ├── anti_detection.py         # 反反爬（UA 轮换、请求随机化）
│   ├── path_resolver.py          # 路径解析（支持打包模式）
│   └── __init__.py
│
├── web/                          # 前端（单页应用）
│   ├── templates/
│   │   └── index.html            # 页面结构（37 个功能标签页）
│   ├── static/
│   │   ├── css/app.css           # 暗色主题样式
│   │   └── js/app.js             # 前端交互逻辑（含力导向图渲染）
│   └── __init__.py
│
├── plugins/                      # 插件目录
│   └── example_fingerprint.json  # 示例插件
│
└── .gitignore
```

## 技术架构

```
┌──────────────────────────────────────────────────┐
│                    浏览器                         │
│    HTML + CSS + 原生 JavaScript，无前端框架       │
│    暗色主题，7 个功能分组，37 个功能标签页          │
└──────────────────────┬───────────────────────────┘
                       │ HTTP / JSON API
┌──────────────────────┴───────────────────────────┐
│               Flask Web 服务                     │
│    130+ REST API 路由                            │
│    后台线程执行长时间任务，进度实时轮询             │
├──────────────────────────────────────────────────┤
│                  核心模块层（51 个模块）            │
│                                                  │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐            │
│  │ 发现模块  │ │ 安全检测  │ │ 指纹识别  │            │
│  │ 7 个     │ │ 13 个    │ │ 3 个     │            │
│  └─────────┘ └─────────┘ └─────────┘            │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐            │
│  │ 情报收集  │ │ 流量分析  │ │ 智能分析  │            │
│  │ 2 个     │ │ 4 个     │ │ 7 个     │            │
│  └─────────┘ └─────────┘ └─────────┘            │
│  ┌─────────┐ ┌─────────┐                        │
│  │ 输出模块  │ │ 工具模块  │                        │
│  │ 5 个     │ │ 7 个     │                        │
│  └─────────┘ └─────────┘                        │
├──────────────────────────────────────────────────┤
│                SQLite 数据库                      │
│    13 张表 · 线程安全单例 · 参数化查询防注入      │
└──────────────────────────────────────────────────┘

外部依赖：
  Playwright Chromium ── 用于登录会话捕获（CDP 通信）
```

**设计原则：**
- **零前端依赖** — 不引入 jQuery / Vue / React / D3.js，所有交互用原生 JavaScript 实现
- **最小后端依赖** — 仅 5 个第三方库（flask / requests / beautifulsoup4 / lxml / playwright），其余全用 Python 标准库
- **支持打包为单文件 exe** — 使用 PyInstaller，双击即可运行，无需安装 Python
- **后台异步执行** — 长时间任务在后台线程运行，前端轮询进度，不会阻塞界面

## 数据库

使用 SQLite，数据库文件自动创建在 `data/api_hunter.db`，包含 13 张表：

| 表名 | 说明 |
|------|------|
| `targets` | 扫描目标记录 |
| `api_endpoints` | 发现的 API 端点（URL、方法、参数、风险等级） |
| `analysis_results` | 分析结果 |
| `scan_sessions` | 扫描会话记录 |
| `crawled_pages` | 全站爬取的页面数据 |
| `site_technologies` | 检测到的技术栈 |
| `captured_traffic` | 代理抓取的流量记录 |
| `tasks` | 后台任务队列 |
| `favorites` | 用户收藏的接口 |
| `request_history` | 请求构造器的历史记录 |
| `sessions` | 登录会话（Cookie） |
| `crawl_rules` | 用户自定义的爬取规则 |
| `scan_checkpoints` | 扫描断点续传状态 |

## 已知限制

- SQLite 不支持高并发写入，多个用户同时操作可能出现短暂锁等待
- 目前没有用户认证机制，部署在公网有安全风险，**建议仅在本地或受信任的内网环境使用**
- 子域名枚举依赖外部公共服务（crt.sh / CertSpotter / AlienVault OTX），响应速度受其影响
- OAST 带外检测依赖 oast.pro 回调服务，需要目标服务器能访问外网
- 登录会话功能依赖 Playwright Chromium，首次使用需执行 `playwright install chromium`（约 150 MB）
- 打包后的 exe 文件体积较大（约 50-100 MB），这是因为包含了 Python 解释器和所有依赖

## 法律合规说明

使用本工具时，请务必遵守以下原则：

1. **获取授权** — 在对任何系统进行扫描之前，必须获得系统所有者的书面授权。

2. **限定范围** — 只在授权范围内进行测试，不要超出授权的 URL 路径、IP 范围和测试时间。

3. **保护数据** — 扫描过程中获取的任何数据（接口信息、Cookie、敏感数据等）都应当保密处理，不得泄露给未授权的第三方。

4. **禁止恶意使用** — 严禁将本工具用于攻击他人系统、窃取数据、破坏服务等非法目的。

5. **遵守当地法律** — 不同国家和地区对安全测试的法律规定不同，请确保你的使用行为符合当地法律法规。

**相关法律法规参考（中国大陆）：**
- 《中华人民共和国网络安全法》第二十七条：任何个人和组织不得从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动
- 《中华人民共和国刑法》第二百八十五条、第二百八十六条：非法侵入计算机信息系统罪、破坏计算机信息系统罪
- 《中华人民共和国数据安全法》第三十二条：任何组织、个人收集数据，应当采取合法、正当的方式

## License

本项目仅供授权安全测试和学习研究使用。使用者应当遵守相关法律法规，对自身行为承担全部法律责任。
