# 灵探 API 接口文档

> **版本:** 2.0  
> **基础地址:** `http://localhost:8888`  
> **更新时间:** 2026-05-29

---

## 目录

- [1. 扫描相关](#1-扫描相关)
- [2. 数据查询](#2-数据查询)
- [3. 数据导出](#3-数据导出)
- [4. 安全扫描](#4-安全扫描)
- [5. 全站爬取](#5-全站爬取)
- [6. 流量代理](#6-流量代理)
- [7. GraphQL 分析](#7-graphql-分析)
- [8. WebSocket 检测](#8-websocket-检测)
- [9. 报告生成](#9-报告生成)
- [10. 任务管理](#10-任务管理)
- [11. 插件管理](#11-插件管理)
- [12. 参数挖掘](#12-参数挖掘)
- [13. 认证检测](#13-认证检测)
- [14. 安全头审计](#14-安全头审计)
- [15. 子域名枚举](#15-子域名枚举)
- [16. 规范导入](#16-规范导入)
- [17. 变更监控](#17-变更监控)
- [18. 流量分析](#18-流量分析)
- [19. CI/CD 集成](#19-cicd-集成)
- [20. 收藏与历史](#20-收藏与历史)
- [21. 会话管理](#21-会话管理)
- [22. 爬取规则](#22-爬取规则)
- [23. 智能分析](#23-智能分析)
- [24. WAF 检测](#24-waf-检测)
- [25. 技术栈指纹](#25-技术栈指纹)
- [26. Payload 绕过](#26-payload-绕过)
- [27. 扫描断点续传](#27-扫描断点续传)
- [28. 备份文件探测](#28-备份文件探测)
- [29. 云存储泄露检测](#29-云存储泄露检测)
- [30. Favicon 指纹](#30-favicon-指纹)
- [31. 403/401 绕过](#31-403401-绕过)
- [32. Wayback Machine](#32-wayback-machine)
- [33. 404 页面学习](#33-404-页面学习)
- [34. OAST 带外检测](#34-oast-带外检测)
- [35. YAML 模板引擎](#35-yaml-模板引擎)
- [36. 威胁情报](#36-威胁情报)
- [37. JARM 指纹](#37-jarm-指纹)
- [38. 依赖图](#38-依赖图)
- [39. 工具类](#39-工具类)

---

## 1. 扫描相关

### 1.1 网站扫描

**POST** `/api/scan/web`

扫描目标网站，自动发现 API 接口。

**请求参数:**
```json
{
  "url": "https://example.com",
  "deep_scan": true
}
```

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| url | string | ✅ | 目标 URL |
| deep_scan | boolean | ❌ | 深度扫描，默认 true |

**响应示例:**
```json
{
  "message": "扫描已启动",
  "target": "https://example.com"
}
```

---

### 1.2 单 URL 分析

**POST** `/api/scan/analyze-url`

分析单个 URL 的接口信息。

**请求参数:**
```json
{
  "url": "https://api.example.com/users",
  "method": "GET",
  "headers": {},
  "body": ""
}
```

**响应示例:**
```json
{
  "url": "https://api.example.com/users",
  "method": "GET",
  "status_code": 200,
  "content_type": "application/json",
  "parameters": [],
  "category": "user",
  "risk_level": "info"
}
```

---

### 1.3 JS 文件分析

**POST** `/api/scan/js`

分析 JavaScript 文件中的 API 接口。

**请求参数:**
```json
{
  "url": "https://example.com/app.js"
}
```

---

### 1.4 批量 JS 分析

**POST** `/api/scan/batch-js`

批量分析多个 JS 文件。

**请求参数:**
```json
{
  "urls": ["https://example.com/app1.js", "https://example.com/app2.js"]
}
```

---

### 1.5 文件上传分析

**POST** `/api/upload`

上传 HAR/APK/IPA/小程序包/Burp XML 文件进行分析。

**请求参数:** `multipart/form-data`

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| file | file | ✅ | 文件 |
| type | string | ❌ | 文件类型: auto/apk/ipa/har/burp/miniprogram |

---

### 1.6 批量文件上传

**POST** `/api/upload/batch`

批量上传多个文件进行分析。

**请求参数:** `multipart/form-data`，字段名 `files`

---

### 1.7 批量扫描

**POST** `/api/scan/batch`

批量扫描多个 URL。

**请求参数:**
```json
{
  "urls": ["https://example1.com", "https://example2.com"]
}
```

---

### 1.8 连接测试

**POST** `/api/test-connection`

测试与目标 URL 的连接。

**请求参数:**
```json
{
  "url": "https://example.com"
}
```

**响应示例:**
```json
{
  "status": 200,
  "content_type": "text/html",
  "size": 1234,
  "time": 0.5,
  "reachable": true,
  "headers": {}
}
```

---

### 1.9 扫描状态

**GET** `/api/scan/status`

获取当前扫描状态。

**响应示例:**
```json
{
  "active": true,
  "type": "web",
  "target": "https://example.com",
  "progress": 45,
  "message": "正在爬取页面...",
  "results": [],
  "start_time": 1234567890,
  "error": null
}
```

---

### 1.10 扫描进度

**GET** `/api/scan/progress`

获取扫描进度信息。

**响应示例:**
```json
{
  "active": true,
  "progress": 45,
  "message": "正在爬取页面...",
  "type": "web",
  "target": "https://example.com",
  "error": null,
  "elapsed": 12.5
}
```

---

### 1.11 停止扫描

**POST** `/api/scan/stop`

停止当前扫描任务。

---

## 2. 数据查询

### 2.1 获取接口列表

**GET** `/api/endpoints`

**查询参数:**

| 参数 | 类型 | 说明 |
|------|------|------|
| target_id | int | 目标 ID |
| category | string | 接口分类 |
| search | string | 搜索关键词 |

**响应示例:**
```json
{
  "endpoints": [
    {
      "id": 1,
      "url": "https://api.example.com/users",
      "method": "GET",
      "status_code": 200,
      "category": "user",
      "risk_level": "info"
    }
  ],
  "total": 1
}
```

---

### 2.2 获取接口详情

**GET** `/api/endpoint/<int:endpoint_id>`

获取单个接口的详细信息。

---

### 2.3 获取统计信息

**GET** `/api/stats`

获取接口统计信息。

**响应示例:**
```json
{
  "total_endpoints": 100,
  "total_targets": 5,
  "by_method": {"GET": 60, "POST": 40},
  "by_category": {"user": 30, "product": 20},
  "by_risk": {"info": 80, "low": 15, "medium": 5},
  "by_source": {"web-scan": 70, "har": 30}
}
```

---

### 2.4 获取目标列表

**GET** `/api/targets`

获取所有扫描目标。

---

### 2.5 获取接口 cURL

**GET** `/api/curl/<int:endpoint_id>`

生成指定接口的 cURL 命令。

**响应示例:**
```json
{
  "curl": "curl -X GET 'https://api.example.com/users' -H 'User-Agent: ...'"
}
```

---

## 3. 数据导出

### 3.1 导出数据

**GET** `/api/export/<format>`

**支持格式:** json, csv, markdown, postman

---

### 3.2 导出 OpenAPI 规范

**GET/POST** `/api/export/openapi`

生成 OpenAPI 3.0 规范。

**POST 请求参数:**
```json
{
  "title": "My API",
  "version": "1.0.0"
}
```

---

### 3.3 下载 OpenAPI 文件

**GET** `/api/export/openapi/file`

下载 OpenAPI 规范文件。

---

### 3.4 导出 SARIF

**GET/POST** `/api/export/sarif`

生成 SARIF 格式安全报告。

---

### 3.5 下载 SARIF 文件

**GET** `/api/export/sarif/file`

下载 SARIF 文件。

---

## 4. 安全扫描

### 4.1 启动安全扫描

**POST** `/api/security/scan`

**请求参数:**
```json
{
  "url": "https://example.com"
}
```

---

### 4.2 安全扫描进度

**GET** `/api/security/progress`

---

### 4.3 停止安全扫描

**POST** `/api/security/stop`

---

## 5. 全站爬取

### 5.1 启动全站爬取

**POST** `/api/site/crawl`

**请求参数:**
```json
{
  "url": "https://example.com",
  "max_pages": 100
}
```

---

### 5.2 爬取进度

**GET** `/api/site/progress`

---

### 5.3 停止爬取

**POST** `/api/site/stop`

---

### 5.4 获取爬取页面

**GET** `/api/site/pages`

**查询参数:**

| 参数 | 类型 | 说明 |
|------|------|------|
| target_id | int | 目标 ID |
| limit | int | 返回数量限制 |

---

### 5.5 获取页面详情

**GET** `/api/site/page/<int:page_id>`

---

### 5.6 获取技术栈

**GET** `/api/site/technologies`

**查询参数:**

| 参数 | 类型 | 说明 |
|------|------|------|
| target_id | int | 目标 ID |

---

### 5.7 获取站点地图

**GET** `/api/site/sitemap`

**查询参数:**

| 参数 | 类型 | 说明 |
|------|------|------|
| target_id | int | 目标 ID |

---

### 5.8 获取静态资源

**GET** `/api/site/assets`

**查询参数:**

| 参数 | 类型 | 说明 |
|------|------|------|
| target_id | int | 目标 ID |
| type | string | 资源类型 |

---

### 5.9 下载静态资源

**POST** `/api/site/assets/download`

**请求参数:**
```json
{
  "urls": ["https://example.com/style.css", "https://example.com/app.js"]
}
```

---

### 5.10 SEO 分析

**POST** `/api/site/seo`

**请求参数:**
```json
{
  "target_id": 1
}
```

---

## 6. 流量代理

### 6.1 启动代理

**POST** `/api/proxy/start`

**请求参数:**
```json
{
  "port": 8088
}
```

---

### 6.2 停止代理

**POST** `/api/proxy/stop`

---

### 6.3 代理状态

**GET** `/api/proxy/status`

---

### 6.4 获取流量记录

**GET** `/api/proxy/traffic`

**查询参数:**

| 参数 | 类型 | 说明 |
|------|------|------|
| host | string | 主机过滤 |
| method | string | 方法过滤 |
| keyword | string | 关键词过滤 |
| limit | int | 返回数量 |

---

### 6.5 获取流量详情

**GET** `/api/proxy/traffic/<int:tid>`

---

### 6.6 清除流量记录

**POST** `/api/proxy/clear`

---

## 7. GraphQL 分析

### 7.1 GraphQL 内省

**POST** `/api/graphql/introspect`

**请求参数:**
```json
{
  "url": "https://api.example.com/graphql",
  "headers": {}
}
```

---

### 7.2 发现 GraphQL 端点

**POST** `/api/graphql/find`

**请求参数:**
```json
{
  "html": "<a href='/graphql'>API</a>",
  "js_code": "fetch('/api/graphql')"
}
```

---

## 8. WebSocket 检测

### 8.1 检测 WebSocket

**GET** `/api/websocket/detect`

从已爬取页面中检测 WebSocket 端点。

---

### 8.2 测试 WebSocket

**POST** `/api/websocket/test`

**请求参数:**
```json
{
  "url": "wss://example.com/ws"
}
```

---

## 9. 报告生成

### 9.1 生成报告

**POST** `/api/report/generate`

**请求参数:**
```json
{
  "target_id": 1
}
```

**响应示例:**
```json
{
  "success": true,
  "filename": "report_20260529.html"
}
```

---

### 9.2 下载报告

**GET** `/api/report/download/<filename>`

---

## 10. 任务管理

### 10.1 获取任务列表

**GET** `/api/tasks`

**查询参数:**

| 参数 | 类型 | 说明 |
|------|------|------|
| limit | int | 返回数量 |

---

### 10.2 获取任务详情

**GET** `/api/tasks/<task_id>`

---

### 10.3 停止任务

**POST** `/api/tasks/<task_id>/stop`

---

## 11. 插件管理

### 11.1 获取插件列表

**GET** `/api/plugins`

---

### 11.2 安装插件

**POST** `/api/plugins/install`

**请求参数:**
```json
{
  "json": "{\"name\":\"MyPlugin\",\"type\":\"security_payload\",\"rules\":[...]}"
}
```

---

### 11.3 启用/禁用插件

**POST** `/api/plugins/<name>/toggle`

---

### 11.4 删除插件

**DELETE** `/api/plugins/<name>`

---

### 11.5 获取插件示例

**GET** `/api/plugins/example`

---

## 12. 参数挖掘

### 12.1 启动参数挖掘

**POST** `/api/param/mine`

**请求参数:**
```json
{
  "url": "https://example.com"
}
```

---

### 12.2 参数挖掘进度

**GET** `/api/param/progress`

---

### 12.3 停止参数挖掘

**POST** `/api/param/stop`

---

## 13. 认证检测

### 13.1 启动认证检测

**POST** `/api/auth/check`

**请求参数:**
```json
{
  "url": "https://example.com",
  "auth_headers": {}
}
```

---

### 13.2 认证检测进度

**GET** `/api/auth/progress`

---

### 13.3 停止认证检测

**POST** `/api/auth/stop`

---

### 13.4 JWT 分析

**POST** `/api/auth/jwt/analyze`

**请求参数:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

**响应示例:**
```json
{
  "valid": true,
  "algorithm": "HS256",
  "header": {"alg": "HS256"},
  "payload": {"user_id": 123}
}
```

---

## 14. 安全头审计

### 14.1 启动安全头审计

**POST** `/api/header/audit`

**请求参数:**
```json
{
  "url": "https://example.com"
}
```

---

### 14.2 审计进度

**GET** `/api/header/progress`

---

### 14.3 停止审计

**POST** `/api/header/stop`

---

## 15. 子域名枚举

### 15.1 启动子域名枚举

**POST** `/api/subdomain/enum`

**请求参数:**
```json
{
  "domain": "example.com",
  "bruteforce": false
}
```

---

### 15.2 枚举进度

**GET** `/api/subdomain/progress`

---

### 15.3 停止枚举

**POST** `/api/subdomain/stop`

---

## 16. 规范导入

### 16.1 导入 OpenAPI/Swagger 规范

**POST** `/api/spec/import`

**请求参数 (URL):**
```json
{
  "url": "https://petstore.swagger.io/v2/swagger.json"
}
```

**请求参数 (文本):**
```json
{
  "content": "{\"openapi\":\"3.0.0\",...}",
  "filename": "api.json"
}
```

---

### 16.2 上传规范文件

**POST** `/api/spec/import/file`

**请求参数:** `multipart/form-data`，字段名 `file`

---

## 17. 变更监控

### 17.1 创建快照

**POST** `/api/monitor/snapshot`

**请求参数:**
```json
{
  "target_id": "default"
}
```

---

### 17.2 检测变更

**GET** `/api/monitor/changes`

**查询参数:**

| 参数 | 类型 | 说明 |
|------|------|------|
| target_id | string | 目标 ID |

---

### 17.3 获取快照列表

**GET** `/api/monitor/snapshots`

---

### 17.4 对比差异

**POST** `/api/monitor/diff`

**请求参数:**
```json
{
  "old": [],
  "new": []
}
```

---

## 18. 流量分析

### 18.1 分析所有流量

**POST** `/api/traffic/analyze`

---

### 18.2 分析单条流量

**GET** `/api/traffic/analyze/<int:traffic_id>`

---

## 19. CI/CD 集成

### 19.1 CI/CD 扫描

**POST** `/api/ci/scan`

**请求参数:**
```json
{
  "url": "https://example.com",
  "spec": "",
  "security": false,
  "auth_check": false,
  "header_audit": false,
  "fail_on": "high",
  "depth": "normal",
  "max_pages": 100
}
```

**响应示例:**
```json
{
  "summary": {
    "passed": true,
    "exit_code": 0,
    "total_endpoints": 50,
    "high_risk": 0
  },
  "endpoints": [],
  "phases": {},
  "timestamp": "2026-05-29T12:00:00"
}
```

---

### 19.2 健康检查

**GET** `/api/ci/health`

**响应示例:**
```json
{
  "status": "ok",
  "tool": "灵探",
  "version": "2.0",
  "timestamp": "2026-05-29T12:00:00",
  "modules": {
    "crawler": true,
    "fuzzer": true,
    "analyzer": true
  }
}
```

---

## 20. 收藏与历史

### 20.1 获取收藏列表

**GET** `/api/favorites`

**响应示例:**
```json
{
  "favorites": [
    {
      "id": 1,
      "url": "https://api.example.com/users",
      "method": "GET",
      "label": "用户列表"
    }
  ],
  "favorite_set": ["GET:https://api.example.com/users"]
}
```

---

### 20.2 切换收藏状态

**POST** `/api/favorites/toggle`

**请求参数:**
```json
{
  "url": "https://api.example.com/users",
  "method": "GET",
  "label": "用户列表"
}
```

---

### 20.3 获取请求历史

**GET** `/api/history`

**查询参数:**

| 参数 | 类型 | 说明 |
|------|------|------|
| limit | int | 返回数量 |

---

### 20.4 清除请求历史

**DELETE** `/api/history`

---

### 20.5 删除单条历史

**DELETE** `/api/history/<int:hist_id>`

---

## 21. 会话管理

### 21.1 获取会话列表

**GET** `/api/sessions`

---

### 21.2 打开登录窗口

**POST** `/api/sessions/open`

**请求参数:**
```json
{
  "url": "https://example.com/login",
  "name": "测试会话"
}
```

---

### 21.3 捕获会话

**POST** `/api/sessions/capture/<win_id>`

---

### 21.4 关闭登录窗口

**POST** `/api/sessions/close/<win_id>`

---

### 21.5 删除会话

**DELETE** `/api/sessions/<int:sid>`

---

## 22. 爬取规则

### 22.1 获取规则列表

**GET** `/api/crawl-rules`

---

### 22.2 创建规则

**POST** `/api/crawl-rules`

**请求参数:**
```json
{
  "name": "博客爬取",
  "url_pattern": "/blog/",
  "max_depth": 3,
  "include_patterns": ["/blog/"],
  "exclude_patterns": ["/admin/"]
}
```

---

### 22.3 删除规则

**DELETE** `/api/crawl-rules/<int:rid>`

---

### 22.4 获取规则示例

**GET** `/api/crawl-rules/examples`

---

## 23. 智能分析

### 23.1 页面分类

**POST** `/api/analyze/classify`

**请求参数:**
```json
{
  "url": "https://example.com/blog/post-1",
  "html": "<article>...</article>"
}
```

**响应示例:**
```json
{
  "type": "article_detail",
  "confidence": 0.85,
  "label": "文章详情"
}
```

---

### 23.2 结构化数据提取

**POST** `/api/analyze/extract`

**请求参数:**
```json
{
  "url": "https://example.com",
  "html": "<html>...</html>"
}
```

---

### 23.3 翻页检测

**POST** `/api/analyze/pagination`

**请求参数:**
```json
{
  "url": "https://example.com/list?page=2",
  "html": "<nav class='pagination'>...</nav>"
}
```

---

### 23.4 SPA 分析

**POST** `/api/analyze/spa`

**请求参数:**
```json
{
  "url": "https://example.com",
  "html": "<div id='__next'></div>"
}
```

---

## 24. WAF 检测

### 24.1 WAF 检测

**POST** `/api/waf/detect`

**请求参数:**
```json
{
  "url": "https://example.com"
}
```

**响应示例:**
```json
{
  "detected": true,
  "waf_name": "Cloudflare",
  "confidence": 0.9,
  "bypass_suggestions": ["使用分块传输", "使用Unicode编码"]
}
```

---

## 25. 技术栈指纹

### 25.1 技术栈指纹识别

**POST** `/api/tech/fingerprint`

**请求参数:**
```json
{
  "url": "https://example.com"
}
```

**响应示例:**
```json
{
  "technologies": [
    {"name": "WordPress", "category": "CMS", "confidence": 0.95},
    {"name": "Nginx", "category": "Web Server", "confidence": 0.8}
  ]
}
```

---

## 26. Payload 绕过

### 26.1 测试 Payload 绕过

**POST** `/api/evasion/test`

**请求参数:**
```json
{
  "payload": "' OR '1'='1",
  "url": "https://example.com",
  "waf_info": {"detected": true, "waf_name": "Cloudflare"}
}
```

**响应示例:**
```json
{
  "payload": "' OR '1'='1",
  "evaded": [
    {"strategy": "url_encode", "payload": "%27%20OR%20%271%27%3D%271"},
    {"strategy": "case_swap", "payload": "' oR '1'='1"}
  ]
}
```

---

## 27. 扫描断点续传

### 27.1 获取检查点列表

**GET** `/api/scan/checkpoints`

---

### 27.2 删除检查点

**DELETE** `/api/scan/checkpoints/<checkpoint_id>`

---

## 28. 备份文件探测

### 28.1 启动备份探测

**POST** `/api/backup/scan`

**请求参数:**
```json
{
  "url": "https://example.com"
}
```

---

### 28.2 探测进度

**GET** `/api/backup/progress`

---

## 29. 云存储泄露检测

### 29.1 云存储扫描

**POST** `/api/cloud/scan`

**请求参数:**
```json
{
  "url": "https://example.com",
  "html": "<script>var s3 = 'https://bucket.s3.amazonaws.com'</script>"
}
```

---

## 30. Favicon 指纹

### 30.1 Favicon 分析

**POST** `/api/favicon/analyze`

**请求参数:**
```json
{
  "url": "https://example.com"
}
```

---

### 30.2 Favicon 对比

**POST** `/api/favicon/compare`

**请求参数:**
```json
{
  "url1": "https://example1.com",
  "url2": "https://example2.com"
}
```

---

## 31. 403/401 绕过

### 31.1 启动绕过测试

**POST** `/api/forbidden/scan`

**请求参数:**
```json
{
  "url": "https://example.com/admin"
}
```

---

### 31.2 测试进度

**GET** `/api/forbidden/progress`

---

## 32. Wayback Machine

### 32.1 启动 Wayback 查询

**POST** `/api/wayback/scan`

**请求参数:**
```json
{
  "url": "example.com"
}
```

---

### 32.2 查询进度

**GET** `/api/wayback/progress`

---

## 33. 404 页面学习

### 33.1 学习 404 页面

**POST** `/api/errorpage/learn`

**请求参数:**
```json
{
  "url": "https://example.com/nonexistent-page-12345"
}
```

---

## 34. OAST 带外检测

### 34.1 启动 OAST 检测

**POST** `/api/oast/scan`

**请求参数:**
```json
{
  "url": "https://example.com/search",
  "param": "q",
  "method": "GET"
}
```

---

### 34.2 检测进度

**GET** `/api/oast/progress`

---

### 34.3 停止检测

**POST** `/api/oast/stop`

---

## 35. YAML 模板引擎

### 35.1 获取模板列表

**GET** `/api/templates/list`

---

### 35.2 运行模板

**POST** `/api/templates/run`

**请求参数:**
```json
{
  "url": "https://example.com",
  "template_id": "tech-spring-boot",
  "severity_filter": "high",
  "tag_filter": "tech"
}
```

---

### 35.3 添加自定义模板

**POST** `/api/templates/add`

**请求参数:**
```json
{
  "id": "custom-test",
  "info": {"name": "Custom Test", "severity": "low"},
  "requests": [
    {
      "method": "GET",
      "path": ["/test"],
      "matchers": [{"type": "status", "value": [200]}]
    }
  ]
}
```

---

## 36. 威胁情报

### 36.1 启动情报查询

**POST** `/api/intel/query`

**请求参数:**
```json
{
  "domain": "example.com",
  "shodan_key": "YOUR_SHODAN_KEY",
  "censys_id": "YOUR_CENSYS_ID",
  "censys_secret": "YOUR_CENSYS_SECRET",
  "fofa_email": "YOUR_FOFA_EMAIL",
  "fofa_key": "YOUR_FOFA_KEY"
}
```

---

### 36.2 查询进度

**GET** `/api/intel/progress`

---

## 37. JARM 指纹

### 37.1 JARM 指纹识别

**POST** `/api/jarm/fingerprint`

**请求参数:**
```json
{
  "host": "example.com",
  "port": 443
}
```

**响应示例:**
```json
{
  "host": "example.com",
  "port": 443,
  "jarm_hash": "29d29d15d29d29d00029d29d29d29d...",
  "matches": [],
  "raw_probes": []
}
```

---

### 37.2 JARM 对比

**POST** `/api/jarm/compare`

**请求参数:**
```json
{
  "target1": {"host": "example1.com", "port": 443},
  "target2": {"host": "example2.com", "port": 443}
}
```

---

## 38. 依赖图

### 38.1 获取依赖图数据

**GET** `/api/graph/data`

**查询参数:**

| 参数 | 类型 | 说明 |
|------|------|------|
| target_id | int | 目标 ID |

**响应示例:**
```json
{
  "nodes": [
    {
      "id": "https://example.com",
      "label": "/",
      "title": "Home",
      "status": 200,
      "depth": 0
    }
  ],
  "edges": [
    {
      "source": "https://example.com",
      "target": "https://example.com/about"
    }
  ],
  "total_nodes": 10,
  "total_edges": 15
}
```

---

## 39. 工具类

### 39.1 端口扫描

**POST** `/api/tools/portscan`

**请求参数:**
```json
{
  "host": "127.0.0.1",
  "type": "web",
  "web_only": false
}
```

---

### 39.2 差异对比

**POST** `/api/tools/diff`

**请求参数:**
```json
{
  "old_target_id": 1,
  "new_target_id": 2
}
```

---

### 39.3 接口分组

**GET/POST** `/api/tools/group`

---

### 39.4 自定义请求

**POST** `/api/tools/request`

**请求参数:**
```json
{
  "url": "https://api.example.com/users",
  "method": "POST",
  "headers": {"Content-Type": "application/json"},
  "body": "{\"name\":\"test\"}"
}
```

**响应示例:**
```json
{
  "status_code": 200,
  "headers": {},
  "body": "{\"id\":1}",
  "body_size": 100,
  "time": 0.5,
  "url": "https://api.example.com/users",
  "curl": "curl -X POST ...",
  "is_json": true
}
```

---

### 39.5 脚本生成

**POST** `/api/scripts/generate`

**请求参数:**
```json
{
  "type": "python",
  "target_id": 1
}
```

**支持类型:** python, playwright, curl

---

### 39.6 清除数据

**POST** `/api/clear`

清除所有扫描数据。

---

## 附录

### 错误响应格式

所有错误响应格式统一：
```json
{
  "error": "错误信息"
}
```

### 常见 HTTP 状态码

| 状态码 | 说明 |
|--------|------|
| 200 | 成功 |
| 400 | 请求参数错误 |
| 404 | 资源不存在 |
| 422 | CI/CD 扫描未通过 |
| 500 | 服务器内部错误 |
| 502 | 连接失败 |
| 504 | 请求超时 |

### 认证方式

当前 API 不需要认证，仅限本地使用。

### 请求限制

- 文件上传最大 500MB
- 批量扫描最多 50 个 URL
- 批量 JS 分析最多 30 个文件
- 静态资源下载最多 200 个

---

*文档生成时间: 2026-05-29*
