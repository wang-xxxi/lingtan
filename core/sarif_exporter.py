"""SARIF 导出 — 静态分析结果交换格式 (GitHub/VS Code/Azure DevOps 集成)"""
import json
import time


class SARIFExporter:
    """SARIF 2.1.0 格式导出器"""

    VERSION = '2.1.0'
    SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json'

    # 灵探检测类型到 SARIF 规则的映射
    RULE_MAP = {
        'sql_injection': {
            'id': 'LINGTAN-SQLI-001',
            'name': 'SQLInjection',
            'shortDescription': {'text': 'SQL 注入漏洞'},
            'fullDescription': {'text': '参数中注入 SQL 特殊字符后响应异常，可能存在 SQL 注入漏洞'},
            'helpUri': 'https://owasp.org/www-community/attacks/SQL_Injection',
            'defaultConfiguration': {'level': 'error'},
        },
        'sql_injection_blind': {
            'id': 'LINGTAN-SQLI-002',
            'name': 'BlindSQLInjection',
            'shortDescription': {'text': '盲注 SQL 注入漏洞'},
            'fullDescription': {'text': '基于时间的盲注检测，响应时间异常延迟'},
            'helpUri': 'https://owasp.org/www-community/attacks/Blind_SQL_Injection',
            'defaultConfiguration': {'level': 'error'},
        },
        'reflected_xss': {
            'id': 'LINGTAN-XSS-001',
            'name': 'ReflectedXSS',
            'shortDescription': {'text': '反射型 XSS 漏洞'},
            'fullDescription': {'text': '注入的 XSS payload 在响应中原样返回'},
            'helpUri': 'https://owasp.org/www-community/attacks/xss/',
            'defaultConfiguration': {'level': 'error'},
        },
        'path_traversal': {
            'id': 'LINGTAN-PT-001',
            'name': 'PathTraversal',
            'shortDescription': {'text': '路径遍历漏洞'},
            'fullDescription': {'text': '通过 ../ 等方式可能访问系统文件'},
            'helpUri': 'https://owasp.org/www-community/attacks/Path_Traversal',
            'defaultConfiguration': {'level': 'error'},
        },
        'ssrf': {
            'id': 'LINGTAN-SSRF-001',
            'name': 'SSRF',
            'shortDescription': {'text': '服务端请求伪造'},
            'fullDescription': {'text': '参数中注入内网地址，响应异常'},
            'helpUri': 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
            'defaultConfiguration': {'level': 'error'},
        },
        'command_injection': {
            'id': 'LINGTAN-CMDI-001',
            'name': 'CommandInjection',
            'shortDescription': {'text': '命令注入漏洞'},
            'fullDescription': {'text': '注入系统命令分隔符后响应异常'},
            'helpUri': 'https://owasp.org/www-community/attacks/Command_Injection',
            'defaultConfiguration': {'level': 'error'},
        },
        'open_redirect': {
            'id': 'LINGTAN-OR-001',
            'name': 'OpenRedirect',
            'shortDescription': {'text': '开放重定向漏洞'},
            'fullDescription': {'text': '参数可控制重定向目标'},
            'helpUri': 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
            'defaultConfiguration': {'level': 'warning'},
        },
        'sensitive_file': {
            'id': 'LINGTAN-SF-001',
            'name': 'SensitiveFileExposure',
            'shortDescription': {'text': '敏感文件泄露'},
            'fullDescription': {'text': '备份文件、配置文件、版本控制目录等可通过 Web 访问'},
            'defaultConfiguration': {'level': 'warning'},
        },
        'security_header_missing': {
            'id': 'LINGTAN-SH-001',
            'name': 'MissingSecurityHeader',
            'shortDescription': {'text': '安全响应头缺失'},
            'fullDescription': {'text': 'HTTP 响应头缺少安全相关的配置'},
            'defaultConfiguration': {'level': 'note'},
        },
        'cloud_storage_public': {
            'id': 'LINGTAN-CS-001',
            'name': 'PublicCloudStorage',
            'shortDescription': {'text': '云存储公开访问'},
            'fullDescription': {'text': '云存储桶/容器允许公开访问'},
            'defaultConfiguration': {'level': 'error'},
        },
        'backup_file': {
            'id': 'LINGTAN-BF-001',
            'name': 'BackupFileExposure',
            'shortDescription': {'text': '备份文件泄露'},
            'fullDescription': {'text': '.bak/.old/.git 等备份文件可通过 Web 访问'},
            'defaultConfiguration': {'level': 'warning'},
        },
        '403_bypass': {
            'id': 'LINGTAN-BP-001',
            'name': 'ForbiddenBypass',
            'shortDescription': {'text': '403 访问控制绕过'},
            'fullDescription': {'text': '通过 Header 欺骗或路径变换可绕过 403 限制'},
            'defaultConfiguration': {'level': 'warning'},
        },
    }

    # 严重程度映射
    SEVERITY_LEVEL = {
        'critical': 'error',
        'high': 'error',
        'medium': 'warning',
        'low': 'note',
        'info': 'none',
    }

    def export(self, scan_results, source_url='', tool_name='灵探'):
        """将扫描结果导出为 SARIF 2.1.0 格式

        Args:
            scan_results: 扫描结果 dict，需包含:
                - 'vulnerabilities': list of vuln dicts
                - 'sensitive_files': list of file dicts (可选)
                - 'findings': list of finding dicts (可选)
            source_url: 扫描目标 URL
            tool_name: 工具名称

        Returns:
            dict: SARIF 2.1.0 格式的 JSON 对象
        """
        rules = []
        results = []
        rule_ids_seen = set()

        # 处理漏洞列表
        vulns = scan_results.get('vulnerabilities', [])
        for vuln in vulns:
            vtype = vuln.get('type', 'unknown')
            rule_info = self.RULE_MAP.get(vtype)
            if not rule_info:
                # 动态创建规则
                rule_info = {
                    'id': f'LINGTAN-GEN-{vtype.upper()[:10]}',
                    'name': vtype,
                    'shortDescription': {'text': vuln.get('description', vtype)},
                    'defaultConfiguration': {'level': self.SEVERITY_LEVEL.get(vuln.get('severity', 'info'), 'note')},
                }

            if rule_info['id'] not in rule_ids_seen:
                rules.append({'id': rule_info['id'], **rule_info})
                rule_ids_seen.add(rule_info['id'])

            sarif_result = {
                'ruleId': rule_info['id'],
                'level': self.SEVERITY_LEVEL.get(vuln.get('severity', 'info'), 'note'),
                'message': {
                    'text': vuln.get('description', ''),
                    'markdown': f'**{vuln.get("type", "")}**: {vuln.get("description", "")}',
                },
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {
                            'uri': vuln.get('url', source_url),
                            'uriBaseId': 'ROOTPATH',
                        },
                    },
                    'logicalLocations': [{
                        'fullyQualifiedName': vuln.get('parameter', ''),
                    }],
                }],
                'properties': {
                    'evidence': vuln.get('evidence', ''),
                    'payload': vuln.get('payload', ''),
                    'severity': vuln.get('severity', 'info'),
                },
            }
            results.append(sarif_result)

        # 处理敏感文件
        for f in scan_results.get('sensitive_files', []):
            rule_id = 'LINGTAN-SF-001'
            if rule_id not in rule_ids_seen:
                rules.append(self.RULE_MAP['sensitive_file'])
                rule_ids_seen.add(rule_id)

            results.append({
                'ruleId': rule_id,
                'level': 'warning',
                'message': {'text': f'敏感文件泄露: {f.get("path", "")}'},
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {'uri': f.get("url", ""), 'uriBaseId': 'ROOTPATH'},
                    },
                }],
            })

        # 处理备份文件探测结果
        for f in scan_results.get('findings', []):
            severity = f.get('severity', 'low')
            rule_id = 'LINGTAN-BF-001'
            if rule_id not in rule_ids_seen:
                rules.append(self.RULE_MAP['backup_file'])
                rule_ids_seen.add(rule_id)

            results.append({
                'ruleId': rule_id,
                'level': self.SEVERITY_LEVEL.get(severity, 'note'),
                'message': {'text': f'{f.get("description", "")}: {f.get("path", "")}'},
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {'uri': f.get("url", ""), 'uriBaseId': 'ROOTPATH'},
                    },
                }],
            })

        # 处理安全头
        for header in scan_results.get('missing_headers', []):
            rule_id = 'LINGTAN-SH-001'
            if rule_id not in rule_ids_seen:
                rules.append(self.RULE_MAP['security_header_missing'])
                rule_ids_seen.add(rule_id)

            results.append({
                'ruleId': rule_id,
                'level': 'note',
                'message': {'text': f'安全响应头缺失: {header}'},
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {'uri': source_url, 'uriBaseId': 'ROOTPATH'},
                    },
                }],
            })

        sarif = {
            '$schema': self.SCHEMA,
            'version': self.VERSION,
            'runs': [{
                'tool': {
                    'driver': {
                        'name': tool_name,
                        'fullName': '灵探 API 接口发现与安全分析系统',
                        'version': '1.0.0',
                        'informationUri': 'https://github.com/LingTan/LingTan',
                        'rules': rules,
                    },
                },
                'results': results,
                'invocations': [{
                    'executionSuccessful': True,
                    'endTimeUtc': self._timestamp(),
                    'toolExecutionNotifications': [],
                }],
                'artifacts': self._build_artifacts(source_url, results),
            }],
        }

        return sarif

    def export_to_file(self, scan_results, filepath, source_url='', tool_name='灵探'):
        """导出到文件"""
        sarif = self.export(scan_results, source_url, tool_name)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, ensure_ascii=False, indent=2)
        return filepath

    @staticmethod
    def _timestamp():
        """生成 ISO 8601 时间戳"""
        return time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())

    @staticmethod
    def _build_artifacts(source_url, results):
        """构建 artifacts 列表"""
        uris_seen = set()
        artifacts = []
        for r in results:
            for loc in r.get('locations', []):
                uri = loc.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
                if uri and uri not in uris_seen:
                    uris_seen.add(uri)
                    artifacts.append({
                        'location': {'uri': uri, 'uriBaseId': 'ROOTPATH'},
                    })
        return artifacts
