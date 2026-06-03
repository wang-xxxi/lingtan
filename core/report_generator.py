"""Professional HTML security report generation"""
import os
import time
import json
import html as html_module
from datetime import datetime

from core.path_resolver import get_reports_dir
REPORTS_DIR = get_reports_dir()


class ReportGenerator:
    """Generate self-contained HTML security reports"""

    def __init__(self):
        os.makedirs(REPORTS_DIR, exist_ok=True)

    def generate(self, endpoints=None, stats=None, targets=None,
                 technologies=None, seo_result=None, pages=None,
                 security_results=None, title=None):
        """Generate a complete HTML report"""
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        filename = f'report_{int(time.time())}.html'
        filepath = os.path.join(REPORTS_DIR, filename)

        if not title:
            target = ''
            if targets:
                target = targets[0].get('url', '') if isinstance(targets[0], dict) else str(targets[0])
            title = f'灵探安全扫描报告 — {target}' if target else '灵探安全扫描报告'

        # Parse security data
        vulns = []
        sensitive_files = []
        info_disclosure = []
        waf_info = None
        scan_time = 0
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        if security_results:
            vulns = security_results.get('vulnerabilities', [])
            sensitive_files = security_results.get('sensitive_files', [])
            info_disclosure = security_results.get('info_disclosure', [])
            waf_info = security_results.get('waf_info')
            scan_time = security_results.get('scan_time', 0)
            summary = security_results.get('summary', summary)

        # Also collect security issues from endpoints
        for ep in (endpoints or []):
            for issue in (ep.get('security_issues') or []):
                sev = issue.get('risk_level', 'high')
                vulns.append({
                    'type': issue.get('type', 'unknown'),
                    'severity': sev,
                    'title': issue.get('description', issue.get('type', '')),
                    'description': issue.get('description', ''),
                    'url': ep.get('url', ''),
                    'evidence': issue.get('evidence', ''),
                })

        # Recalculate summary
        all_findings = vulns + sensitive_files + info_disclosure
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in all_findings:
            sev = f.get('severity', 'info')
            summary[sev] = summary.get(sev, 0) + 1

        # Calculate overall risk score (0-100)
        risk_score = min(100, summary['critical'] * 20 + summary['high'] * 10 +
                         summary['medium'] * 5 + summary['low'] * 2)

        html_content = self._build_html(
            title=title, now=now, scan_time=scan_time,
            endpoints=endpoints or [], stats=stats or {},
            targets=targets or [], technologies=technologies or [],
            seo_result=seo_result, pages=pages or [],
            vulns=vulns, sensitive_files=sensitive_files,
            info_disclosure=info_disclosure, waf_info=waf_info,
            summary=summary, risk_score=risk_score,
        )

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return {'filename': filename, 'filepath': filepath}

    def _build_html(self, **d):
        """Build the complete HTML document"""
        return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html_module.escape(d['title'])}</title>
<style>{self._get_css()}</style>
</head>
<body>
<div class="report">
{self._header_section(d)}
{self._executive_summary(d)}
{self._vuln_details_section(d)}
{self._sensitive_files_section(d)}
{self._waf_section(d)}
{self._headers_section(d)}
{self._endpoints_section(d)}
{self._tech_section(d)}
{self._seo_section(d)}
{self._pages_section(d)}
{self._footer_section(d)}
</div>
<script>{self._get_js()}</script>
</body>
</html>'''

    # ── CSS ──

    def _get_css(self):
        return '''
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:#f5f7fa;color:#1a1d27;line-height:1.6}
.report{max-width:1100px;margin:0 auto;padding:24px}

/* Header */
.report-header{background:linear-gradient(135deg,#6c63ff,#4f46e5);color:#fff;padding:40px 36px;border-radius:16px;margin-bottom:24px;position:relative;overflow:hidden}
.report-header::after{content:'';position:absolute;top:-50%;right:-10%;width:300px;height:300px;background:rgba(255,255,255,0.05);border-radius:50%}
.report-header h1{font-size:26px;margin-bottom:6px;font-weight:700}
.report-header .meta{opacity:0.8;font-size:13px;display:flex;gap:20px;flex-wrap:wrap}

/* Executive Summary */
.exec-summary{background:#fff;border:1px solid #e2e4ea;border-radius:16px;padding:28px;margin-bottom:20px}
.exec-summary h2{font-size:18px;margin-bottom:16px;color:#1a1d27}
.risk-meter{display:flex;align-items:center;gap:20px;margin-bottom:20px;padding:20px;background:#f8f9fc;border-radius:12px}
.risk-score{width:90px;height:90px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:800;color:#fff;flex-shrink:0}
.risk-critical-bg{background:linear-gradient(135deg,#dc2626,#ef4444)}
.risk-high-bg{background:linear-gradient(135deg,#ea580c,#f97316)}
.risk-medium-bg{background:linear-gradient(135deg,#ca8a04,#eab308)}
.risk-low-bg{background:linear-gradient(135deg,#16a34a,#22c55e)}
.risk-info-bg{background:linear-gradient(135deg,#2563eb,#60a5fa)}
.risk-detail h3{font-size:16px;margin-bottom:4px}
.risk-detail p{font-size:13px;color:#6b7280}
.sev-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-top:16px}
.sev-card{background:#fff;border:1px solid #e2e4ea;border-radius:10px;padding:14px;text-align:center}
.sev-count{font-size:28px;font-weight:800;line-height:1}
.sev-label{font-size:12px;color:#6b7280;margin-top:4px}
.sev-critical .sev-count{color:#dc2626}
.sev-high .sev-count{color:#f97316}
.sev-medium .sev-count{color:#eab308}
.sev-low .sev-count{color:#22c55e}
.sev-info .sev-count{color:#60a5fa}

/* Section */
.section{background:#fff;border:1px solid #e2e4ea;border-radius:16px;padding:28px;margin-bottom:20px}
.section h2{font-size:18px;margin-bottom:16px;padding-bottom:8px;border-bottom:2px solid #6c63ff;display:inline-block}

/* Vuln Card */
.vuln-card{border:1px solid #e2e4ea;border-radius:12px;padding:20px;margin-bottom:16px;position:relative;border-left:4px solid}
.vuln-critical{border-left-color:#dc2626}
.vuln-high{border-left-color:#f97316}
.vuln-medium{border-left-color:#eab308}
.vuln-low{border-left-color:#22c55e}
.vuln-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;flex-wrap:wrap;gap:8px}
.vuln-title{font-size:15px;font-weight:700}
.vuln-badge{display:inline-block;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;color:#fff}
.vuln-badge-critical{background:#dc2626}
.vuln-badge-high{background:#f97316}
.vuln-badge-medium{background:#eab308;color:#1a1d27}
.vuln-badge-low{background:#22c55e}
.vuln-meta{display:grid;grid-template-columns:auto 1fr;gap:4px 16px;font-size:13px;margin-bottom:10px}
.vuln-meta dt{color:#6b7280;font-weight:600}
.vuln-meta dd{color:#1a1d27;word-break:break-all}
.vuln-evidence{background:#1a1d27;color:#a5f3fc;border-radius:8px;padding:12px 16px;font-family:"Cascadia Code","Fira Code",monospace;font-size:12px;margin:10px 0;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.vuln-remediation{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:12px 16px;font-size:13px;color:#166534;margin-top:10px}
.vuln-remediation strong{color:#15803d}

/* Table */
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px 12px;border-bottom:2px solid #e2e4ea;color:#6b7280;font-weight:600;font-size:12px;text-transform:uppercase}
td{padding:8px 12px;border-bottom:1px solid #f0f1f5;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:#f8f9fc}

/* Badges */
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase}
.badge-get{background:rgba(59,130,246,0.15);color:#3b82f6}
.badge-post{background:rgba(16,185,129,0.15);color:#10b981}
.badge-put{background:rgba(245,158,11,0.15);color:#f59e0b}
.badge-delete{background:rgba(239,68,68,0.15);color:#ef4444}
.badge-patch{background:rgba(108,99,255,0.15);color:#6c63ff}
.risk-critical{background:rgba(220,38,38,0.15);color:#dc2626}
.risk-high{background:rgba(249,115,22,0.15);color:#f97316}
.risk-medium{background:rgba(234,179,8,0.15);color:#eab308}
.risk-low{background:rgba(34,197,94,0.15);color:#22c55e}
.risk-info{background:rgba(96,165,250,0.15);color:#60a5fa}

.tech-badge{display:inline-block;padding:4px 12px;border-radius:16px;font-size:12px;margin:3px;border:1px solid #e2e4ea;background:#f8f9fc}
.score-circle{width:80px;height:80px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:700;color:#fff}
.score-good{background:linear-gradient(135deg,#10b981,#34d399)}
.score-ok{background:linear-gradient(135deg,#f59e0b,#fbbf24)}
.score-bad{background:linear-gradient(135deg,#ef4444,#f87171)}

/* Filter tabs */
.filter-tabs{display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap}
.filter-tab{padding:4px 14px;border-radius:20px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid #e2e4ea;background:#fff;color:#6b7280;transition:all 0.2s}
.filter-tab:hover,.filter-tab.active{background:#6c63ff;color:#fff;border-color:#6c63ff}
.filter-count{background:rgba(255,255,255,0.3);border-radius:10px;padding:0 6px;font-size:10px;margin-left:4px}

/* Summary list */
.summary-list{list-style:none}
.summary-list li{padding:6px 0;border-bottom:1px solid #f0f1f5;font-size:13px;display:flex;align-items:center;gap:8px}
.summary-list li:last-child{border-bottom:none}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dot-critical{background:#dc2626}
.dot-high{background:#f97316}
.dot-medium{background:#eab308}
.dot-low{background:#22c55e}

.footer{text-align:center;color:#9ca3af;font-size:12px;padding:20px 0}
@media print{body{background:#fff}.report{padding:0}.section{break-inside:avoid}.filter-tabs{display:none}}
'''

    # ── JavaScript ──

    def _get_js(self):
        return '''
document.querySelectorAll('.filter-tab').forEach(function(tab){
    tab.addEventListener('click',function(){
        var sev=this.getAttribute('data-sev');
        this.parentElement.querySelectorAll('.filter-tab').forEach(function(t){t.classList.remove('active')});
        this.classList.add('active');
        document.querySelectorAll('.vuln-card').forEach(function(card){
            if(sev==='all'||card.getAttribute('data-severity')===sev){
                card.style.display='';
            }else{
                card.style.display='none';
            }
        });
    });
});
'''

    # ── Sections ──

    def _header_section(self, d):
        targets = d.get('targets', [])
        target_url = ''
        if targets:
            t = targets[0]
            target_url = t.get('url', '') if isinstance(t, dict) else str(t)
        ep_count = len(d.get('endpoints', []))
        scan_time = d.get('scan_time', 0)

        return f'''
<div class="report-header">
    <h1>{html_module.escape(d['title'])}</h1>
    <div class="meta">
        <span>生成时间: {d['now']}</span>
        {f'<span>目标: {html_module.escape(target_url)}</span>' if target_url else ''}
        <span>发现接口: {ep_count}</span>
        {f'<span>扫描耗时: {scan_time}s</span>' if scan_time else ''}
    </div>
</div>'''

    def _executive_summary(self, d):
        summary = d['summary']
        risk_score = d['risk_score']

        if risk_score >= 70:
            score_class = 'risk-critical-bg'
            risk_level = '高风险'
            risk_desc = '存在严重安全问题，需要立即修复'
        elif risk_score >= 40:
            score_class = 'risk-high-bg'
            risk_level = '中高风险'
            risk_desc = '存在若干安全隐患，建议尽快处理'
        elif risk_score >= 15:
            score_class = 'risk-medium-bg'
            risk_level = '中等风险'
            risk_desc = '发现少量安全问题，建议定期关注'
        elif risk_score > 0:
            score_class = 'risk-low-bg'
            risk_level = '低风险'
            risk_desc = '发现轻微安全问题，整体风险可控'
        else:
            score_class = 'risk-info-bg'
            risk_level = '未发现风险'
            risk_desc = '未检测到已知安全漏洞'

        total = sum(summary.values())

        return f'''
<div class="exec-summary">
    <h2>安全评估概览</h2>
    <div class="risk-meter">
        <div class="risk-score {score_class}">{risk_score}</div>
        <div class="risk-detail">
            <h3>风险等级: {risk_level}</h3>
            <p>{risk_desc}</p>
            <p style="margin-top:4px;font-size:12px;color:#9ca3af">共发现 {total} 项安全问题</p>
        </div>
    </div>
    <div class="sev-grid">
        <div class="sev-card sev-critical"><div class="sev-count">{summary.get("critical",0)}</div><div class="sev-label">严重</div></div>
        <div class="sev-card sev-high"><div class="sev-count">{summary.get("high",0)}</div><div class="sev-label">高风险</div></div>
        <div class="sev-card sev-medium"><div class="sev-count">{summary.get("medium",0)}</div><div class="sev-label">中风险</div></div>
        <div class="sev-card sev-low"><div class="sev-count">{summary.get("low",0)}</div><div class="sev-label">低风险</div></div>
        <div class="sev-card sev-info"><div class="sev-count">{summary.get("info",0)}</div><div class="sev-label">信息</div></div>
    </div>
</div>'''

    def _vuln_details_section(self, d):
        vulns = d.get('vulns', [])
        if not vulns:
            return ''

        # Sort by severity
        sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        vulns_sorted = sorted(vulns, key=lambda v: sev_order.get(v.get('severity', 'info'), 5))

        cards = ''
        for i, v in enumerate(vulns_sorted):
            sev = v.get('severity', 'info')
            title = v.get('title') or v.get('description', v.get('type', '未知'))
            vtype = v.get('type', '')
            url = v.get('url', '')
            parameter = v.get('parameter', '')
            payload = v.get('payload', '')
            evidence = v.get('evidence', '')
            response = v.get('response_snippet', '')
            cvss = v.get('cvss', '')
            remediation = v.get('remediation', '')

            evidence_block = ''
            if payload:
                evidence_block += f'<div class="vuln-evidence">Payload: {html_module.escape(str(payload))}</div>'
            if response:
                evidence_block += f'<div class="vuln-evidence">响应片段: {html_module.escape(str(response))}</div>'
            elif evidence:
                evidence_block += f'<div class="vuln-evidence">{html_module.escape(str(evidence))}</div>'

            remediation_block = ''
            if remediation:
                remediation_block = f'<div class="vuln-remediation"><strong>修复建议:</strong> {html_module.escape(str(remediation))}</div>'

            cards += f'''
    <div class="vuln-card vuln-{sev}" data-severity="{sev}">
        <div class="vuln-header">
            <span class="vuln-title">{html_module.escape(str(title))}</span>
            <span class="vuln-badge vuln-badge-{sev}">{sev.upper()}</span>
        </div>
        <dl class="vuln-meta">
            <dt>类型</dt><dd>{html_module.escape(str(vtype))}</dd>
            <dt>URL</dt><dd style="word-break:break-all">{html_module.escape(str(url))}</dd>
            {f'<dt>参数</dt><dd>{html_module.escape(str(parameter))}</dd>' if parameter else ''}
            {f'<dt>CVSS</dt><dd>{cvss}</dd>' if cvss else ''}
        </dl>
        {evidence_block}
        {remediation_block}
    </div>'''

        # Filter tabs
        counts = {}
        for v in vulns_sorted:
            s = v.get('severity', 'info')
            counts[s] = counts.get(s, 0) + 1

        tabs = '<div class="filter-tabs"><span class="filter-tab active" data-sev="all">全部 <span class="filter-count">{len(vulns_sorted)}</span></span>'
        for sev in ['critical', 'high', 'medium', 'low']:
            if counts.get(sev):
                tabs += f'<span class="filter-tab" data-sev="{sev}">{sev.upper()} <span class="filter-count">{counts[sev]}</span></span>'
        tabs += '</div>'

        return f'''
<div class="section">
    <h2>漏洞详情 ({len(vulns_sorted)})</h2>
    {tabs}
    {cards}
</div>'''

    def _sensitive_files_section(self, d):
        files = d.get('sensitive_files', [])
        if not files:
            return ''

        rows = ''
        for f in files[:100]:
            sev = f.get('severity', 'high')
            sev_class = f'risk-{sev}'
            url = html_module.escape(str(f.get('url', ''))[:120])
            desc = html_module.escape(str(f.get('description', '')))
            size = f.get('size', 0)
            size_str = f'{size}B' if size < 1024 else f'{size//1024}KB'
            remediation = html_module.escape(str(f.get('remediation', '')))
            rows += f'<tr><td><span class="badge {sev_class}">{sev}</span></td><td title="{url}">{url}</td><td>{desc}</td><td>{size_str}</td></tr>\n'

        return f'''
<div class="section">
    <h2>敏感文件泄露 ({len(files)})</h2>
    <p style="font-size:13px;color:#6b7280;margin-bottom:12px">以下文件可被公开访问，可能泄露配置信息、数据库备份或密钥</p>
    <table>
        <thead><tr><th>等级</th><th>URL</th><th>描述</th><th>大小</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
</div>'''

    def _waf_section(self, d):
        waf = d.get('waf_info')
        if not waf:
            return ''

        detected = waf.get('detected', False)
        if detected:
            content = f'''
        <div style="display:flex;gap:20px;align-items:center;padding:16px;background:#fef2f2;border-radius:8px;border:1px solid #fecaca;margin-bottom:12px">
            <div style="font-size:32px">&#128737;</div>
            <div>
                <div style="font-weight:700;color:#dc2626">{html_module.escape(waf.get('waf_name','未知'))}</div>
                <div style="font-size:13px;color:#6b7280">厂商: {html_module.escape(waf.get('vendor','未知'))} | 置信度: {waf.get('confidence',0)}%</div>
            </div>
        </div>'''
            evidence = waf.get('evidence', [])
            if evidence:
                content += '<div style="font-size:13px;margin-bottom:8px"><strong>检测依据:</strong></div><ul style="font-size:13px;color:#6b7280;padding-left:20px">'
                for e in evidence[:5]:
                    content += f'<li>{html_module.escape(str(e))}</li>'
                content += '</ul>'
            bypass = waf.get('bypass_suggestions', [])
            if bypass:
                content += '<div style="font-size:13px;margin-top:8px"><strong>绕过建议:</strong> ' + ' | '.join(html_module.escape(str(b)) for b in bypass[:5]) + '</div>'
        else:
            content = '<div style="padding:16px;background:#f0fdf4;border-radius:8px;border:1px solid #bbf7d0;font-size:13px;color:#166534">未检测到 WAF 防护</div>'

        return f'''
<div class="section">
    <h2>WAF 防护检测</h2>
    {content}
</div>'''

    def _headers_section(self, d):
        """Show security header findings and info disclosure"""
        vulns = d.get('vulns', [])
        info = d.get('info_disclosure', [])

        header_vulns = [v for v in vulns if v.get('type', '').endswith('security_header') or v.get('type', '').endswith('security_header')]
        if not header_vulns and not info:
            return ''

        content = ''
        if header_vulns:
            missing = [v for v in header_vulns if 'missing' in v.get('type', '')]
            weak = [v for v in header_vulns if 'weak' in v.get('type', '')]
            if missing:
                content += '<div style="margin-bottom:12px"><strong style="font-size:14px">缺少的安全响应头:</strong><ul class="summary-list" style="margin-top:8px">'
                for v in missing[:10]:
                    header_name = v.get('title', '').replace('缺少安全响应头: ', '')
                    desc = v.get('description', '')
                    content += f'<li><span class="dot dot-medium"></span><strong>{html_module.escape(header_name)}</strong> — {html_module.escape(desc)}</li>'
                content += '</ul></div>'
            if weak:
                content += '<div style="margin-bottom:12px"><strong style="font-size:14px">配置不当的响应头:</strong><ul class="summary-list" style="margin-top:8px">'
                for v in weak[:10]:
                    content += f'<li><span class="dot dot-low"></span>{html_module.escape(v.get("title",""))}</li>'
                content += '</ul></div>'

        if info:
            content += '<div><strong style="font-size:14px">信息泄露:</strong><ul class="summary-list" style="margin-top:8px">'
            for item in info[:10]:
                content += f'<li><span class="dot dot-low"></span>{html_module.escape(item.get("title",""))}: {html_module.escape(item.get("description",""))}</li>'
            content += '</ul></div>'

        return f'''
<div class="section">
    <h2>安全响应头</h2>
    {content}
</div>'''

    def _endpoints_section(self, d):
        endpoints = d.get('endpoints', [])
        if not endpoints:
            return ''
        rows = ''
        for ep in endpoints[:200]:
            method = ep.get('method', 'GET')
            method_class = f'badge-{method.lower()}'
            risk = ep.get('risk_level', 'info')
            risk_class = f'risk-{risk}'
            url = html_module.escape(str(ep.get('url', ''))[:120])
            cat = html_module.escape(str(ep.get('category', ''))[:30])
            rows += f'<tr><td><span class="badge {method_class}">{method}</span></td><td>{url}</td><td>{cat}</td><td><span class="badge {risk_class}">{risk}</span></td></tr>\n'

        return f'''
<div class="section">
    <h2>接口列表 ({len(endpoints)})</h2>
    <table>
        <thead><tr><th>方法</th><th>URL</th><th>分类</th><th>风险</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
</div>'''

    def _tech_section(self, d):
        techs = d.get('technologies', [])
        if not techs:
            return ''
        badges = ''
        for t in techs:
            name = html_module.escape(str(t.get('name', '')))
            cat = html_module.escape(str(t.get('category', '')))
            conf = t.get('confidence', 0)
            badges += f'<span class="tech-badge">{name} <small>({cat}, {int(conf*100)}%)</span>\n'

        return f'''
<div class="section">
    <h2>技术栈 ({len(techs)})</h2>
    <div>{badges}</div>
</div>'''

    def _seo_section(self, d):
        seo = d.get('seo_result')
        if not seo:
            return ''
        overall = seo.get('overall_score', 0)
        seo_info = seo.get('seo', {})
        perf_info = seo.get('performance', {})
        seo_score = seo_info.get('average_score', 0)
        perf_score = perf_info.get('average_score', 0)

        score_class = 'score-good' if overall >= 70 else ('score-ok' if overall >= 40 else 'score-bad')
        seo_class = 'score-good' if seo_score >= 70 else ('score-ok' if seo_score >= 40 else 'score-bad')
        perf_class = 'score-good' if perf_score >= 70 else ('score-ok' if perf_score >= 40 else 'score-bad')

        issues_html = ''
        summary = seo_info.get('summary', {})
        for issue in (summary.get('top_issues') or [])[:10]:
            issues_html += f'<li><span class="dot dot-medium"></span>{html_module.escape(issue["issue"])} ({issue["count"]} 页)</li>\n'

        return f'''
<div class="section">
    <h2>SEO 与性能</h2>
    <div style="display:flex;gap:24px;flex-wrap:wrap;margin-bottom:16px;">
        <div style="text-align:center"><div class="score-circle {score_class}">{overall}</div><div style="margin-top:8px;font-size:13px;color:#6b7280">综合</div></div>
        <div style="text-align:center"><div class="score-circle {seo_class}">{seo_score}</div><div style="margin-top:8px;font-size:13px;color:#6b7280">SEO</div></div>
        <div style="text-align:center"><div class="score-circle {perf_class}">{perf_score}</div><div style="margin-top:8px;font-size:13px;color:#6b7280">性能</div></div>
    </div>
    {f'<h3 style="font-size:14px;margin-bottom:8px">主要问题</h3><ul class="summary-list">{issues_html}</ul>' if issues_html else ''}
</div>'''

    def _pages_section(self, d):
        pages = d.get('pages', [])
        if not pages:
            return ''
        rows = ''
        for p in pages[:100]:
            url = html_module.escape(str(p.get('url', ''))[:100])
            title = html_module.escape(str(p.get('title', ''))[:60])
            status = p.get('status_code', '')
            rows += f'<tr><td>{status}</td><td>{url}</td><td>{title}</td></tr>\n'

        return f'''
<div class="section">
    <h2>爬取页面 ({len(pages)})</h2>
    <table>
        <thead><tr><th>状态</th><th>URL</th><th>标题</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
</div>'''

    def _footer_section(self, d):
        return f'<div class="footer">灵探 安全扫描报告 | {d["now"]} | 本报告仅供授权安全测试使用</div>'
