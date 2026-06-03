// ===== 灵探 Frontend Application =====

const API_BASE = '';
let pollTimer = null;

// ===== Tab Navigation =====
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
        if (item && item.dataset && item.dataset.tab) {
            // Expand parent group if collapsed
            const group = item.closest('.nav-group');
            if (group && group.classList.contains('collapsed')) {
                group.classList.remove('collapsed');
                const header = document.querySelector(`.nav-group-header[data-group="${group.dataset.group}"]`);
                if (header) header.classList.remove('collapsed');
            }
            switchTab(item.dataset.tab);
        }
    });
});

// Group collapse/expand
document.querySelectorAll('.nav-group-header').forEach(header => {
    header.addEventListener('click', () => {
        const groupName = header.dataset.group;
        const group = document.querySelector(`.nav-group[data-group="${groupName}"]`);
        if (group) {
            group.classList.toggle('collapsed');
            header.classList.toggle('collapsed');
        }
    });
});

function switchTab(tabId) {
    if (!tabId) return;
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    const navItem = document.querySelector(`.nav-item[data-tab="${tabId}"]`);
    if (navItem) navItem.classList.add('active');
    const tab = document.getElementById(`tab-${tabId}`);
    if (tab) tab.classList.add('active');
    if (tabId === 'dashboard') loadDashboard();
    if (tabId === 'endpoints') loadEndpoints();
    if (tabId === 'requester') { updateCurlPreview(); loadHistory(); loadFavorites(); }
    if (tabId === 'sitemap') loadSitemap();
    if (tabId === 'dep-graph') loadDepGraph();
    if (tabId === 'assets') loadAssets();
    if (tabId === 'proxy') loadProxyTraffic();
    if (tabId === 'tasks') loadTasks();
    if (tabId === 'plugins') loadPlugins();
    if (tabId === 'sessions') loadSessions();
}

// ===== Toast Notifications =====
function showToast(message, type = 'info') {
    try {
        const container = document.getElementById('toast-container');
        if (!container) return;
        const toast = document.createElement('div');
        toast.className = `toast ${type || 'info'}`;
        toast.textContent = String(message || '');
        container.appendChild(toast);
        setTimeout(() => {
            try {
                toast.style.opacity = '0';
                toast.style.transform = 'translateX(40px)';
                toast.style.transition = 'all 0.3s ease';
                setTimeout(() => { try { toast.remove(); } catch(e){} }, 300);
            } catch(e) {}
        }, 3500);
    } catch(e) {}
}

// ===== API Helpers =====
async function apiCall(url, options = {}) {
    try {
        const resp = await fetch(API_BASE + url, {
            headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
            ...options,
        });
        let data;
        try { data = await resp.json(); } catch { data = { error: '响应解析失败' }; }
        if (!resp.ok) {
            throw new Error(data.error || `HTTP ${resp.status}`);
        }
        return data;
    } catch (e) {
        throw e;
    }
}

// ===== Dashboard =====
async function loadDashboard() {
    try {
        const [stats, endpointsData] = await Promise.all([
            apiCall('/api/stats'),
            apiCall('/api/endpoints?limit=10'),
        ]);

        safeSetText('stat-endpoints', stats.total_endpoints || 0);
        safeSetText('stat-targets', stats.total_targets || 0);
        safeSetText('stat-categories', Object.keys(stats.by_category || {}).length);

        const highRisk = stats.by_risk || {};
        safeSetText('stat-highrisk', (highRisk.critical || 0) + (highRisk.high || 0));

        renderBarChart('category-chart', stats.by_category || {}, 'blue');
        renderBarChart('method-chart', stats.by_method || {}, 'green');
        renderBarChart('risk-chart', stats.by_risk || {}, 'purple');

        renderRecentTable(endpointsData.endpoints || []);
        populateCategoryFilter(stats.by_category || {});
    } catch (e) {
        console.error('Dashboard error:', e);
    }
}

function safeSetText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

function renderBarChart(containerId, data, colorClass) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const entries = Object.entries(data || {}).sort((a, b) => b[1] - a[1]);
    const maxVal = Math.max(...entries.map(e => e[1] || 0), 1);
    const colors = ['blue', 'green', 'purple', 'orange', 'red', 'cyan', 'pink'];

    if (entries.length === 0) {
        container.innerHTML = '<p style="color:var(--text-muted);font-size:13px;text-align:center;padding:40px 0;">暂无数据</p>';
        return;
    }

    container.innerHTML = entries.slice(0, 8).map(([label, count], i) => {
        const pct = Math.max(((count || 0) / maxVal) * 100, 8);
        const color = colors[i % colors.length];
        const safeLabel = escapeHtml(String(label || ''));
        return `<div class="bar-chart-item">
            <span class="bar-label" title="${safeLabel}">${safeLabel}</span>
            <div class="bar-track"><div class="bar-fill ${color}" style="width:${pct}%">${count || 0}</div></div>
            <span class="bar-count">${count || 0}</span>
        </div>`;
    }).join('');
}

function renderRecentTable(endpoints) {
    const tbody = document.getElementById('recent-tbody');
    if (!tbody) return;
    if (!endpoints || !endpoints.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:30px;">暂无数据，请先进行扫描</td></tr>';
        return;
    }
    tbody.innerHTML = endpoints.map(ep => {
        const method = (ep.method || 'GET').toLowerCase();
        const risk = ep.risk_level || 'info';
        return `<tr onclick="showDetail(${ep.id || 0})" style="cursor:pointer">
            <td><span class="badge badge-${method}">${escapeHtml(ep.method || 'GET')}</span></td>
            <td title="${escapeHtml(ep.url || '')}">${truncate(ep.url || '', 60)}</td>
            <td>${escapeHtml(ep.category || '-')}</td>
            <td><span class="risk-badge risk-${risk}">${riskLabel(risk)}</span></td>
            <td><span class="source-badge">${escapeHtml(ep.source || '-')}</span></td>
            <td>${formatTime(ep.discovered_at)}</td>
        </tr>`;
    }).join('');
}

function populateCategoryFilter(categories) {
    const select = document.getElementById('filter-category');
    if (!select) return;
    const current = select.value;
    select.innerHTML = '<option value="">所有分类</option>';
    Object.entries(categories || {}).sort((a, b) => b[1] - a[1]).forEach(([cat, count]) => {
        select.innerHTML += `<option value="${escapeHtml(cat)}">${escapeHtml(cat)} (${count})</option>`;
    });
    select.value = current;
}

// ===== Web Scan =====
async function startWebScan() {
    const urlEl = document.getElementById('scan-url');
    const url = urlEl ? urlEl.value.trim() : '';
    if (!url) { showToast('请输入目标网站URL', 'error'); return; }

    const deepEl = document.getElementById('deep-scan');
    const deepScan = deepEl ? deepEl.checked : true;
    const btn = document.getElementById('btn-scan');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 扫描中...'; }

    try {
        await apiCall('/api/scan/web', {
            method: 'POST',
            body: JSON.stringify({ url, deep_scan: deepScan }),
        });
        const progCard = document.getElementById('scan-progress-card');
        const resCard = document.getElementById('scan-results-card');
        if (progCard) progCard.style.display = 'block';
        if (resCard) resCard.style.display = 'none';
        startPolling();
    } catch (e) {
        showToast(e.message || '扫描启动失败', 'error');
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg> 开始扫描';
        }
    }
}

function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(async () => {
        try {
            const status = await apiCall('/api/scan/progress');
            const fill = document.getElementById('progress-fill');
            const msg = document.getElementById('progress-message');
            const statusText = document.getElementById('scan-status-text');
            if (fill) fill.style.width = (status.progress || 0) + '%';
            if (msg) msg.textContent = status.message || '';
            if (statusText) statusText.textContent = status.active ? `扫描中 - ${status.target || ''}` : '扫描完成';

            if (status.error) {
                showToast('扫描出错: ' + status.error, 'error');
            }

            if (!status.active) {
                clearInterval(pollTimer);
                pollTimer = null;
                const btn = document.getElementById('btn-scan');
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg> 开始扫描';
                }
                loadScanResults();
            }
        } catch (e) {
            console.error('Poll error:', e);
        }
    }, 1200);
}

function stopScan() {
    apiCall('/api/scan/stop', { method: 'POST' })
        .then(() => showToast('扫描已停止', 'info'))
        .catch(e => showToast(e.message || '停止失败', 'error'));
}

async function loadScanResults() {
    try {
        const data = await apiCall('/api/endpoints?limit=200');
        const results = data.endpoints || [];
        if (results.length > 0) {
            const resCard = document.getElementById('scan-results-card');
            if (resCard) resCard.style.display = 'block';
            safeSetText('scan-result-count', `${results.length} 个接口`);
            const tbody = document.getElementById('scan-results-tbody');
            if (tbody) {
                tbody.innerHTML = results.map(ep => {
                    const method = (ep.method || 'GET').toLowerCase();
                    const risk = ep.risk_level || 'info';
                    return `<tr onclick="showDetail(${ep.id || 0})" style="cursor:pointer">
                        <td><span class="badge badge-${method}">${escapeHtml(ep.method || 'GET')}</span></td>
                        <td title="${escapeHtml(ep.url || '')}">${truncate(ep.url || '', 55)}</td>
                        <td>${ep.status_code || '-'}</td>
                        <td>${escapeHtml(ep.category || '-')}</td>
                        <td>${truncate(ep.description || '-', 30)}</td>
                        <td><span class="risk-badge risk-${risk}">${riskLabel(risk)}</span></td>
                    </tr>`;
                }).join('');
            }
        }
    } catch (e) { console.error('Load results error:', e); }
}

// ===== URL Analysis =====
async function analyzeUrl() {
    const urlEl = document.getElementById('analyze-url');
    const url = urlEl ? urlEl.value.trim() : '';
    const methodEl = document.getElementById('analyze-method');
    const method = methodEl ? methodEl.value : 'GET';
    if (!url) { showToast('请输入URL', 'error'); return; }

    const card = document.getElementById('analyze-result-card');
    if (card) { card.style.display = 'block'; card.querySelector('h3').innerHTML = '<span class="spinner"></span> 分析中...'; }

    try {
        const bodyEl = document.getElementById('analyze-body');
        const body = bodyEl ? bodyEl.value : '';
        const result = await apiCall('/api/scan/analyze-url', {
            method: 'POST',
            body: JSON.stringify({ url, method, body: body || undefined }),
        });
        if (card) card.querySelector('h3').textContent = '分析结果';
        const resultDiv = document.getElementById('analyze-result');
        if (resultDiv) resultDiv.innerHTML = renderDetail(result);
    } catch (e) {
        if (card) card.querySelector('h3').textContent = '分析失败';
        const resultDiv = document.getElementById('analyze-result');
        if (resultDiv) resultDiv.innerHTML = `<p style="color:var(--danger)">${escapeHtml(e.message || '未知错误')}</p>`;
    }
}

const methodSelect = document.getElementById('analyze-method');
if (methodSelect) {
    methodSelect.addEventListener('change', function() {
        const bodyRow = document.getElementById('analyze-body-row');
        if (bodyRow) {
            bodyRow.style.display = (this.value === 'POST' || this.value === 'PUT' || this.value === 'PATCH') ? 'flex' : 'none';
        }
    });
}

// ===== JS Analysis =====
async function analyzeJs() {
    const urlEl = document.getElementById('js-url');
    const url = urlEl ? urlEl.value.trim() : '';
    if (!url) { showToast('请输入JS文件URL', 'error'); return; }

    const card = document.getElementById('js-result-card');
    if (card) { card.style.display = 'block'; card.querySelector('h3').innerHTML = '<span class="spinner"></span> 分析中...'; }

    try {
        const result = await apiCall('/api/scan/js', {
            method: 'POST',
            body: JSON.stringify({ url }),
        });
        if (card) card.querySelector('h3').textContent = '分析结果';
        const resultDiv = document.getElementById('js-result');
        if (resultDiv) resultDiv.innerHTML = renderJsResult(result);
    } catch (e) {
        if (card) card.querySelector('h3').textContent = '分析失败';
        const resultDiv = document.getElementById('js-result');
        if (resultDiv) resultDiv.innerHTML = `<p style="color:var(--danger)">${escapeHtml(e.message || '未知错误')}</p>`;
    }
}

function renderJsResult(result) {
    if (!result) return '<p style="color:var(--text-muted)">无结果</p>';
    if (result.error) return `<p style="color:var(--danger)">${escapeHtml(result.error)}</p>`;

    let html = '<div class="detail-grid">';
    html += kv('源文件', result.source_url || '-');
    html += kv('代码行数', result.code_stats ? result.code_stats.total_lines : 0);
    html += kv('发现接口', (result.api_endpoints || []).length);
    html += kv('HTTP方法', (result.api_methods || []).join(', ') || '无');
    html += kv('GraphQL', result.graphql_found ? '是' : '否');
    html += kv('认证模式', (result.auth_patterns || []).join(', ') || '无');
    if (result.code_stats && result.code_stats.minified) html += kv('代码状态', '已压缩(minified)');
    html += '</div>';

    if (result.base_urls && result.base_urls.length) {
        html += '<div class="detail-section"><h4>基础URL</h4>';
        html += '<div class="pre-block">' + result.base_urls.map(u => escapeHtml(u)).join('\n') + '</div></div>';
    }

    const eps = result.api_endpoints || [];
    if (eps.length) {
        html += `<div class="detail-section"><h4>发现的API接口 (${eps.length})</h4>`;
        html += '<div class="pre-block">' + eps.slice(0, 50).map(ep =>
            `[${escapeHtml(ep.type || '')}] ${escapeHtml(ep.url || '')}`
        ).join('\n');
        if (eps.length > 50) html += `\n... 还有 ${eps.length - 50} 个`;
        html += '</div></div>';
    }

    return html;
}

// ===== File Upload =====
const uploadZone = document.getElementById('upload-zone');
const fileInput = document.getElementById('file-input');

if (uploadZone && fileInput) {
    uploadZone.addEventListener('click', () => fileInput.click());
    uploadZone.addEventListener('dragover', e => { e.preventDefault(); uploadZone.classList.add('dragover'); });
    uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragover'));
    uploadZone.addEventListener('drop', e => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        if (e.dataTransfer && e.dataTransfer.files.length) handleFileUpload(e.dataTransfer.files);
    });
    fileInput.addEventListener('change', () => { if (fileInput.files.length) handleFileUpload(fileInput.files); });
}

async function handleFileUpload(files) {
    if (!files || !files.length) return;
    const card = document.getElementById('upload-result-card');
    if (card) { card.style.display = 'block'; card.querySelector('h3').innerHTML = '<span class="spinner"></span> 分析中...'; }

    const fileTypeEl = document.getElementById('file-type');
    const fileType = fileTypeEl ? fileTypeEl.value : 'auto';

    try {
        if (files.length === 1) {
            const formData = new FormData();
            formData.append('file', files[0]);
            formData.append('type', fileType);
            const resp = await fetch(API_BASE + '/api/upload', { method: 'POST', body: formData });
            let result;
            try { result = await resp.json(); } catch { result = { error: '响应解析失败' }; }
            if (card) card.querySelector('h3').textContent = '分析结果';
            const resultDiv = document.getElementById('upload-result');
            if (resultDiv) resultDiv.innerHTML = renderUploadResult(result);
            showToast('文件分析完成', 'success');
        } else {
            const formData = new FormData();
            for (const f of files) formData.append('files', f);
            const resp = await fetch(API_BASE + '/api/upload/batch', { method: 'POST', body: formData });
            let result;
            try { result = await resp.json(); } catch { result = { error: '响应解析失败' }; }
            if (card) card.querySelector('h3').textContent = '批量分析结果';
            const resultDiv = document.getElementById('upload-result');
            if (resultDiv) resultDiv.innerHTML = renderBatchResult(result);
            showToast(`分析完成，共 ${result.total_files || 0} 个文件`, 'success');
        }
    } catch (e) {
        if (card) card.querySelector('h3').textContent = '分析失败';
        const resultDiv = document.getElementById('upload-result');
        if (resultDiv) resultDiv.innerHTML = `<p style="color:var(--danger)">${escapeHtml(e.message || '未知错误')}</p>`;
    }
}

function renderUploadResult(result) {
    if (!result) return '<p style="color:var(--text-muted)">无结果</p>';
    if (result.error) return `<p style="color:var(--danger)">${escapeHtml(result.error)}</p>`;

    let html = '<div class="detail-grid">';
    html += kv('文件', result.file || '-');
    if (result.app_info) {
        if (result.app_info.package) html += kv('包名', result.app_info.package);
        if (result.app_info.display_name) html += kv('应用名', result.app_info.display_name);
        if (result.app_info.bundle_id) html += kv('Bundle ID', result.app_info.bundle_id);
        if (result.app_info.version) html += kv('版本', result.app_info.version);
    }
    html += kv('发现接口', result.endpoint_count || (result.endpoints || []).length);
    html += kv('涉及域名', (result.domains || []).length);
    html += '</div>';

    if (result.domains && result.domains.length) {
        html += '<div class="detail-section"><h4>发现的域名</h4>';
        html += '<div class="pre-block">' + result.domains.slice(0, 30).map(d => escapeHtml(d)).join('\n') + '</div></div>';
    }

    const eps = result.endpoints || [];
    if (eps.length) {
        html += '<div class="detail-section"><h4>发现的API接口</h4>';
        html += '<table class="data-table"><thead><tr><th>方法</th><th>URL</th><th>来源</th></tr></thead><tbody>';
        eps.slice(0, 50).forEach(ep => {
            html += `<tr><td><span class="badge badge-${(ep.method || 'unknown').toLowerCase()}">${escapeHtml(ep.method || 'N/A')}</span></td>`;
            html += `<td title="${escapeHtml(ep.url || '')}">${truncate(ep.url || '', 70)}</td>`;
            html += `<td><span class="source-badge">${escapeHtml(ep.source || '-')}</span></td></tr>`;
        });
        html += '</tbody></table>';
        if (eps.length > 50) html += `<p style="color:var(--text-secondary);font-size:12px;margin-top:8px;">... 还有 ${eps.length - 50} 个接口未显示</p>`;
        html += '</div>';
    }

    if (result.security_notes && result.security_notes.length) {
        html += '<div class="detail-section"><h4>安全提示</h4>';
        result.security_notes.forEach(note => { html += `<p style="color:var(--warning);font-size:13px;">⚠ ${escapeHtml(note)}</p>`; });
        html += '</div>';
    }

    return html;
}

function renderBatchResult(result) {
    if (!result) return '<p>无结果</p>';
    let html = `<p style="margin-bottom:12px;">共分析 ${result.total_files || 0} 个文件</p>`;
    (result.results || []).forEach((r, i) => {
        html += `<div class="card" style="margin-bottom:8px;padding:12px;"><h4 style="font-size:14px;margin-bottom:8px;">${escapeHtml(r.file || `文件 ${i+1}`)}</h4>`;
        if (r.error) html += `<p style="color:var(--danger);font-size:13px;">${escapeHtml(r.error)}</p>`;
        else html += `<p style="font-size:13px;color:var(--text-secondary);">发现 ${r.endpoint_count || (r.endpoints||[]).length} 个接口，${(r.domains||[]).length} 个域名</p>`;
        html += '</div>';
    });
    return html;
}

// ===== Endpoints List =====
let favSet = new Set(); // 'METHOD:url' set for fast lookup
let favOnlyFilter = false;

async function loadFavSet() {
    try {
        const data = await apiCall('/api/favorites');
        favSet = new Set(data.favorite_set || []);
    } catch (e) { /* ignore */ }
}

function toggleFavFilter() {
    favOnlyFilter = !favOnlyFilter;
    const btn = document.getElementById('filter-fav-btn');
    if (btn) btn.textContent = favOnlyFilter ? '★' : '☆';
    if (btn) btn.style.color = favOnlyFilter ? 'var(--warning)' : '';
    loadEndpoints();
}

async function toggleFavorite(url, method, label) {
    try {
        const result = await apiCall('/api/favorites/toggle', {
            method: 'POST',
            body: JSON.stringify({ url, method, label }),
        });
        showToast(result.message, 'success');
        const key = `${method}:${url}`;
        if (result.favorited) favSet.add(key); else favSet.delete(key);
        loadEndpoints(); // refresh display
    } catch (e) { showToast(e.message, 'error'); }
}

async function loadEndpoints() {
    const searchEl = document.getElementById('search-input');
    const search = searchEl ? searchEl.value : '';
    const catEl = document.getElementById('filter-category');
    const category = catEl ? catEl.value : '';
    const methodEl = document.getElementById('filter-method');
    const method = methodEl ? methodEl.value : '';
    const riskEl = document.getElementById('filter-risk');
    const risk = riskEl ? riskEl.value : '';
    const sourceEl = document.getElementById('filter-source');
    const source = sourceEl ? sourceEl.value : '';

    let url = '/api/endpoints?limit=500';
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (category) url += `&category=${encodeURIComponent(category)}`;

    try {
        const data = await apiCall(url);
        let endpoints = data.endpoints || [];
        if (method) endpoints = endpoints.filter(e => e.method === method);
        if (risk) endpoints = endpoints.filter(e => e.risk_level === risk);
        if (source) endpoints = endpoints.filter(e => e.source === source);
        if (favOnlyFilter) endpoints = endpoints.filter(e => favSet.has(`${e.method || 'GET'}:${e.url}`));

        safeSetText('endpoint-count', `共 ${endpoints.length} 个接口`);

        const tbody = document.getElementById('endpoints-tbody');
        if (!tbody) return;
        if (!endpoints.length) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-muted);padding:30px;">暂无接口数据</td></tr>';
            return;
        }
        tbody.innerHTML = endpoints.map(ep => {
            const method_l = (ep.method || 'GET').toLowerCase();
            const risk_l = ep.risk_level || 'info';
            const favKey = `${ep.method || 'GET'}:${ep.url}`;
            const isFav = favSet.has(favKey);
            const favBtn = `<button class="btn-link" onclick="toggleFavorite('${escHtml(ep.url || '')}','${escHtml(ep.method || 'GET')}','')" title="收藏" style="color:${isFav ? 'var(--warning)' : 'var(--text-muted)'}">${isFav ? '★' : '☆'}</button>`;
            return `<tr>
                <td><span class="badge badge-${method_l}">${escapeHtml(ep.method || 'GET')}</span></td>
                <td title="${escapeHtml(ep.url || '')}">${truncate(ep.url || '', 45)}</td>
                <td>${ep.status_code || '-'}</td>
                <td>${escapeHtml(ep.category || '-')}</td>
                <td>${truncate(ep.description || '-', 20)}</td>
                <td><span class="risk-badge risk-${risk_l}">${riskLabel(risk_l)}</span></td>
                <td><span class="source-badge">${escapeHtml(ep.source || '-')}</span></td>
                <td>${favBtn} <button class="btn-link" onclick="showDetail(${ep.id || 0})">详情</button></td>
            </tr>`;
        }).join('');
    } catch (e) {
        showToast('加载接口列表失败: ' + (e.message || ''), 'error');
    }
}

const searchInput = document.getElementById('search-input');
if (searchInput) searchInput.addEventListener('keypress', e => { if (e.key === 'Enter') loadEndpoints(); });
const filterSource = document.getElementById('filter-source');
if (filterSource) filterSource.addEventListener('change', loadEndpoints);

['filter-category', 'filter-method', 'filter-risk'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', loadEndpoints);
});

// ===== Detail Modal =====
async function showDetail(endpointId) {
    if (!endpointId) return;
    try {
        const data = await apiCall(`/api/endpoint/${endpointId}`);
        if (data.error) { showToast('未找到接口详情', 'error'); return; }
        const body = document.getElementById('modal-body');
        if (body) body.innerHTML = renderDetailModal(data);
        const modal = document.getElementById('detail-modal');
        if (modal) modal.classList.add('active');
    } catch (e) {
        // Fallback: try from loaded endpoints
        try {
            const allData = await apiCall('/api/endpoints?limit=5000');
            const ep = (allData.endpoints || []).find(e => e.id === endpointId);
            if (ep) {
                const body = document.getElementById('modal-body');
                if (body) body.innerHTML = renderDetailModal(ep);
                const modal = document.getElementById('detail-modal');
                if (modal) modal.classList.add('active');
            } else { showToast('未找到接口详情', 'error'); }
        } catch (e2) { showToast('加载详情失败', 'error'); }
    }
}

function renderDetailModal(ep) {
    if (!ep) return '<p>无数据</p>';
    let html = '<div class="detail-grid">';
    html += kv('URL', ep.url || '');
    html += `<span class="detail-label">方法</span><span class="detail-value"><span class="badge badge-${(ep.method||'get').toLowerCase()}">${escapeHtml(ep.method||'GET')}</span></span>`;
    html += kv('状态码', ep.status_code || '-');
    html += kv('分类', ep.category || '-');
    html += kv('描述', ep.description || '-');
    html += `<span class="detail-label">风险等级</span><span class="detail-value"><span class="risk-badge risk-${ep.risk_level||'info'}">${riskLabel(ep.risk_level)}</span></span>`;
    html += kv('来源', ep.source || '-');
    html += kv('Content-Type', ep.content_type || '-');
    html += kv('响应大小', ep.response_size ? formatBytes(ep.response_size) : '-');
    html += kv('发现时间', formatTime(ep.discovered_at));
    html += '</div>';

    // Parameters
    if (ep.parameters) {
        let params;
        try { params = typeof ep.parameters === 'string' ? JSON.parse(ep.parameters) : ep.parameters; } catch { params = null; }
        if (params && Array.isArray(params) && params.length) {
            html += '<div class="detail-section"><h4>参数</h4><div class="pre-block">' + syntaxHighlight(JSON.stringify(params, null, 2)) + '</div></div>';
        }
    }

    if (ep.request_body) {
        html += '<div class="detail-section"><h4>请求体</h4><div class="pre-block">';
        try { html += syntaxHighlight(JSON.stringify(JSON.parse(ep.request_body), null, 2)); }
        catch { html += escapeHtml(ep.request_body); }
        html += '</div></div>';
    }

    if (ep.response_sample) {
        html += '<div class="detail-section"><h4>响应示例</h4><div class="pre-block" style="max-height:300px;">';
        try { html += syntaxHighlight(JSON.stringify(JSON.parse(ep.response_sample), null, 2)); }
        catch { html += escapeHtml(ep.response_sample); }
        html += '</div></div>';
    }

    if (ep.headers) {
        let headers;
        try { headers = typeof ep.headers === 'string' ? JSON.parse(ep.headers) : ep.headers; } catch { headers = null; }
        if (headers && typeof headers === 'object' && Object.keys(headers).length) {
            html += '<div class="detail-section"><h4>请求头</h4><div class="pre-block">';
            html += Object.entries(headers).map(([k, v]) => `${escapeHtml(String(k))}: ${escapeHtml(String(v))}`).join('\n');
            html += '</div></div>';
        }
    }

    return html;
}

function closeModal() {
    const modal = document.getElementById('detail-modal');
    if (modal) modal.classList.remove('active');
}
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

// ===== Export =====
function exportData(format) {
    window.open(API_BASE + `/api/export/${format}`, '_blank');
}

// ===== Clear Data =====
async function clearAllData() {
    if (!confirm('确定要清除所有数据吗？此操作不可恢复。')) return;
    try {
        await apiCall('/api/clear', { method: 'POST' });
        showToast('数据已清除', 'success');
        // Refresh current tab data
        const activeTab = document.querySelector('.tab-content.active');
        const tabId = activeTab ? activeTab.id.replace('tab-', '') : '';
        loadDashboard();
        if (tabId === 'endpoints') loadEndpoints();
        else if (tabId === 'sitemap') loadSitemap();
        else if (tabId === 'assets') loadAssets();
        else if (tabId === 'tasks') loadTasks();
        else if (tabId === 'sessions') loadSessions();
    } catch (e) { showToast(e.message || '清除失败', 'error'); }
}

// ===== Utility Functions =====
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

function truncate(text, len) {
    if (!text) return '';
    text = String(text);
    return text.length > len ? text.slice(0, len) + '...' : text;
}

function riskLabel(level) {
    const labels = { critical: '严重', high: '高风险', medium: '中风险', low: '低风险', info: '信息' };
    return labels[level] || level || '信息';
}

function formatTime(ts) {
    if (!ts) return '-';
    try {
        const d = new Date(ts * 1000);
        return `${d.getMonth()+1}/${d.getDate()} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
    } catch { return '-'; }
}

function formatBytes(bytes) {
    if (!bytes || bytes < 0) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
    return (bytes/(1024*1024)).toFixed(1) + ' MB';
}

function kv(label, value) {
    return `<span class="detail-label">${escapeHtml(label)}</span><span class="detail-value">${escapeHtml(String(value))}</span>`;
}

function syntaxHighlight(json) {
    if (!json) return '';
    try {
        return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, match => {
            let cls = 'json-number';
            if (/^"/.test(match)) { cls = /:$/.test(match) ? 'json-key' : 'json-string'; }
            else if (/true|false/.test(match)) cls = 'json-boolean';
            else if (/null/.test(match)) cls = 'json-null';
            return `<span class="${cls}">${match}</span>`;
        });
    } catch { return escapeHtml(json); }
}

function renderDetail(result) {
    if (!result) return '<p style="color:var(--text-muted)">无结果</p>';
    let html = '<div class="detail-grid">';
    html += kv('URL', result.url || '');
    html += kv('方法', result.method || 'GET');
    html += kv('状态码', result.status_code || '-');
    html += kv('Content-Type', result.content_type || '-');
    html += kv('响应大小', result.response_size ? formatBytes(result.response_size) : '-');
    html += kv('响应时间', result.response_time ? result.response_time.toFixed(3)+'s' : '-');
    html += kv('分类', result.category || '-');
    html += kv('描述', result.description || '-');
    html += `<span class="detail-label">风险</span><span class="detail-value"><span class="risk-badge risk-${result.risk_level||'info'}">${riskLabel(result.risk_level)}</span></span>`;
    html += '</div>';

    if (result.response_sample) {
        html += '<div class="detail-section"><h4>响应示例</h4><div class="pre-block" style="max-height:300px;">';
        try { html += syntaxHighlight(JSON.stringify(JSON.parse(result.response_sample), null, 2)); }
        catch { html += escapeHtml(result.response_sample); }
        html += '</div></div>';
    }

    if (result.json_structure) {
        html += '<div class="detail-section"><h4>JSON结构</h4><div class="pre-block">' + syntaxHighlight(JSON.stringify(result.json_structure, null, 2)) + '</div></div>';
    }

    if (result.sensitive_data && result.sensitive_data.length) {
        html += '<div class="detail-section"><h4 style="color:var(--warning);">敏感数据检测</h4>';
        result.sensitive_data.forEach(sd => { html += `<p style="font-size:13px;color:var(--warning);">⚠ ${escapeHtml(sd.type)}: 检测到 ${sd.count} 处</p>`; });
        html += '</div>';
    }

    if (result.security_issues && result.security_issues.length) {
        html += '<div class="detail-section"><h4 style="color:var(--danger);">安全风险</h4>';
        result.security_issues.forEach(issue => { html += `<p style="font-size:13px;color:var(--danger);">🔴 ${escapeHtml(issue.description)}</p>`; });
        html += '</div>';
    }

    return html;
}

// ===== Security Scan =====
let securityPollTimer = null;

async function startSecurityScan() {
    const urlEl = document.getElementById('security-url');
    const url = urlEl ? urlEl.value.trim() : '';
    if (!url) { showToast('请输入目标URL', 'error'); return; }

    const useEndpointsEl = document.getElementById('security-use-endpoints');
    const useEndpoints = useEndpointsEl ? useEndpointsEl.checked : true;

    const btn = document.getElementById('btn-security-scan');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 扫描中...'; }

    try {
        await apiCall('/api/security/scan', {
            method: 'POST',
            body: JSON.stringify({ url, use_endpoints: useEndpoints }),
        });
        const progCard = document.getElementById('security-progress-card');
        const resDiv = document.getElementById('security-results');
        if (progCard) progCard.style.display = 'block';
        if (resDiv) resDiv.style.display = 'none';
        startSecurityPolling();
    } catch (e) {
        showToast(e.message || '安全扫描启动失败', 'error');
        if (btn) { btn.disabled = false; btn.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> 开始安全扫描'; }
    }
}

function startSecurityPolling() {
    if (securityPollTimer) clearInterval(securityPollTimer);
    securityPollTimer = setInterval(async () => {
        try {
            const status = await apiCall('/api/security/progress');
            const fill = document.getElementById('security-progress-fill');
            const msg = document.getElementById('security-progress-message');
            const statusText = document.getElementById('security-status-text');
            if (fill) fill.style.width = (status.progress || 0) + '%';
            if (msg) msg.textContent = status.message || '';
            if (statusText) statusText.textContent = status.active ? '安全扫描中...' : '扫描完成';

            if (!status.active) {
                clearInterval(securityPollTimer);
                securityPollTimer = null;
                const btn = document.getElementById('btn-security-scan');
                if (btn) { btn.disabled = false; btn.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> 开始安全扫描'; }
                loadSecurityResults();
            }
        } catch (e) { console.error('Security poll error:', e); }
    }, 1500);
}

function stopSecurityScan() {
    apiCall('/api/security/stop', { method: 'POST' })
        .then(() => showToast('安全扫描已停止', 'info'))
        .catch(e => showToast(e.message || '停止失败', 'error'));
}

async function loadSecurityResults() {
    try {
        const resDiv = document.getElementById('security-results');
        if (resDiv) resDiv.style.display = 'block';

        // Get scan results from fuzzer
        let scanResults = null;
        try {
            const progress = await apiCall('/api/security/progress');
            scanResults = progress.results;
        } catch (e) {}

        // WAF info
        const wafInfo = scanResults && scanResults.waf_info;
        if (wafInfo) {
            const wafCard = document.getElementById('security-waf-card');
            const wafBadge = document.getElementById('security-waf-badge');
            const wafContent = document.getElementById('security-waf-content');
            if (wafCard) wafCard.style.display = 'block';
            if (wafInfo.detected) {
                if (wafBadge) { wafBadge.textContent = '已检测到 WAF'; wafBadge.className = 'badge badge-danger'; }
                let html = `<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:8px;">
                    <span><strong>WAF:</strong> ${escHtml(wafInfo.waf_name)}</span>
                    <span><strong>厂商:</strong> ${escHtml(wafInfo.vendor)}</span>
                    <span><strong>置信度:</strong> ${wafInfo.confidence}%</span>
                </div>`;
                if (wafInfo.evidence && wafInfo.evidence.length) {
                    html += '<div style="font-size:13px;margin-bottom:4px;"><strong>证据:</strong> ' + wafInfo.evidence.map(e => escHtml(e)).join(' | ') + '</div>';
                }
                if (wafInfo.bypass_suggestions && wafInfo.bypass_suggestions.length) {
                    html += '<div style="font-size:13px;color:var(--accent);"><strong>绕过建议:</strong> ' + wafInfo.bypass_suggestions.join(' | ') + '</div>';
                }
                if (wafContent) wafContent.innerHTML = html;
            } else {
                if (wafBadge) { wafBadge.textContent = '未检测到 WAF'; wafBadge.className = 'badge badge-success'; }
                if (wafContent) wafContent.innerHTML = '<span style="font-size:13px;color:var(--text-muted);">目标未部署 WAF 或 WAF 未响应探测请求</span>';
            }
        }

        // Get vulnerabilities from scan results
        let vulns = (scanResults && scanResults.vulnerabilities) || [];
        let sensitiveFiles = (scanResults && scanResults.sensitive_files) || [];
        let infoDisclosure = (scanResults && scanResults.info_disclosure) || [];

        // Also collect from endpoints
        try {
            const epData = await apiCall('/api/endpoints?limit=1000');
            (epData.endpoints || []).forEach(ep => {
                if (ep.security_issues && ep.security_issues.length) {
                    ep.security_issues.forEach(issue => {
                        vulns.push({
                            severity: issue.risk_level || 'high',
                            title: issue.description || issue.type,
                            type: issue.type,
                            url: ep.url,
                            evidence: issue.evidence || '',
                        });
                    });
                }
            });
        } catch (e) {}

        // Sort by severity
        const sevOrder = {critical: 0, high: 1, medium: 2, low: 3, info: 4};
        vulns.sort((a, b) => (sevOrder[a.severity] || 5) - (sevOrder[b.severity] || 5));

        // Summary grid
        const summaryGrid = document.getElementById('security-summary-grid');
        if (summaryGrid) {
            const summary = {critical: 0, high: 0, medium: 0, low: 0, info: 0};
            [...vulns, ...sensitiveFiles, ...infoDisclosure].forEach(v => {
                summary[v.severity] = (summary[v.severity] || 0) + 1;
            });
            summaryGrid.innerHTML = `
                <div class="stat-card"><div class="stat-icon red"><span style="font-size:20px;">&#9888;</span></div><div class="stat-info"><span class="stat-value">${summary.critical}</span><span class="stat-label">严重</span></div></div>
                <div class="stat-card"><div class="stat-icon orange"><span style="font-size:20px;">&#9888;</span></div><div class="stat-info"><span class="stat-value">${summary.high}</span><span class="stat-label">高风险</span></div></div>
                <div class="stat-card"><div class="stat-icon yellow"><span style="font-size:20px;">&#9888;</span></div><div class="stat-info"><span class="stat-value">${summary.medium}</span><span class="stat-label">中风险</span></div></div>
                <div class="stat-card"><div class="stat-icon green"><span style="font-size:20px;">&#9888;</span></div><div class="stat-info"><span class="stat-value">${summary.low}</span><span class="stat-label">低风险</span></div></div>`;
        }

        // Vulnerability table with CVSS and remediation
        const tbody = document.getElementById('security-vuln-tbody');
        if (tbody) {
            if (vulns.length) {
                tbody.innerHTML = vulns.map(v => {
                    const sev = v.severity || 'info';
                    const title = escHtml(v.title || v.description || v.type || '-');
                    const url = escHtml(v.url || '');
                    const cvss = v.cvss || '-';
                    let evidence = '';
                    if (v.payload) evidence = 'Payload: ' + escHtml(String(v.payload));
                    if (v.response_snippet) evidence += (v.payload ? '\n' : '') + escHtml(String(v.response_snippet));
                    if (!evidence) evidence = escHtml(String(v.evidence || '-'));
                    const remediation = escHtml(v.remediation || '');
                    return `<tr>
                        <td><span class="risk-badge risk-${sev}">${riskLabel(sev)}</span></td>
                        <td style="font-weight:700">${cvss}</td>
                        <td><strong>${title}</strong><br><span style="font-size:11px;color:var(--text-muted)">${escHtml(v.type || '')}</span></td>
                        <td title="${url}" style="max-width:200px;word-break:break-all;font-size:12px">${truncate(url, 40)}</td>
                        <td style="font-size:11px;max-width:180px;white-space:pre-wrap;word-break:break-all">${evidence}</td>
                        <td style="font-size:12px;color:var(--success)">${remediation || '-'}</td>
                    </tr>`;
                }).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:20px;">未发现漏洞</td></tr>';
            }
            safeSetText('security-vuln-count', `${vulns.length} 个漏洞`);
        }

        // Sensitive files
        if (sensitiveFiles.length) {
            const sfCard = document.getElementById('security-sensitive-card');
            const sfTbody = document.getElementById('security-sensitive-tbody');
            const sfCount = document.getElementById('security-sensitive-count');
            if (sfCard) sfCard.style.display = 'block';
            if (sfCount) sfCount.textContent = sensitiveFiles.length;
            if (sfTbody) {
                sfTbody.innerHTML = sensitiveFiles.map(f => `<tr>
                    <td title="${escHtml(f.url || '')}">${truncate(f.url || '', 50)}</td>
                    <td>${f.status || '-'}</td>
                    <td>${f.size ? (f.size < 1024 ? f.size + 'B' : (f.size/1024).toFixed(1) + 'KB') : '-'}</td>
                    <td><span class="risk-badge risk-${f.severity || 'high'}">${riskLabel(f.severity)}</span></td>
                </tr>`).join('');
            }
        }

        // Info disclosure
        if (infoDisclosure.length) {
            const idCard = document.getElementById('security-info-card');
            const idTbody = document.getElementById('security-info-tbody');
            if (idCard) idCard.style.display = 'block';
            if (idTbody) {
                idTbody.innerHTML = infoDisclosure.map(i => `<tr>
                    <td><span class="risk-badge risk-${i.severity || 'low'}">${riskLabel(i.severity)}</span></td>
                    <td>${escHtml(i.title || i.type || '')}</td>
                    <td>${escHtml(i.description || '')}</td>
                    <td title="${escHtml(i.url || '')}">${truncate(i.url || '', 40)}</td>
                </tr>`).join('');
            }
        }

        showToast('安全扫描完成', 'success');
    } catch (e) {
        showToast('加载安全结果失败: ' + (e.message || ''), 'error');
    }
}

// ===== Request Builder =====
function sendRequest() {
    const urlEl = document.getElementById('req-url');
    const url = urlEl ? urlEl.value.trim() : '';
    if (!url) { showToast('请输入请求URL', 'error'); return; }

    const methodEl = document.getElementById('req-method');
    const method = methodEl ? methodEl.value : 'GET';
    const headersEl = document.getElementById('req-headers');
    const headersStr = headersEl ? headersEl.value.trim() : '';
    const bodyEl = document.getElementById('req-body');
    const body = bodyEl ? bodyEl.value.trim() : '';

    let headers = {};
    if (headersStr) {
        try { headers = JSON.parse(headersStr); } catch { showToast('请求头格式错误，请使用JSON格式', 'error'); return; }
    }

    const reqCard = document.getElementById('req-response-card');
    if (reqCard) reqCard.style.display = 'block';
    const title = document.getElementById('req-response-title');
    if (title) title.innerHTML = '<span class="spinner"></span> 请求中...';

    apiCall('/api/tools/request', {
        method: 'POST',
        body: JSON.stringify({ url, method, headers, body: body || undefined }),
    }).then(data => {
        if (title) title.textContent = '响应';
        const meta = document.getElementById('req-response-meta');
        if (meta) {
            const statusColor = data.status_code < 300 ? 'var(--success)' : data.status_code < 400 ? 'var(--warning)' : 'var(--danger)';
            meta.innerHTML = `<span style="color:${statusColor};font-weight:600;">${data.status_code || '-'}</span> <span style="color:var(--text-muted);font-size:12px;">${data.response_time ? data.response_time.toFixed(3) + 's' : ''}</span> <span style="color:var(--text-muted);font-size:12px;">${formatBytes(data.response_size)}</span>`;
        }

        const respHeaders = document.getElementById('req-resp-headers');
        if (respHeaders && data.response_headers) {
            respHeaders.textContent = Object.entries(data.response_headers).map(([k, v]) => `${k}: ${v}`).join('\n');
        }

        const respBody = document.getElementById('req-resp-body');
        if (respBody) {
            const content = data.response_body || '';
            try {
                const parsed = JSON.parse(content);
                respBody.innerHTML = syntaxHighlight(JSON.stringify(parsed, null, 2));
            } catch {
                respBody.textContent = content.slice(0, 5000);
            }
        }
        showToast('请求完成', 'success');
    }).catch(e => {
        if (title) title.textContent = '请求失败';
        showToast(e.message || '请求失败', 'error');
    });
}

function getCurlCommand() {
    const urlEl = document.getElementById('req-url');
    const url = urlEl ? urlEl.value.trim() : '';
    const methodEl = document.getElementById('req-method');
    const method = methodEl ? methodEl.value : 'GET';
    const headersEl = document.getElementById('req-headers');
    const headersStr = headersEl ? headersEl.value.trim() : '';
    const bodyEl = document.getElementById('req-body');
    const body = bodyEl ? bodyEl.value.trim() : '';

    let parts = ['curl'];
    if (method && method !== 'GET') parts.push(`-X ${method}`);

    if (headersStr) {
        try {
            const headers = JSON.parse(headersStr);
            Object.entries(headers).forEach(([k, v]) => {
                parts.push(`-H '${k}: ${v}'`);
            });
        } catch {}
    }

    if (body) {
        parts.push(`-d '${body.replace(/'/g, "'\\''")}'`);
    }

    parts.push(`'${url}'`);
    return ' \\\n  '.join(parts);
}

function updateCurlPreview() {
    const preview = document.getElementById('curl-preview');
    if (preview) preview.textContent = getCurlCommand();
}

function copyCurl() {
    const cmd = getCurlCommand();
    navigator.clipboard.writeText(cmd).then(() => showToast('cURL命令已复制', 'success'))
        .catch(() => {
            const ta = document.createElement('textarea');
            ta.value = cmd;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            showToast('cURL命令已复制', 'success');
        });
}

// Auto-update cURL preview
['req-method', 'req-url', 'req-headers', 'req-body'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', updateCurlPreview);
});

// ===== OpenAPI Export =====
let openapiSpec = null;

async function exportOpenAPI() {
    const titleEl = document.getElementById('openapi-title');
    const versionEl = document.getElementById('openapi-version');
    const title = titleEl ? titleEl.value.trim() : '灵探 Auto-Generated Spec';
    const version = versionEl ? versionEl.value.trim() : '1.0.0';

    try {
        const data = await apiCall('/api/export/openapi', {
            method: 'POST',
            body: JSON.stringify({ title, version }),
        });
        openapiSpec = data;
        const resultDiv = document.getElementById('openapi-result');
        if (resultDiv) resultDiv.style.display = 'block';
        const preview = document.getElementById('openapi-preview');
        if (preview) preview.innerHTML = syntaxHighlight(JSON.stringify(data, null, 2));
        showToast('OpenAPI规范生成成功', 'success');
    } catch (e) {
        showToast(e.message || '生成失败', 'error');
    }
}

function downloadOpenAPI() {
    if (openapiSpec) {
        const blob = new Blob([JSON.stringify(openapiSpec, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'openapi-spec.json';
        a.click();
        URL.revokeObjectURL(url);
        showToast('文件已下载', 'success');
    } else {
        showToast('请先生成OpenAPI规范', 'error');
    }
}

// ===== Port Scanner =====
async function runPortScan() {
    const hostEl = document.getElementById('portscan-host');
    const host = hostEl ? hostEl.value.trim() : '127.0.0.1';
    const webOnlyEl = document.getElementById('portscan-web-only');
    const webOnly = webOnlyEl ? webOnlyEl.checked : false;

    try {
        const data = await apiCall('/api/tools/portscan', {
            method: 'POST',
            body: JSON.stringify({ host, web_only: webOnly }),
        });
        const resultDiv = document.getElementById('portscan-result');
        if (resultDiv) resultDiv.style.display = 'block';

        const summary = document.getElementById('portscan-summary');
        if (summary) {
            summary.innerHTML = kv('目标主机', data.host || host) +
                kv('扫描端口数', data.total_scanned || 0) +
                kv('开放端口', (data.open_ports || []).length) +
                kv('扫描耗时', (data.scan_time || 0) + 's');
        }

        const tbody = document.getElementById('portscan-tbody');
        if (tbody) {
            const ports = data.open_ports || [];
            if (ports.length) {
                tbody.innerHTML = ports.map(p => `<tr>
                    <td><strong>${p.port}</strong></td>
                    <td>${escapeHtml(p.service || '-')}</td>
                    <td style="font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(p.banner || '-')}</td>
                </tr>`).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--text-muted);padding:20px;">未发现开放端口</td></tr>';
            }
        }
        showToast(`端口扫描完成，发现 ${(data.open_ports || []).length} 个开放端口`, 'success');
    } catch (e) {
        showToast(e.message || '端口扫描失败', 'error');
    }
}

// ===== Diff Comparison =====
async function runDiff() {
    try {
        const data = await apiCall('/api/tools/diff', { method: 'POST', body: '{}' });
        const resultDiv = document.getElementById('diff-result');
        if (resultDiv) resultDiv.style.display = 'block';

        const summary = data.summary || {};
        const summaryDiv = document.getElementById('diff-summary');
        if (summaryDiv) {
            summaryDiv.innerHTML = `
                <div class="stat-card"><div class="stat-icon blue"><span class="stat-value">${summary.old_count || 0}</span></div><div class="stat-info"><span class="stat-label">上次扫描</span></div></div>
                <div class="stat-card"><div class="stat-icon green"><span class="stat-value">${summary.new_count || 0}</span></div><div class="stat-info"><span class="stat-label">本次扫描</span></div></div>
                <div class="stat-card"><div class="stat-icon green"><span class="stat-value" style="color:var(--success);">+${summary.added || 0}</span></div><div class="stat-info"><span class="stat-label">新增</span></div></div>
                <div class="stat-card"><div class="stat-icon red"><span class="stat-value" style="color:var(--danger);">-${summary.removed || 0}</span></div><div class="stat-info"><span class="stat-label">移除</span></div></div>
                <div class="stat-card"><div class="stat-icon orange"><span class="stat-value" style="color:var(--warning);">${summary.changed || 0}</span></div><div class="stat-info"><span class="stat-label">变更</span></div></div>`;
        }

        renderDiffTable('diff-added-card', 'diff-added-tbody', data.added || [], 'added');
        renderDiffTable('diff-removed-card', 'diff-removed-tbody', data.removed || [], 'removed');
        renderDiffChangedTable(data.changed || []);

        if (!(data.added || []).length && !(data.removed || []).length && !(data.changed || []).length) {
            showToast('两次扫描结果无差异', 'info');
        } else {
            showToast('对比分析完成', 'success');
        }
    } catch (e) {
        showToast(e.message || '对比分析失败', 'error');
    }
}

function renderDiffTable(cardId, tbodyId, items, type) {
    const card = document.getElementById(cardId);
    const tbody = document.getElementById(tbodyId);
    if (!card || !tbody) return;

    if (items.length) {
        card.style.display = 'block';
        tbody.innerHTML = items.map(ep => `<tr>
            <td><span class="badge badge-${(ep.method || 'GET').toLowerCase()}">${escapeHtml(ep.method || 'GET')}</span></td>
            <td>${escapeHtml(ep.url || '-')}</td>
        </tr>`).join('');
    } else {
        card.style.display = 'none';
    }
}

function renderDiffChangedTable(items) {
    const card = document.getElementById('diff-changed-card');
    const tbody = document.getElementById('diff-changed-tbody');
    if (!card || !tbody) return;

    if (items.length) {
        card.style.display = 'block';
        tbody.innerHTML = items.map(item => {
            const ep = item.endpoint || {};
            const changes = item.changes || {};
            const changeStr = Object.entries(changes).map(([k, v]) => `${k}: ${v.old} -> ${v.new}`).join(', ');
            return `<tr>
                <td><span class="badge badge-${(ep.method || 'GET').toLowerCase()}">${escapeHtml(ep.method || 'GET')}</span></td>
                <td>${escapeHtml(ep.url || '-')}</td>
                <td style="font-size:12px;color:var(--warning);">${escapeHtml(changeStr)}</td>
            </tr>`;
        }).join('');
    } else {
        card.style.display = 'none';
    }
}

// ===== Endpoint Grouping =====
async function runGroup() {
    try {
        const data = await apiCall('/api/tools/group', { method: 'POST', body: '{}' });
        const resultDiv = document.getElementById('group-result');
        if (resultDiv) resultDiv.style.display = 'block';

        const summary = document.getElementById('group-summary');
        if (summary) {
            summary.innerHTML = kv('总分组数', data.total_groups || 0);
        }

        const listDiv = document.getElementById('group-list');
        if (listDiv) {
            const groups = data.groups || [];
            if (groups.length) {
                listDiv.innerHTML = groups.map(g => {
                    const methods = (g.methods || []).map(m => `<span class="badge badge-${m.toLowerCase()}">${m}</span>`).join(' ');
                    const riskBadges = Object.entries(g.risk_levels || {}).map(([r, c]) =>
                        `<span class="risk-badge risk-${r}" style="margin-right:4px;">${riskLabel(r)}: ${c}</span>`
                    ).join('');
                    return `<div class="card" style="margin-bottom:8px;padding:12px;">
                        <div class="card-header" style="margin-bottom:4px;">
                            <h4 style="font-size:14px;margin:0;">${escapeHtml(g.name || '-')}</h4>
                            <span class="badge">${g.count || 0} 个接口</span>
                        </div>
                        <div style="margin-bottom:4px;">${methods}</div>
                        <div>${riskBadges || '<span style="color:var(--text-muted);font-size:12px;">无风险信息</span>'}</div>
                        <div style="margin-top:8px;max-height:120px;overflow:auto;">
                            ${(g.endpoints || []).slice(0, 10).map(ep => `<div style="font-size:12px;color:var(--text-secondary);padding:2px 0;"><span class="badge badge-${(ep.method || 'GET').toLowerCase()}" style="font-size:10px;margin-right:4px;">${escapeHtml(ep.method || 'GET')}</span>${truncate(ep.url || '', 70)}</div>`).join('')}
                            ${(g.endpoints || []).length > 10 ? `<div style="font-size:11px;color:var(--text-muted);">...还有 ${g.endpoints.length - 10} 个</div>` : ''}
                        </div>
                    </div>`;
                }).join('');
            } else {
                listDiv.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:20px;">暂无分组数据，请先进行扫描</p>';
            }
        }
        showToast('接口分组完成', 'success');
    } catch (e) {
        showToast(e.message || '接口分组失败', 'error');
    }
}

// ===== Batch Scan =====
async function runBatchScan() {
    const urlsEl = document.getElementById('batch-urls');
    const urlsText = urlsEl ? urlsEl.value.trim() : '';
    if (!urlsText) { showToast('请输入至少一个URL', 'error'); return; }

    const urls = urlsText.split('\n').map(u => u.trim()).filter(u => u);
    if (!urls.length) { showToast('请输入至少一个URL', 'error'); return; }

    const btn = document.getElementById('btn-batch-scan');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 扫描中...'; }

    const progDiv = document.getElementById('batch-progress');
    if (progDiv) progDiv.style.display = 'block';

    try {
        const data = await apiCall('/api/scan/batch', {
            method: 'POST',
            body: JSON.stringify({ urls }),
        });

        if (progDiv) progDiv.style.display = 'none';
        const resultDiv = document.getElementById('batch-result');
        if (resultDiv) resultDiv.style.display = 'block';

        const summary = document.getElementById('batch-summary');
        if (summary) {
            summary.innerHTML = kv('总URL数', data.total || urls.length) +
                kv('完成数', data.completed || 0);
        }

        const tbody = document.getElementById('batch-tbody');
        if (tbody) {
            const results = data.results || [];
            if (results.length) {
                tbody.innerHTML = results.map(r => {
                    if (r.error) {
                        return `<tr><td>${escapeHtml(r.url || '-')}</td><td style="color:var(--danger);">错误</td><td>-</td><td style="color:var(--danger);">${escapeHtml(r.error)}</td></tr>`;
                    }
                    const eps = r.endpoints || [];
                    const cats = [...new Set(eps.map(e => e.category).filter(Boolean))].join(', ');
                    const risk = eps.some(e => e.risk_level === 'critical') ? 'critical' :
                                 eps.some(e => e.risk_level === 'high') ? 'high' : 'info';
                    return `<tr>
                        <td title="${escapeHtml(r.url || '')}">${truncate(r.url || '', 50)}</td>
                        <td>${eps.length}</td>
                        <td style="font-size:12px;">${escapeHtml(cats || '-')}</td>
                        <td><span class="risk-badge risk-${risk}">${riskLabel(risk)}</span></td>
                    </tr>`;
                }).join('');
            }
        }
        showToast('批量扫描完成', 'success');
    } catch (e) {
        if (progDiv) progDiv.style.display = 'none';
        showToast(e.message || '批量扫描失败', 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = '开始批量扫描'; }
    }
}

// ===== Site Crawl =====
let siteCrawlPollTimer = null;
let siteCrawlData = { pages: [], technologies: [] };

async function startSiteCrawl() {
    const urlEl = document.getElementById('site-crawl-url');
    const url = urlEl ? urlEl.value.trim() : '';
    if (!url) { showToast('请输入目标网站URL', 'error'); return; }

    const maxPagesEl = document.getElementById('site-crawl-max-pages');
    const maxPages = maxPagesEl ? parseInt(maxPagesEl.value) || 100 : 100;

    const btn = document.getElementById('btn-site-crawl');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 爬取中...'; }

    try {
        await apiCall('/api/site/crawl', {
            method: 'POST',
            body: JSON.stringify({ url, max_pages: maxPages }),
        });
        const progCard = document.getElementById('site-crawl-progress-card');
        const resDiv = document.getElementById('site-crawl-results');
        if (progCard) progCard.style.display = 'block';
        if (resDiv) resDiv.style.display = 'none';
        startSiteCrawlPolling();
    } catch (e) {
        showToast(e.message || '全站爬取启动失败', 'error');
        if (btn) { btn.disabled = false; btn.textContent = '开始爬取'; }
    }
}

function startSiteCrawlPolling() {
    if (siteCrawlPollTimer) clearInterval(siteCrawlPollTimer);
    siteCrawlPollTimer = setInterval(async () => {
        try {
            const status = await apiCall('/api/site/progress');
            const fill = document.getElementById('site-crawl-progress-fill');
            const msg = document.getElementById('site-crawl-progress-message');
            const statusText = document.getElementById('site-crawl-status-text');
            if (fill) fill.style.width = (status.progress || 0) + '%';
            if (msg) msg.textContent = status.message || '';
            if (statusText) statusText.textContent = status.active ? `爬取中 - ${status.pages_found || 0} 页` : '爬取完成';

            if (!status.active) {
                clearInterval(siteCrawlPollTimer);
                siteCrawlPollTimer = null;
                const btn = document.getElementById('btn-site-crawl');
                if (btn) { btn.disabled = false; btn.textContent = '开始爬取'; }
                loadSiteCrawlResults();
            }
        } catch (e) { console.error('Site crawl poll error:', e); }
    }, 2000);
}

function stopSiteCrawl() {
    apiCall('/api/site/stop', { method: 'POST' })
        .then(() => showToast('爬取已停止', 'info'))
        .catch(e => showToast(e.message || '停止失败', 'error'));
}

async function loadSiteCrawlResults() {
    try {
        const [pagesData, techData] = await Promise.all([
            apiCall('/api/site/pages?limit=1000'),
            apiCall('/api/site/technologies'),
        ]);

        siteCrawlData.pages = pagesData.pages || [];
        siteCrawlData.technologies = techData.technologies || [];

        const resDiv = document.getElementById('site-crawl-results');
        if (resDiv) resDiv.style.display = 'block';

        // Overview
        const overview = document.getElementById('site-overview-grid');
        if (overview) {
            const pages = siteCrawlData.pages;
            const totalAssets = pages.reduce((sum, p) => sum + (p.assets ? (typeof p.assets === 'string' ? 0 : p.assets.length) : 0), 0);
            const avgRT = pages.length ? pages.reduce((s, p) => {
                const perf = p.performance || {};
                return s + (typeof perf === 'string' ? 0 : (perf.response_time || 0));
            }, 0) / pages.length : 0;
            overview.innerHTML = `
                <div class="stat-card"><div class="stat-icon blue"><span class="stat-value">${pages.length}</span></div><div class="stat-info"><span class="stat-label">页面数</span></div></div>
                <div class="stat-card"><div class="stat-icon green"><span class="stat-value">${totalAssets}</span></div><div class="stat-info"><span class="stat-label">资源数</span></div></div>
                <div class="stat-card"><div class="stat-icon purple"><span class="stat-value">${siteCrawlData.technologies.length}</span></div><div class="stat-info"><span class="stat-label">技术栈</span></div></div>
                <div class="stat-card"><div class="stat-icon orange"><span class="stat-value">${avgRT.toFixed(2)}s</span></div><div class="stat-info"><span class="stat-label">平均响应</span></div></div>`;
        }

        // Tech badges
        renderTechBadges(siteCrawlData.technologies);

        // Pages table
        renderSitePages(siteCrawlData.pages);

        showToast('全站爬取完成', 'success');
    } catch (e) {
        showToast('加载爬取结果失败', 'error');
    }
}

function renderTechBadges(techs) {
    const container = document.getElementById('site-tech-badges');
    const countEl = document.getElementById('site-tech-count');
    if (!container) return;

    if (countEl) countEl.textContent = `${techs.length} 项技术`;

    if (!techs.length) {
        container.innerHTML = '<p style="color:var(--text-muted);font-size:13px;">未检测到技术栈</p>';
        return;
    }

    const categories = {};
    techs.forEach(t => {
        const cat = t.category || 'Other';
        if (!categories[cat]) categories[cat] = [];
        categories[cat].push(t);
    });

    const catColors = { CMS: 'blue', Frontend: 'green', Library: 'purple', 'CSS Framework': 'cyan',
        Analytics: 'orange', CDN: 'pink', Server: 'red', Hosting: 'yellow',
        Framework: 'green', 'Build Tool': 'orange', Animation: 'purple',
        Visualization: 'cyan', 'UI Component': 'blue', Icon: 'pink' };

    let html = '';
    Object.entries(categories).sort((a, b) => b[1].length - a[1].length).forEach(([cat, items]) => {
        html += `<div style="margin-bottom:8px;"><span style="font-size:12px;color:var(--text-muted);margin-right:8px;">${escapeHtml(cat)}</span>`;
        items.forEach(t => {
            const conf = t.confidence || 0;
            const color = catColors[cat] || 'blue';
            html += `<span class="tech-badge tech-badge-${color}" title="${escapeHtml(t.evidence || '')}">${escapeHtml(t.name)} ${Math.round(conf * 100)}%</span>`;
        });
        html += '</div>';
    });
    container.innerHTML = html;
}

function renderSitePages(pages) {
    const tbody = document.getElementById('site-pages-tbody');
    if (!tbody) return;
    if (!pages.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:30px;">暂无页面数据</td></tr>';
        return;
    }
    tbody.innerHTML = pages.map(p => {
        const sc = p.status_code || 0;
        const scClass = sc < 300 ? 'green' : sc < 400 ? 'yellow' : 'red';
        const size = p.page_size ? formatBytes(p.page_size) : '-';
        const assetCount = Array.isArray(p.assets) ? p.assets.length : 0;
        return `<tr>
            <td><span class="badge badge-${scClass}">${sc}</span></td>
            <td title="${escapeHtml(p.url || '')}">${truncate(p.url || '', 55)}</td>
            <td>${truncate(p.title || '-', 30)}</td>
            <td>${size}</td>
            <td>${p.depth || 0}</td>
            <td>${assetCount}</td>
        </tr>`;
    }).join('');
}

const sitePageSearchEl = document.getElementById('site-page-search');
if (sitePageSearchEl) sitePageSearchEl.addEventListener('input', function() {
    const q = this.value.toLowerCase();
    const filtered = siteCrawlData.pages.filter(p =>
        (p.url || '').toLowerCase().includes(q) || (p.title || '').toLowerCase().includes(q)
    );
    renderSitePages(filtered);
});

// ===== Sitemap =====
let sitemapData = null;

async function loadSitemap() {
    try {
        const data = await apiCall('/api/site/sitemap');
        sitemapData = data;
        renderSitemapTree(data);
    } catch (e) {
        showToast(e.message || '加载站点地图失败', 'error');
    }
}

function renderSitemapTree(node) {
    const container = document.getElementById('sitemap-tree');
    if (!container) return;
    if (!node || !node.url) {
        container.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:40px;">请先进行全站爬取</p>';
        return;
    }
    container.innerHTML = '<ul class="sitemap-root">' + renderSitemapNode(node, 0) + '</ul>';
}

function renderSitemapNode(node, depth) {
    if (!node) return '';
    const title = node.title || node.url || '';
    const sc = node.status_code || '';
    const scClass = sc < 300 ? 'green' : sc < 400 ? 'yellow' : 'red';
    const hasChildren = node.children && node.children.length > 0;

    let html = '<li class="sitemap-node">';
    if (hasChildren) {
        html += `<details ${depth < 2 ? 'open' : ''}><summary>`;
    }
    html += `<span class="sitemap-label" title="${escapeHtml(node.url || '')}">`;
    if (sc) html += `<span class="badge badge-${scClass}" style="font-size:10px;margin-right:4px;">${sc}</span>`;
    html += escapeHtml(truncate(title, 50));
    if (hasChildren) html += ` <span style="color:var(--text-muted);font-size:11px;">(${node.children.length})</span>`;
    html += '</span>';
    if (hasChildren) {
        html += '</summary><ul class="sitemap-children">';
        node.children.forEach(child => { html += renderSitemapNode(child, depth + 1); });
        html += '</ul></details>';
    }
    html += '</li>';
    return html;
}

function expandAllSitemap() {
    document.querySelectorAll('#sitemap-tree details').forEach(d => d.open = true);
}

function collapseAllSitemap() {
    document.querySelectorAll('#sitemap-tree details').forEach(d => d.open = false);
}

// ===== Assets =====
let assetList = [];

async function loadAssets() {
    const typeEl = document.getElementById('asset-type-filter');
    const type = typeEl ? typeEl.value : '';
    try {
        let url = '/api/site/assets';
        if (type) url += `?type=${encodeURIComponent(type)}`;
        const data = await apiCall(url);
        assetList = data.assets || [];

        // Stats
        const stats = document.getElementById('asset-type-stats');
        if (stats) {
            const tc = data.type_counts || {};
            stats.innerHTML = Object.entries(tc).map(([t, c]) =>
                `<div class="stat-card"><div class="stat-icon blue"><span class="stat-value">${c}</span></div><div class="stat-info"><span class="stat-label">${t}</span></div></div>`
            ).join('') || '<p style="color:var(--text-muted);font-size:13px;">暂无数据</p>';
        }

        safeSetText('asset-count', `共 ${assetList.length} 个资源`);

        const tbody = document.getElementById('assets-tbody');
        if (tbody) {
            if (!assetList.length) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:30px;">暂无资源数据</td></tr>';
            } else {
                tbody.innerHTML = assetList.map((a, i) => `<tr>
                    <td><input type="checkbox" class="asset-cb" data-idx="${i}"></td>
                    <td><span class="badge badge-blue">${escapeHtml(a.type || '-')}</span></td>
                    <td title="${escapeHtml(a.url || '')}">${truncate(a.url || '', 70)}</td>
                    <td style="font-size:11px;" title="${escapeHtml(a.source_page || '')}">${truncate(a.source_page || '', 35)}</td>
                </tr>`).join('');
            }
        }
    } catch (e) {
        showToast('加载资源失败', 'error');
    }
}

function toggleAllAssets(checkbox) {
    document.querySelectorAll('.asset-cb').forEach(cb => { cb.checked = checkbox.checked; });
}

async function downloadSelectedAssets() {
    const checked = document.querySelectorAll('.asset-cb:checked');
    if (!checked.length) { showToast('请先选择要下载的资源', 'error'); return; }

    const urls = Array.from(checked).map(cb => {
        const idx = parseInt(cb.dataset.idx);
        return assetList[idx] ? assetList[idx].url : null;
    }).filter(Boolean);

    showToast(`正在打包 ${urls.length} 个资源...`, 'info');

    try {
        const resp = await fetch(API_BASE + '/api/site/assets/download', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ urls }),
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.error || '下载失败');
        }
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'assets.zip';
        a.click();
        URL.revokeObjectURL(url);
        showToast('资源已下载', 'success');
    } catch (e) {
        showToast(e.message || '下载失败', 'error');
    }
}

const assetTypeFilterEl = document.getElementById('asset-type-filter');
if (assetTypeFilterEl) assetTypeFilterEl.addEventListener('change', loadAssets);

// ===== Script Generation =====
let generatedScript = '';
let generatedScriptType = '';

async function generateScript(type) {
    generatedScriptType = type;
    const card = document.getElementById('script-result-card');
    const title = document.getElementById('script-result-title');
    if (card) card.style.display = 'block';
    if (title) title.innerHTML = '<span class="spinner"></span> 生成中...';

    try {
        const data = await apiCall('/api/scripts/generate', {
            method: 'POST',
            body: JSON.stringify({ type }),
        });
        generatedScript = data.script || '';
        if (title) title.textContent = `${type.toUpperCase()} 脚本`;
        const code = document.getElementById('script-result-code');
        if (code) code.textContent = generatedScript;
        showToast('脚本生成成功', 'success');
    } catch (e) {
        if (title) title.textContent = '生成失败';
        showToast(e.message || '脚本生成失败', 'error');
    }
}

function copyScript() {
    if (!generatedScript) { showToast('请先生成脚本', 'error'); return; }
    navigator.clipboard.writeText(generatedScript).then(() => showToast('已复制', 'success'))
        .catch(() => {
            const ta = document.createElement('textarea');
            ta.value = generatedScript;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            showToast('已复制', 'success');
        });
}

function downloadScript() {
    if (!generatedScript) { showToast('请先生成脚本', 'error'); return; }
    const exts = { python: 'py', curl: 'sh', playwright: 'py' };
    const ext = exts[generatedScriptType] || 'txt';
    const blob = new Blob([generatedScript], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `api_hunter_script.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('脚本已下载', 'success');
}

// ===== SEO Analysis =====
async function runSEOAnalysis() {
    const btn = document.getElementById('btn-seo-analyze');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 分析中...'; }

    try {
        const data = await apiCall('/api/site/seo', { method: 'POST', body: '{}' });
        const resDiv = document.getElementById('seo-results');
        if (resDiv) resDiv.style.display = 'block';

        // Summary
        const summaryGrid = document.getElementById('seo-summary-grid');
        if (summaryGrid) {
            const seoScore = data.seo ? data.seo.average_score : 0;
            const perfScore = data.performance ? data.performance.average_score : 0;
            const overall = data.overall_score || 0;
            const seoColor = overall >= 80 ? 'green' : overall >= 50 ? 'orange' : 'red';
            summaryGrid.innerHTML = `
                <div class="stat-card"><div class="stat-icon ${seoColor}"><span class="stat-value" style="font-size:28px;">${overall}</span></div><div class="stat-info"><span class="stat-label">总评分</span></div></div>
                <div class="stat-card"><div class="stat-icon blue"><span class="stat-value">${seoScore}</span></div><div class="stat-info"><span class="stat-label">SEO分数</span></div></div>
                <div class="stat-card"><div class="stat-icon purple"><span class="stat-value">${perfScore}</span></div><div class="stat-info"><span class="stat-label">性能分数</span></div></div>
                <div class="stat-card"><div class="stat-icon green"><span class="stat-value">${data.seo ? (data.seo.summary || {}).pages_above_80 || 0 : 0}</span></div><div class="stat-info"><span class="stat-label">优秀页面</span></div></div>`;
        }

        // Top issues
        const issuesDiv = document.getElementById('seo-top-issues');
        if (issuesDiv && data.seo && data.seo.summary) {
            const issues = data.seo.summary.top_issues || [];
            if (issues.length) {
                issuesDiv.innerHTML = issues.map(i => `<div style="padding:6px 0;border-bottom:1px solid var(--border);font-size:13px;"><span style="color:var(--warning);">⚠</span> ${escapeHtml(i.issue)} <span style="color:var(--text-muted);">(${i.count} 个页面)</span></div>`).join('');
            } else {
                issuesDiv.innerHTML = '<p style="color:var(--success);font-size:13px;">未发现常见问题</p>';
            }
        }

        // Per-page table
        const tbody = document.getElementById('seo-pages-tbody');
        if (tbody && data.seo && data.seo.pages) {
            tbody.innerHTML = data.seo.pages.map(p => {
                const scoreColor = p.score >= 80 ? 'green' : p.score >= 50 ? 'orange' : 'red';
                return `<tr>
                    <td><span class="badge badge-${scoreColor}">${p.score}</span></td>
                    <td title="${escapeHtml(p.url || '')}">${truncate(p.url || '', 55)}</td>
                    <td>${truncate(p.title || '-', 25)}</td>
                    <td>${p.issue_count || 0}</td>
                </tr>`;
            }).join('');
        }

        showToast('SEO分析完成', 'success');
    } catch (e) {
        showToast(e.message || 'SEO分析失败', 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = '开始分析'; }
    }
}

// ===== Proxy =====
let proxyPollTimer = null;

async function startProxy() {
    const port = document.getElementById('proxy-port').value || '8088';
    try {
        const res = await apiCall('/api/proxy/start', { method: 'POST', body: JSON.stringify({ port: parseInt(port) }) });
        if (res.success) {
            showToast(res.message, 'success');
            document.getElementById('btn-proxy-start').style.display = 'none';
            document.getElementById('btn-proxy-stop').style.display = '';
            document.getElementById('proxy-status').innerHTML = `<span style="color:var(--success);">● 运行中 - 127.0.0.1:${port}</span><br><span style="font-size:12px;">在浏览器设置 HTTP 代理为 127.0.0.1:${port} 即可抓包</span>`;
            proxyPollTimer = setInterval(loadProxyTraffic, 3000);
            loadProxyTraffic();
        } else {
            showToast(res.message, 'error');
        }
    } catch (e) { showToast(e.message, 'error'); }
}

async function stopProxy() {
    try {
        const res = await apiCall('/api/proxy/stop', { method: 'POST' });
        showToast(res.message, res.success ? 'success' : 'error');
        document.getElementById('btn-proxy-start').style.display = '';
        document.getElementById('btn-proxy-stop').style.display = 'none';
        document.getElementById('proxy-status').innerHTML = '<span style="color:var(--text-muted);">已停止</span>';
        if (proxyPollTimer) { clearInterval(proxyPollTimer); proxyPollTimer = null; }
    } catch (e) { showToast(e.message, 'error'); }
}

async function loadProxyTraffic() {
    const keyword = document.getElementById('proxy-filter')?.value || '';
    const method = document.getElementById('proxy-method-filter')?.value || '';
    try {
        const rows = await apiCall(`/api/proxy/traffic?keyword=${encodeURIComponent(keyword)}&method=${encodeURIComponent(method)}&limit=200`);
        const tbody = document.getElementById('proxy-tbody');
        if (tbody) {
            tbody.innerHTML = (rows || []).map(r => {
                const t = r.captured_at ? new Date(r.captured_at * 1000).toLocaleTimeString() : '';
                const mClass = `badge-${(r.method || 'get').toLowerCase()}`;
                const url = (r.url || '').substring(0, 80);
                return `<tr><td style="font-size:11px;color:var(--text-muted);">${t}</td><td><span class="badge ${mClass}">${r.method || ''}</span></td><td title="${escHtml(r.url || '')}">${escHtml(url)}</td><td>${r.status_code || ''}</td><td><button class="btn-link" onclick="showTrafficDetail(${r.id})">详情</button></td></tr>`;
            }).join('');
        }
        const count = document.getElementById('proxy-count');
        if (count) count.textContent = `${(rows || []).length} 条记录`;
    } catch (e) {}
}

async function showTrafficDetail(id) {
    try {
        const d = await apiCall(`/api/proxy/traffic/${id}`);
        if (!d) return;
        let html = `<div class="detail-grid">`;
        html += kv('方法', d.method);
        html += kv('URL', d.url);
        html += kv('状态码', d.status_code);
        html += `</div>`;
        if (d.request_headers && typeof d.request_headers === 'object') {
            html += `<div class="detail-section"><h4>请求头</h4><div class="pre-block">${escHtml(JSON.stringify(d.request_headers, null, 2))}</div></div>`;
        }
        if (d.request_body) {
            html += `<div class="detail-section"><h4>请求体</h4><div class="pre-block">${escHtml(d.request_body.substring(0, 3000))}</div></div>`;
        }
        if (d.response_headers && typeof d.response_headers === 'object') {
            html += `<div class="detail-section"><h4>响应头</h4><div class="pre-block">${escHtml(JSON.stringify(d.response_headers, null, 2))}</div></div>`;
        }
        if (d.response_body) {
            html += `<div class="detail-section"><h4>响应体</h4><div class="pre-block">${escHtml(d.response_body.substring(0, 3000))}</div></div>`;
        }
        document.getElementById('modal-body').innerHTML = html;
        document.getElementById('detail-modal').classList.add('active');
    } catch (e) { showToast(e.message, 'error'); }
}

async function clearProxyTraffic() {
    if (!confirm('确定清空所有捕获的流量？')) return;
    await apiCall('/api/proxy/clear', { method: 'POST' });
    loadProxyTraffic();
    showToast('已清空', 'success');
}

// ===== GraphQL =====
async function introspectGraphQL() {
    const url = document.getElementById('graphql-url').value.trim();
    if (!url) { showToast('请输入GraphQL端点URL', 'error'); return; }
    showToast('正在执行Introspection...', 'info');
    try {
        const res = await apiCall('/api/graphql/introspect', { method: 'POST', body: JSON.stringify({ url }) });
        if (res.error) { showToast(res.error, 'error'); return; }
        const analysis = res.analysis;
        if (!analysis) { showToast('无分析结果', 'error'); return; }

        document.getElementById('graphql-results').style.display = '';
        // Summary
        document.getElementById('graphql-summary').innerHTML = `
            <div class="stat-card"><div class="stat-icon blue">Q</div><div class="stat-info"><div class="stat-value">${(analysis.queries || []).length}</div><div class="stat-label">Queries</div></div></div>
            <div class="stat-card"><div class="stat-icon green">M</div><div class="stat-info"><div class="stat-value">${(analysis.mutations || []).length}</div><div class="stat-label">Mutations</div></div></div>
            <div class="stat-card"><div class="stat-icon orange">T</div><div class="stat-info"><div class="stat-value">${analysis.total_types || 0}</div><div class="stat-label">Types</div></div></div>
            <div class="stat-card"><div class="stat-icon purple">E</div><div class="stat-info"><div class="stat-value">${(analysis.enums || []).length}</div><div class="stat-label">Enums</div></div></div>`;

        // Queries
        document.getElementById('gql-queries').innerHTML = (analysis.queries || []).map(q =>
            `<tr><td><strong>${escHtml(q.name)}</strong></td><td>${q.args}</td><td><code>${escHtml(q.type || '')}</code></td></tr>`
        ).join('') || '<tr><td colspan="3" style="color:var(--text-muted);">无</td></tr>';

        // Mutations
        document.getElementById('gql-mutations').innerHTML = (analysis.mutations || []).map(m =>
            `<tr><td><strong>${escHtml(m.name)}</strong></td><td>${m.args}</td><td><code>${escHtml(m.type || '')}</code></td></tr>`
        ).join('') || '<tr><td colspan="3" style="color:var(--text-muted);">无</td></tr>';

        // Types
        document.getElementById('gql-types').innerHTML = (analysis.types || []).map(t =>
            `<tr><td><strong>${escHtml(t.name)}</strong></td><td>${(t.fields || []).length}</td><td>${escHtml((t.description || '').substring(0, 100))}</td></tr>`
        ).join('') || '<tr><td colspan="3" style="color:var(--text-muted);">无</td></tr>';

        // Enums
        document.getElementById('gql-enums').innerHTML = (analysis.enums || []).map(e =>
            `<tr><td><strong>${escHtml(e.name)}</strong></td><td style="font-size:12px;">${(e.values || []).map(v => `<span class="badge" style="margin:1px;">${escHtml(v)}</span>`).join(' ')}</td></tr>`
        ).join('') || '<tr><td colspan="2" style="color:var(--text-muted);">无</td></tr>';

        showToast('Introspection完成', 'success');
    } catch (e) { showToast(e.message, 'error'); }
}

async function findGraphQLEndpoints() {
    try {
        const pages = await apiCall('/api/site/pages');
        if (!pages || !pages.length) { showToast('请先进行全站爬取', 'error'); return; }
        let allEndpoints = [];
        for (const p of pages.slice(0, 50)) {
            const res = await apiCall('/api/graphql/find', { method: 'POST', body: JSON.stringify({ html: '', js_code: (p.scripts || []).map(s => s.src || '').join('\n') + ' ' + (p.url || '') }) });
            if (res.endpoints) allEndpoints.push(...res.endpoints);
        }
        allEndpoints = [...new Set(allEndpoints)];
        const container = document.getElementById('graphql-found-endpoints');
        if (allEndpoints.length) {
            container.innerHTML = allEndpoints.map(ep => `<div style="padding:6px 0;font-size:13px;"><code>${escHtml(ep)}</code> <button class="btn-link" onclick="document.getElementById('graphql-url').value='${escHtml(ep)}'">使用</button></div>`).join('');
        } else {
            container.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:8px 0;">未发现GraphQL端点</div>';
        }
    } catch (e) { showToast(e.message, 'error'); }
}

// ===== WebSocket =====
async function detectWebSockets() {
    showToast('正在检测...', 'info');
    try {
        const res = await apiCall('/api/websocket/detect');
        const tbody = document.getElementById('ws-tbody');
        const empty = document.getElementById('ws-empty');
        const libDiv = document.getElementById('ws-libraries');

        if (res.libraries && res.libraries.length) {
            libDiv.innerHTML = '<span style="font-size:13px;color:var(--text-secondary);">检测到的库: </span>' + res.libraries.map(l => `<span class="tech-badge">${escHtml(l)}</span>`).join(' ');
        } else {
            libDiv.innerHTML = '';
        }

        if (res.endpoints && res.endpoints.length) {
            empty.style.display = 'none';
            tbody.innerHTML = res.endpoints.map(ep => {
                const proto = ep.protocol === 'wss' ? 'badge-patch' : 'badge-get';
                return `<tr><td><span class="badge ${proto}">${ep.protocol}</span></td><td><code>${escHtml(ep.url)}</code></td><td style="font-size:12px;color:var(--text-muted);">${escHtml(ep.found_on || '')}</td><td><button class="btn btn-outline btn-sm" onclick="testWS('${escHtml(ep.url)}')">测试</button></td></tr>`;
            }).join('');
            showToast(`发现 ${res.endpoints.length} 个WebSocket端点`, 'success');
        } else {
            empty.style.display = '';
            tbody.innerHTML = '';
            showToast('未发现WebSocket端点', 'info');
        }
    } catch (e) { showToast(e.message, 'error'); }
}

async function testWS(url) {
    showToast('正在测试连接...', 'info');
    try {
        const res = await apiCall('/api/websocket/test', { method: 'POST', body: JSON.stringify({ url }) });
        if (res.connected) {
            showToast('连接成功', 'success');
        } else {
            showToast(res.error || '连接失败', 'error');
        }
    } catch (e) { showToast(e.message, 'error'); }
}

// ===== Report =====
async function generateReport() {
    const btn = document.getElementById('btn-gen-report');
    if (btn) { btn.disabled = true; btn.textContent = '生成中...'; }
    try {
        const res = await apiCall('/api/report/generate', { method: 'POST', body: '{}' });
        if (res.success) {
            showToast('报告生成成功', 'success');
            document.getElementById('report-result').style.display = '';
            document.getElementById('report-list').innerHTML = `
                <div style="display:flex;align-items:center;gap:12px;padding:12px 0;">
                    <span style="font-size:14px;">${escHtml(res.filename)}</span>
                    <a class="btn btn-primary btn-sm" href="/api/report/download/${encodeURIComponent(res.filename)}" target="_blank">下载报告</a>
                </div>`;
        } else {
            showToast(res.error || '生成失败', 'error');
        }
    } catch (e) { showToast(e.message, 'error'); }
    finally { if (btn) { btn.disabled = false; btn.textContent = '生成HTML报告'; } }
}

// ===== Tasks =====
async function loadTasks() {
    try {
        const tasks = await apiCall('/api/tasks');
        const tbody = document.getElementById('tasks-tbody');
        const empty = document.getElementById('tasks-empty');
        if (tasks && tasks.length) {
            empty.style.display = 'none';
            tbody.innerHTML = tasks.map(t => {
                const statusColors = { running: 'var(--success)', completed: 'var(--info)', failed: 'var(--danger)', stopped: 'var(--warning)', pending: 'var(--text-muted)' };
                const color = statusColors[t.status] || 'var(--text-muted)';
                const progressBar = t.status === 'running' ? `<div class="progress-bar" style="height:6px;width:100px;display:inline-block;vertical-align:middle;"><div class="progress-fill" style="width:${t.progress || 0}%;"></div></div>` : '';
                const stopBtn = t.status === 'running' ? `<button class="btn btn-outline btn-sm" onclick="stopTask('${t.id}')">停止</button>` : '';
                return `<tr><td style="font-size:11px;font-family:monospace;">${escHtml(t.id)}</td><td>${escHtml(t.type)}</td><td style="max-width:200px;" title="${escHtml(t.target || '')}">${escHtml((t.target || '').substring(0, 50))}</td><td><span style="color:${color};font-weight:600;">${t.status}</span></td><td>${progressBar} ${t.progress || 0}%</td><td>${stopBtn}</td></tr>`;
            }).join('');
        } else {
            empty.style.display = '';
            tbody.innerHTML = '';
        }
    } catch (e) {}
}

async function stopTask(id) {
    try {
        const res = await apiCall(`/api/tasks/${id}/stop`, { method: 'POST' });
        showToast(res.message, res.success ? 'success' : 'error');
        loadTasks();
    } catch (e) { showToast(e.message, 'error'); }
}

// ===== Plugins =====
async function loadPlugins() {
    try {
        const plugins = await apiCall('/api/plugins');
        const tbody = document.getElementById('plugins-tbody');
        const empty = document.getElementById('plugins-empty');
        if (plugins && plugins.length) {
            empty.style.display = 'none';
            tbody.innerHTML = plugins.map(p => {
                const toggleLabel = p.enabled ? '禁用' : '启用';
                const toggleClass = p.enabled ? 'btn-outline' : 'btn-primary';
                return `<tr><td><strong>${escHtml(p.name)}</strong><br><span style="font-size:11px;color:var(--text-muted);">${escHtml(p.description || '')}</span></td><td><span class="badge badge-get">${escHtml(p.type)}</span></td><td>${p.rules_count}</td><td><span style="color:${p.enabled ? 'var(--success)' : 'var(--text-muted)'};">${p.enabled ? '已启用' : '已禁用'}</span></td><td><button class="btn ${toggleClass} btn-sm" onclick="togglePlugin('${escHtml(p.name)}')">${toggleLabel}</button> <button class="btn btn-outline btn-sm" onclick="deletePlugin('${escHtml(p.name)}')">删除</button></td></tr>`;
            }).join('');
        } else {
            empty.style.display = '';
            tbody.innerHTML = '';
        }
    } catch (e) {}
}

async function togglePlugin(name) {
    try {
        const res = await apiCall(`/api/plugins/${encodeURIComponent(name)}/toggle`, { method: 'POST' });
        showToast(res.message, res.success ? 'success' : 'error');
        loadPlugins();
    } catch (e) { showToast(e.message, 'error'); }
}

async function deletePlugin(name) {
    if (!confirm(`确定删除插件 "${name}"？`)) return;
    try {
        const res = await apiCall(`/api/plugins/${encodeURIComponent(name)}`, { method: 'DELETE' });
        showToast(res.message, res.success ? 'success' : 'error');
        loadPlugins();
    } catch (e) { showToast(e.message, 'error'); }
}

async function installPlugin() {
    const json = document.getElementById('plugin-json').value.trim();
    if (!json) { showToast('请输入插件JSON', 'error'); return; }
    try {
        const res = await apiCall('/api/plugins/install', { method: 'POST', body: JSON.stringify({ json }) });
        showToast(res.message, res.success ? 'success' : 'error');
        if (res.success) {
            document.getElementById('plugin-json').value = '';
            loadPlugins();
        }
    } catch (e) { showToast(e.message, 'error'); }
}

async function loadPluginExample() {
    try {
        const ex = await apiCall('/api/plugins/example');
        document.getElementById('plugin-json').value = JSON.stringify(ex, null, 2);
    } catch (e) { showToast(e.message, 'error'); }
}

// ===== Parameter Mining =====
let paramPollTimer = null;

async function startParamMine() {
    const url = document.getElementById('param-url').value.trim();
    if (!url) { showToast('请输入目标URL', 'error'); return; }
    const btn = document.getElementById('param-start-btn');
    const stopBtn = document.getElementById('param-stop-btn');
    const progBar = document.getElementById('param-progress');
    btn.disabled = true; btn.textContent = '挖掘中...';
    stopBtn.style.display = 'inline-block';
    progBar.style.display = 'block';
    try {
        await apiCall('/api/param/mine', { method: 'POST', body: JSON.stringify({ url }) });
        if (paramPollTimer) clearInterval(paramPollTimer);
        paramPollTimer = setInterval(pollParamProgress, 1500);
    } catch (e) {
        showToast(e.message, 'error');
        btn.disabled = false; btn.textContent = '开始挖掘';
        stopBtn.style.display = 'none'; progBar.style.display = 'none';
    }
}

async function pollParamProgress() {
    try {
        const s = await apiCall('/api/param/progress');
        const fill = document.getElementById('param-progress-fill');
        const text = document.getElementById('param-progress-text');
        if (fill) fill.style.width = (s.progress || 0) + '%';
        if (text) text.textContent = s.message || '';
        if (!s.active) {
            clearInterval(paramPollTimer); paramPollTimer = null;
            document.getElementById('param-start-btn').disabled = false;
            document.getElementById('param-start-btn').textContent = '开始挖掘';
            document.getElementById('param-stop-btn').style.display = 'none';
            loadParamResults(s.results);
        }
    } catch (e) { console.error('Param poll error:', e); }
}

function stopParamMine() {
    apiCall('/api/param/stop', { method: 'POST' }).then(() => showToast('已停止', 'info'));
}

function loadParamResults(results) {
    const div = document.getElementById('param-results');
    if (!results) { div.innerHTML = '<div style="color:var(--text-muted)">无结果</div>'; return; }
    let html = '';
    // Summary
    const s = results.summary || {};
    html += `<div style="display:flex;gap:16px;margin-bottom:12px;">
        <div class="stat-card"><div class="stat-info"><span class="stat-value">${s.total_tested || 0}</span><span class="stat-label">已测试参数</span></div></div>
        <div class="stat-card"><div class="stat-info"><span class="stat-value">${s.interesting || 0}</span><span class="stat-label">有效参数</span></div></div>
    </div>`;
    // Findings
    const findings = results.findings || [];
    if (findings.length) {
        html += '<h4 style="margin:8px 0;">发现的参数:</h4>';
        html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>参数名</th><th>类型</th><th>严重性</th><th>说明</th></tr></thead><tbody>';
        findings.forEach(f => {
            html += `<tr><td><code>${escHtml(f.parameter || '-')}</code></td><td>${escHtml(f.type || '-')}</td>
                <td><span class="risk-badge risk-${f.severity || 'info'}">${escHtml(f.severity || '-')}</span></td>
                <td>${escHtml(f.description || '-')}</td></tr>`;
        });
        html += '</tbody></table></div>';
    }
    // Mined from endpoints
    const mined = results.mined_from_endpoints || [];
    if (mined.length) {
        html += '<h4 style="margin:12px 0 8px;">从接口中提取的参数:</h4>';
        html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>参数名</th><th>出现次数</th><th>示例值</th></tr></thead><tbody>';
        mined.slice(0, 20).forEach(p => {
            html += `<tr><td><code>${escHtml(p.name)}</code></td><td>${p.seen_in}</td><td style="font-size:12px;">${escHtml((p.sample_values || []).join(', '))}</td></tr>`;
        });
        html += '</tbody></table></div>';
    }
    div.innerHTML = html || '<div style="color:var(--text-muted)">未发现参数</div>';
}

async function analyzeJwt() {
    const token = document.getElementById('jwt-token').value.trim();
    if (!token) { showToast('请粘贴JWT令牌', 'error'); return; }
    try {
        const result = await apiCall('/api/auth/jwt/analyze', { method: 'POST', body: JSON.stringify({ token }) });
        const div = document.getElementById('jwt-result');
        let html = '';
        if (result.valid) {
            html += `<div style="margin-bottom:8px;"><strong>算法:</strong> <code>${escHtml(result.algorithm)}</code></div>`;
            html += '<details open><summary>Header</summary><pre style="background:var(--bg-card);padding:8px;border-radius:4px;font-size:12px;overflow:auto;">' + escHtml(JSON.stringify(result.header, null, 2)) + '</pre></details>';
            html += '<details open style="margin-top:8px;"><summary>Payload</summary><pre style="background:var(--bg-card);padding:8px;border-radius:4px;font-size:12px;overflow:auto;">' + escHtml(JSON.stringify(result.payload, null, 2)) + '</pre></details>';
            if (result.algorithm === 'none') {
                html += '<div class="risk-badge risk-critical" style="margin-top:8px;">危</span> 使用none算法，令牌可被任意伪造!</div>';
            }
        } else {
            html += '<div style="color:var(--danger)">JWT格式错误: ' + escHtml((result.errors || []).join('; ')) + '</div>';
        }
        div.innerHTML = html;
    } catch (e) { showToast(e.message, 'error'); }
}

// ===== Auth Detection =====
let authPollTimer = null;

async function startAuthCheck() {
    const url = document.getElementById('auth-url').value.trim();
    if (!url) { showToast('请输入目标URL', 'error'); return; }
    const headersStr = document.getElementById('auth-headers').value.trim();
    let authHeaders = {};
    if (headersStr) { try { authHeaders = JSON.parse(headersStr); } catch(e) { showToast('认证头JSON格式错误', 'error'); return; } }
    const btn = document.getElementById('auth-start-btn');
    const stopBtn = document.getElementById('auth-stop-btn');
    const progBar = document.getElementById('auth-progress');
    btn.disabled = true; btn.textContent = '检测中...';
    stopBtn.style.display = 'inline-block'; progBar.style.display = 'block';
    try {
        await apiCall('/api/auth/check', { method: 'POST', body: JSON.stringify({ url, auth_headers: authHeaders }) });
        if (authPollTimer) clearInterval(authPollTimer);
        authPollTimer = setInterval(pollAuthProgress, 1500);
    } catch (e) {
        showToast(e.message, 'error');
        btn.disabled = false; btn.textContent = '开始检测';
        stopBtn.style.display = 'none'; progBar.style.display = 'none';
    }
}

async function pollAuthProgress() {
    try {
        const s = await apiCall('/api/auth/progress');
        const fill = document.getElementById('auth-progress-fill');
        const text = document.getElementById('auth-progress-text');
        if (fill) fill.style.width = (s.progress || 0) + '%';
        if (text) text.textContent = s.message || '';
        if (!s.active) {
            clearInterval(authPollTimer); authPollTimer = null;
            document.getElementById('auth-start-btn').disabled = false;
            document.getElementById('auth-start-btn').textContent = '开始检测';
            document.getElementById('auth-stop-btn').style.display = 'none';
            loadAuthResults(s.results);
        }
    } catch (e) { console.error('Auth poll error:', e); }
}

function stopAuthCheck() {
    apiCall('/api/auth/stop', { method: 'POST' }).then(() => showToast('已停止', 'info'));
}

function loadAuthResults(results) {
    const div = document.getElementById('auth-results');
    if (!results) { div.innerHTML = '<div style="color:var(--text-muted)">无结果</div>'; return; }
    let html = '';
    const s = results.summary || {};
    html += `<div style="display:flex;gap:16px;margin-bottom:12px;">
        <div class="stat-card"><div class="stat-info"><span class="stat-value" style="color:var(--danger)">${s.critical || 0}</span><span class="stat-label">严重</span></div></div>
        <div class="stat-card"><div class="stat-info"><span class="stat-value" style="color:var(--warning)">${s.high || 0}</span><span class="stat-label">高风险</span></div></div>
        <div class="stat-card"><div class="stat-info"><span class="stat-value" style="color:var(--info)">${s.medium || 0}</span><span class="stat-label">中风险</span></div></div>
    </div>`;
    const findings = results.findings || [];
    if (findings.length) {
        html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>类型</th><th>严重性</th><th>描述</th><th>证据</th></tr></thead><tbody>';
        findings.forEach(f => {
            html += `<tr><td>${escHtml(f.type)}</td><td><span class="risk-badge risk-${f.severity}">${escHtml(f.severity)}</span></td>
                <td>${escHtml(f.description)}</td><td style="font-size:12px;">${escHtml(f.evidence || '-')}</td></tr>`;
        });
        html += '</tbody></table></div>';
    }
    // JWT tokens
    const jwtTokens = results.jwt_tokens || [];
    if (jwtTokens.length) {
        html += '<h4 style="margin:12px 0 8px;">发现的JWT令牌:</h4>';
        jwtTokens.forEach(j => {
            html += `<div style="background:var(--bg-card);padding:8px;border-radius:4px;margin-bottom:8px;">
                <strong>来源:</strong> ${escHtml(j.source)} <strong>算法:</strong> <code>${escHtml(j.algorithm)}</code>
                <details><summary>Payload</summary><pre style="font-size:12px;">${escHtml(JSON.stringify(j.payload, null, 2))}</pre></details></div>`;
        });
    }
    div.innerHTML = html || '<div style="color:var(--text-muted)">未发现问题</div>';
}

// ===== Header Audit =====
let headerPollTimer = null;

async function startHeaderAudit() {
    const url = document.getElementById('header-url').value.trim();
    if (!url) { showToast('请输入目标URL', 'error'); return; }
    const btn = document.getElementById('header-start-btn');
    const stopBtn = document.getElementById('header-stop-btn');
    const progBar = document.getElementById('header-progress');
    btn.disabled = true; btn.textContent = '审计中...';
    stopBtn.style.display = 'inline-block'; progBar.style.display = 'block';
    try {
        await apiCall('/api/header/audit', { method: 'POST', body: JSON.stringify({ url }) });
        if (headerPollTimer) clearInterval(headerPollTimer);
        headerPollTimer = setInterval(pollHeaderProgress, 1500);
    } catch (e) {
        showToast(e.message, 'error');
        btn.disabled = false; btn.textContent = '开始审计';
        stopBtn.style.display = 'none'; progBar.style.display = 'none';
    }
}

async function pollHeaderProgress() {
    try {
        const s = await apiCall('/api/header/progress');
        const fill = document.getElementById('header-progress-fill');
        const text = document.getElementById('header-progress-text');
        if (fill) fill.style.width = (s.progress || 0) + '%';
        if (text) text.textContent = s.message || '';
        if (!s.active) {
            clearInterval(headerPollTimer); headerPollTimer = null;
            document.getElementById('header-start-btn').disabled = false;
            document.getElementById('header-start-btn').textContent = '开始审计';
            document.getElementById('header-stop-btn').style.display = 'none';
            loadHeaderResults(s.results);
        }
    } catch (e) { console.error('Header poll error:', e); }
}

function stopHeaderAudit() {
    apiCall('/api/header/stop', { method: 'POST' }).then(() => showToast('已停止', 'info'));
}

function loadHeaderResults(results) {
    const div = document.getElementById('header-results');
    if (!results) { div.innerHTML = '<div style="color:var(--text-muted)">无结果</div>'; return; }
    let html = '';
    // Score
    const score = results.score || 0;
    const scoreColor = score >= 80 ? 'var(--success)' : score >= 50 ? 'var(--warning)' : 'var(--danger)';
    html += `<div style="text-align:center;margin-bottom:16px;">
        <div style="font-size:48px;font-weight:700;color:${scoreColor}">${score}</div>
        <div style="color:var(--text-muted)">安全评分 / 100</div>
    </div>`;
    // Summary
    const s = results.summary || {};
    html += `<div style="display:flex;gap:12px;margin-bottom:12px;">
        <div class="stat-card"><div class="stat-info"><span class="stat-value" style="color:var(--danger)">${s.critical || 0}</span><span class="stat-label">严重</span></div></div>
        <div class="stat-card"><div class="stat-info"><span class="stat-value" style="color:var(--warning)">${s.high || 0}</span><span class="stat-label">高风险</span></div></div>
        <div class="stat-card"><div class="stat-info"><span class="stat-value" style="color:var(--info)">${s.medium || 0}</span><span class="stat-label">中风险</span></div></div>
        <div class="stat-card"><div class="stat-info"><span class="stat-value" style="color:var(--success)">${s.low || 0}</span><span class="stat-label">低风险</span></div></div>
    </div>`;
    // Findings table
    const findings = results.findings || [];
    if (findings.length) {
        html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>类型</th><th>严重性</th><th>描述</th><th>建议</th></tr></thead><tbody>';
        findings.forEach(f => {
            html += `<tr><td>${escHtml(f.type)}</td><td><span class="risk-badge risk-${f.severity}">${escHtml(f.severity)}</span></td>
                <td>${escHtml(f.description)}</td><td style="font-size:12px;color:var(--text-muted)">${escHtml(f.recommendation || '-')}</td></tr>`;
        });
        html += '</tbody></table></div>';
    }
    // CORS tests
    const corsTests = results.cors_tests || [];
    const vulnCors = corsTests.filter(c => c.vulnerable);
    if (vulnCors.length) {
        html += '<h4 style="margin:12px 0 8px;">CORS测试结果:</h4>';
        html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>测试Origin</th><th>ACAO</th><th>ACAC</th><th>风险</th></tr></thead><tbody>';
        vulnCors.forEach(c => {
            html += `<tr><td style="font-size:12px;">${escHtml(c.origin)}</td><td><code>${escHtml(c.acao)}</code></td><td>${escHtml(c.acac)}</td>
                <td><span class="risk-badge risk-critical">高危</span></td></tr>`;
        });
        html += '</tbody></table></div>';
    }
    div.innerHTML = html || '<div style="color:var(--text-muted)">无结果</div>';
}

// ===== Subdomain Enumeration =====
let subdomainPollTimer = null;

async function startSubdomainEnum() {
    const domain = document.getElementById('subdomain-domain').value.trim();
    if (!domain) { showToast('请输入目标域名', 'error'); return; }
    const bruteforce = document.getElementById('subdomain-bruteforce').checked;
    const btn = document.getElementById('subdomain-start-btn');
    const stopBtn = document.getElementById('subdomain-stop-btn');
    const progBar = document.getElementById('subdomain-progress');
    btn.disabled = true; btn.textContent = '枚举中...';
    stopBtn.style.display = 'inline-block'; progBar.style.display = 'block';
    try {
        await apiCall('/api/subdomain/enum', { method: 'POST', body: JSON.stringify({ domain, bruteforce }) });
        if (subdomainPollTimer) clearInterval(subdomainPollTimer);
        subdomainPollTimer = setInterval(pollSubdomainProgress, 2000);
    } catch (e) {
        showToast(e.message, 'error');
        btn.disabled = false; btn.textContent = '开始枚举';
        stopBtn.style.display = 'none'; progBar.style.display = 'none';
    }
}

async function pollSubdomainProgress() {
    try {
        const s = await apiCall('/api/subdomain/progress');
        const fill = document.getElementById('subdomain-progress-fill');
        const text = document.getElementById('subdomain-progress-text');
        if (fill) fill.style.width = (s.progress || 0) + '%';
        if (text) text.textContent = s.message || '';
        if (!s.active) {
            clearInterval(subdomainPollTimer); subdomainPollTimer = null;
            document.getElementById('subdomain-start-btn').disabled = false;
            document.getElementById('subdomain-start-btn').textContent = '开始枚举';
            document.getElementById('subdomain-stop-btn').style.display = 'none';
            loadSubdomainResults(s.results);
        }
    } catch (e) { console.error('Subdomain poll error:', e); }
}

function stopSubdomainEnum() {
    apiCall('/api/subdomain/stop', { method: 'POST' }).then(() => showToast('已停止', 'info'));
}

function loadSubdomainResults(results) {
    const div = document.getElementById('subdomain-results');
    if (!results) { div.innerHTML = '<div style="color:var(--text-muted)">无结果</div>'; return; }
    let html = '';
    const s = results.summary || {};
    html += `<div style="display:flex;gap:16px;margin-bottom:12px;">
        <div class="stat-card"><div class="stat-info"><span class="stat-value">${s.total_unique || 0}</span><span class="stat-label">子域名总数</span></div></div>
        <div class="stat-card"><div class="stat-info"><span class="stat-value" style="color:var(--success)">${s.alive || 0}</span><span class="stat-label">存活</span></div></div>
    </div>`;
    // DNS records
    const dns = results.dns_records || {};
    if (Object.keys(dns).length) {
        html += '<h4 style="margin:8px 0;">DNS记录:</h4>';
        html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>类型</th><th>记录</th></tr></thead><tbody>';
        for (const [rtype, records] of Object.entries(dns)) {
            records.forEach(r => { html += `<tr><td><code>${escHtml(rtype)}</code></td><td style="font-size:12px;">${escHtml(r)}</td></tr>`; });
        }
        html += '</tbody></table></div>';
    }
    // Subdomain list
    const subs = results.subdomains || [];
    if (subs.length) {
        html += '<h4 style="margin:12px 0 8px;">发现的子域名:</h4>';
        html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>子域名</th><th>IP</th><th>HTTP</th><th>HTTPS</th><th>状态</th></tr></thead><tbody>';
        subs.forEach(sub => {
            const name = typeof sub === 'string' ? sub : sub.subdomain;
            const ip = sub.ip || '-';
            const http = sub.http ? '<span style="color:var(--success)">&#10003;</span>' : '<span style="color:var(--text-muted)">&#10007;</span>';
            const https = sub.https ? '<span style="color:var(--success)">&#10003;</span>' : '<span style="color:var(--text-muted)">&#10007;</span>';
            const alive = sub.alive ? '<span class="risk-badge risk-low">存活</span>' : '<span class="risk-badge" style="background:var(--bg-card);color:var(--text-muted)">未知</span>';
            html += `<tr><td><code>${escHtml(name)}</code></td><td style="font-size:12px;">${escHtml(ip)}</td><td>${http}</td><td>${https}</td><td>${alive}</td></tr>`;
        });
        html += '</tbody></table></div>';
    }
    div.innerHTML = html || '<div style="color:var(--text-muted)">未发现子域名</div>';
}

// ===== OpenAPI Spec Import =====
async function importSpecFromUrl() {
    const url = document.getElementById('spec-url').value.trim();
    if (!url) { showToast('请输入规范URL', 'error'); return; }
    try {
        const result = await apiCall('/api/spec/import', { method: 'POST', body: JSON.stringify({ url }) });
        showSpecResults(result);
    } catch (e) { showToast(e.message, 'error'); }
}

async function importSpecFromContent() {
    const content = document.getElementById('spec-content').value.trim();
    if (!content) { showToast('请粘贴规范内容', 'error'); return; }
    try {
        const result = await apiCall('/api/spec/import', { method: 'POST', body: JSON.stringify({ content }) });
        showSpecResults(result);
    } catch (e) { showToast(e.message, 'error'); }
}

async function importSpecFromFile(event) {
    const file = event.target.files[0];
    if (!file) return;
    const formData = new FormData();
    formData.append('file', file);
    try {
        const resp = await fetch('/api/spec/import/file', { method: 'POST', body: formData });
        const result = await resp.json();
        if (result.error) { showToast(result.error, 'error'); return; }
        showSpecResults(result);
    } catch (e) { showToast(e.message, 'error'); }
    event.target.value = '';
}

function showSpecResults(result) {
    const div = document.getElementById('spec-results');
    if (result.error) { div.innerHTML = '<div style="color:var(--danger)">' + escHtml(result.error) + '</div>'; return; }
    let html = '';
    const s = result.summary || {};
    // Summary
    html += `<div style="display:flex;gap:16px;margin-bottom:12px;flex-wrap:wrap;">
        <div class="stat-card"><div class="stat-info"><span class="stat-value">${s.total_endpoints || 0}</span><span class="stat-label">接口总数</span></div></div>
        <div class="stat-card"><div class="stat-info"><span class="stat-value">${s.total_schemas || 0}</span><span class="stat-label">数据模型</span></div></div>
        <div class="stat-card"><div class="stat-info"><span class="stat-value">${s.total_test_cases || 0}</span><span class="stat-label">测试用例</span></div></div>
    </div>`;
    // Info
    html += `<div style="margin-bottom:12px;"><strong>${escHtml(result.title || '')}</strong> <span style="color:var(--text-muted)">v${escHtml(result.version || '?')}</span>`;
    if (result.base_url) html += ` <span style="color:var(--text-muted);font-size:12px;">@ ${escHtml(result.base_url)}</span>`;
    html += '</div>';
    // Methods
    const methods = s.by_method || {};
    if (Object.keys(methods).length) {
        html += '<div style="margin-bottom:12px;">';
        for (const [m, c] of Object.entries(methods)) {
            html += `<span class="method-badge method-${m.toLowerCase()}">${m}</span> ${c} `;
        }
        html += '</div>';
    }
    // Endpoints
    const endpoints = result.endpoints || [];
    if (endpoints.length) {
        html += '<h4 style="margin:8px 0;">发现的接口:</h4>';
        html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>方法</th><th>路径</th><th>说明</th><th>参数</th><th>已废弃</th></tr></thead><tbody>';
        endpoints.slice(0, 50).forEach(ep => {
            const params = (ep.parameters || []).map(p => p.name).join(', ');
            html += `<tr><td><span class="method-badge method-${(ep.method || 'GET').toLowerCase()}">${escHtml(ep.method)}</span></td>
                <td><code>${escHtml(ep.path || ep.url)}</code></td>
                <td style="font-size:12px;">${escHtml(ep.summary || '-')}</td>
                <td style="font-size:12px;">${escHtml(params || '-')}</td>
                <td>${ep.deprecated ? '<span class="risk-badge risk-medium">是</span>' : '-'}</td></tr>`;
        });
        html += '</tbody></table></div>';
        if (endpoints.length > 50) html += `<div style="font-size:12px;color:var(--text-muted);margin-top:4px;">显示前50个，共${endpoints.length}个</div>`;
    }
    // Schemas
    const schemas = result.schemas || {};
    if (Object.keys(schemas).length) {
        html += '<h4 style="margin:12px 0 8px;">数据模型:</h4>';
        html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>模型名</th><th>类型</th><th>字段数</th></tr></thead><tbody>';
        for (const [name, info] of Object.entries(schemas)) {
            html += `<tr><td><code>${escHtml(name)}</code></td><td>${escHtml(info.type || '-')}</td><td>${info.field_count || 0}</td></tr>`;
        }
        html += '</tbody></table></div>';
    }
    // Test cases preview
    const testCases = result.test_cases || [];
    if (testCases.length) {
        html += '<h4 style="margin:12px 0 8px;">生成的测试用例 (前10个):</h4>';
        html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>名称</th><th>方法</th><th>说明</th></tr></thead><tbody>';
        testCases.slice(0, 10).forEach(tc => {
            html += `<tr><td style="font-size:12px;">${escHtml(tc.name)}</td><td><span class="method-badge method-${(tc.method || 'GET').toLowerCase()}">${escHtml(tc.method)}</span></td><td style="font-size:12px;">${escHtml(tc.description || '-')}</td></tr>`;
        });
        html += '</tbody></table></div>';
    }
    div.innerHTML = html;
}

// ===== Change Monitor =====
async function takeSnapshot() {
    try {
        const result = await apiCall('/api/monitor/snapshot', { method: 'POST', body: JSON.stringify({}) });
        showToast(result.message || '快照已创建', 'success');
        loadSnapshots();
    } catch (e) { showToast(e.message, 'error'); }
}

async function loadSnapshots() {
    try {
        const data = await apiCall('/api/monitor/snapshots');
        const div = document.getElementById('monitor-snapshots');
        const snaps = data.snapshots || [];
        if (!snaps.length) { div.innerHTML = '<div style="color:var(--text-muted)">暂无快照</div>'; return; }
        let html = '<div class="table-wrap"><table class="data-table"><thead><tr><th>#</th><th>时间</th><th>接口数</th><th>Hash</th></tr></thead><tbody>';
        snaps.forEach((s, i) => {
            const time = new Date(s.timestamp * 1000).toLocaleString();
            html += `<tr><td>${i + 1}</td><td style="font-size:12px;">${time}</td><td>${s.count}</td><td style="font-size:11px;font-family:monospace;">${s.hash || '-'}</td></tr>`;
        });
        html += '</tbody></table></div>';
        div.innerHTML = html;
    } catch (e) { console.error(e); }
}

async function checkChanges() {
    try {
        const result = await apiCall('/api/monitor/changes');
        const div = document.getElementById('monitor-changes');
        if (!result.changed) {
            div.innerHTML = `<div style="color:var(--text-muted)">${escHtml(result.message || '无变更')}</div>`;
            return;
        }
        let html = `<div style="display:flex;gap:16px;margin-bottom:12px;">
            <div class="stat-card"><div class="stat-info"><span class="stat-value" style="color:var(--success)">${result.previous_count || 0}</span><span class="stat-label">上次</span></div></div>
            <div class="stat-card"><div class="stat-info"><span class="stat-value" style="color:var(--info)">${result.current_count || 0}</span><span class="stat-label">当前</span></div></div>
        </div>`;
        const diff = result.current_count - result.previous_count;
        const diffColor = diff > 0 ? 'var(--success)' : diff < 0 ? 'var(--danger)' : 'var(--text-muted)';
        html += `<div style="color:${diffColor};font-size:14px;margin-bottom:8px;">变更: ${diff > 0 ? '+' : ''}${diff} 个接口</div>`;
        div.innerHTML = html;
    } catch (e) { showToast(e.message, 'error'); }
}

// ===== Traffic Analysis =====
async function analyzeTraffic() {
    try {
        const result = await apiCall('/api/traffic/analyze', { method: 'POST' });
        showTrafficResults(result);
    } catch (e) { showToast(e.message, 'error'); }
}

function showTrafficResults(results) {
    const div = document.getElementById('traffic-results');
    if (!results || results.error) { div.innerHTML = '<div style="color:var(--danger)">' + escHtml(results?.error || '无数据') + '</div>'; return; }
    let html = '';
    const s = results.summary || {};
    // Summary cards
    html += `<div style="display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;">
        <div class="stat-card"><div class="stat-info"><span class="stat-value">${results.total_requests || 0}</span><span class="stat-label">总请求数</span></div></div>
        <div class="stat-card"><div class="stat-info"><span class="stat-value">${s.total_endpoints || 0}</span><span class="stat-label">发现端点</span></div></div>
        <div class="stat-card"><div class="stat-info"><span class="stat-value">${s.total_auth_tokens || 0}</span><span class="stat-label">认证令牌</span></div></div>
        <div class="stat-card"><div class="stat-info"><span class="stat-value" style="color:var(--danger)">${s.total_sensitive || 0}</span><span class="stat-label">敏感数据</span></div></div>
    </div>`;
    // Findings
    const findings = results.findings || [];
    if (findings.length) {
        html += '<h4 style="margin:8px 0;">安全发现:</h4>';
        html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>类型</th><th>严重性</th><th>描述</th></tr></thead><tbody>';
        findings.forEach(f => {
            html += `<tr><td>${escHtml(f.type)}</td><td><span class="risk-badge risk-${f.severity}">${escHtml(f.severity)}</span></td><td>${escHtml(f.description)}</td></tr>`;
        });
        html += '</tbody></table></div>';
    }
    // Auth tokens
    const tokens = results.auth_tokens || [];
    if (tokens.length) {
        html += '<h4 style="margin:12px 0 8px;">认证令牌:</h4>';
        html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>类型</th><th>来源</th><th>Header</th><th>值</th></tr></thead><tbody>';
        tokens.slice(0, 20).forEach(t => {
            html += `<tr><td>${escHtml(t.type)}</td><td>${escHtml(t.source)}</td><td><code>${escHtml(t.header)}</code></td><td style="font-size:11px;font-family:monospace;">${escHtml(t.value)}</td></tr>`;
        });
        html += '</tbody></table></div>';
    }
    // Sensitive data
    const sensitive = results.sensitive_data || [];
    if (sensitive.length) {
        html += '<h4 style="margin:12px 0 8px;">敏感数据:</h4>';
        html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>类型</th><th>脱敏值</th><th>来源</th></tr></thead><tbody>';
        sensitive.slice(0, 30).forEach(s => {
            html += `<tr><td><span class="risk-badge risk-high">${escHtml(s.type)}</span></td><td style="font-family:monospace;font-size:11px;">${escHtml(s.value)}</td><td style="font-size:12px;">${escHtml(s.context + ': ' + s.location)}</td></tr>`;
        });
        html += '</tbody></table></div>';
    }
    // API endpoints
    const endpoints = results.endpoints_found || [];
    if (endpoints.length) {
        html += '<h4 style="margin:12px 0 8px;">发现的API端点:</h4>';
        html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>方法</th><th>路径</th><th>状态</th><th>参数</th></tr></thead><tbody>';
        endpoints.slice(0, 30).forEach(ep => {
            html += `<tr><td><span class="method-badge method-${(ep.method || 'GET').toLowerCase()}">${escHtml(ep.method)}</span></td>
                <td style="font-size:12px;">${escHtml(ep.path)}</td><td>${ep.status_code || '-'}</td><td style="font-size:12px;">${escHtml((ep.params || []).join(', '))}</td></tr>`;
        });
        html += '</tbody></table></div>';
    }
    div.innerHTML = html || '<div style="color:var(--text-muted)">无分析结果</div>';
}

// ===== Request History =====
async function loadHistory() {
    const container = document.getElementById('req-history-list');
    if (!container) return;
    try {
        const data = await apiCall('/api/history');
        const items = data.history || [];
        if (!items.length) {
            container.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:12px 0;">暂无请求历史</div>';
            return;
        }
        let html = '<div style="max-height:400px;overflow-y:auto;">';
        items.forEach(h => {
            const methodCls = 'method-' + (h.method || 'GET').toLowerCase();
            const time = h.created_at ? h.created_at.substring(11, 19) : '';
            html += `<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px;">
                <span class="method-badge ${methodCls}" style="min-width:48px;text-align:center;">${escHtml(h.method)}</span>
                <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escHtml(h.url)}">${escHtml(h.url)}</span>
                ${h.status_code ? `<span style="color:${h.status_code < 400 ? 'var(--success)' : 'var(--danger)'}">${h.status_code}</span>` : ''}
                ${h.elapsed != null ? `<span style="color:var(--text-muted)">${h.elapsed}ms</span>` : ''}
                <span style="color:var(--text-muted);min-width:60px;text-align:right;">${time}</span>
                <button class="btn btn-sm btn-outline" style="padding:2px 6px;font-size:11px;" onclick="deleteHistory(${h.id})">✕</button>
            </div>`;
        });
        html += '</div>';
        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = '<div style="color:var(--danger);font-size:13px;">加载失败</div>';
    }
}

async function clearHistory() {
    try {
        await apiCall('/api/history', { method: 'DELETE' });
        showToast('历史已清空', 'success');
        loadHistory();
    } catch (e) { showToast(e.message, 'error'); }
}

async function deleteHistory(id) {
    try {
        await apiCall(`/api/history/${id}`, { method: 'DELETE' });
        loadHistory();
    } catch (e) { showToast(e.message, 'error'); }
}

// ===== Favorites List =====
async function loadFavorites() {
    const container = document.getElementById('req-favorites-list');
    if (!container) return;
    try {
        const data = await apiCall('/api/favorites');
        const items = data.favorites || [];
        if (!items.length) {
            container.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:12px 0;">暂无收藏接口</div>';
            return;
        }
        let html = '<div style="max-height:300px;overflow-y:auto;">';
        items.forEach(f => {
            const methodCls = 'method-' + (f.method || 'GET').toLowerCase();
            html += `<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px;">
                <span style="cursor:pointer;" onclick="toggleFavorite('${escHtml(f.url)}','${escHtml(f.method)}','${escHtml(f.label || '')}')" title="取消收藏">★</span>
                <span class="method-badge ${methodCls}" style="min-width:48px;text-align:center;">${escHtml(f.method)}</span>
                <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escHtml(f.url)}">${escHtml(f.label || f.url)}</span>
            </div>`;
        });
        html += '</div>';
        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = '<div style="color:var(--danger);font-size:13px;">加载失败</div>';
    }
}

// ===== Sitemap Filter =====
function filterSitemap(query) {
    const container = document.getElementById('sitemap-tree');
    if (!container) return;
    query = (query || '').toLowerCase().trim();
    if (!query) {
        if (typeof sitemapData !== 'undefined' && sitemapData) renderSitemapTree(sitemapData);
        return;
    }
    container.querySelectorAll('.sitemap-node').forEach(node => {
        const label = node.querySelector('.sitemap-label');
        const text = label ? label.textContent.toLowerCase() : '';
        const title = label ? (label.getAttribute('title') || '').toLowerCase() : '';
        const match = text.includes(query) || title.includes(query);
        node.style.display = match ? '' : 'none';
        if (match) {
            let p = node.parentElement;
            while (p && p !== container) {
                if (p.tagName === 'DETAILS') p.open = true;
                if (p.tagName === 'LI' || p.tagName === 'UL') p.style.display = '';
                p = p.parentElement;
            }
        }
    });
}

// ===== Dependency Graph =====
// ===== Dependency Graph (Force-directed) =====
let _dgNodes = [], _dgEdges = [], _dgAnim = null, _dgDrag = null;

async function loadDepGraph() {
    const info = document.getElementById('dep-graph-info');
    const canvas = document.getElementById('dep-graph-canvas');
    if (!canvas) return;
    if (info) info.textContent = '加载中...';
    try {
        const data = await apiCall('/api/graph/data');
        _dgNodes = (data.nodes || []).map((n, i) => ({ ...n, x: 0, y: 0, vx: 0, vy: 0 }));
        _dgEdges = data.edges || [];
        if (info) info.textContent = `${_dgNodes.length} 个节点, ${_dgEdges.length} 条边`;
        if (!_dgNodes.length) {
            const ctx = canvas.getContext('2d');
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#8b949e';
            ctx.font = '13px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('暂无数据，请先进行网站扫描', canvas.width / 2, canvas.height / 2);
            return;
        }
        _dgInitLayout(canvas);
        _dgStartSimulation(canvas);
    } catch (e) {
        if (info) info.textContent = '加载失败';
        showToast(e.message, 'error');
    }
}

function _dgInitLayout(canvas) {
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width * (window.devicePixelRatio || 1);
    canvas.height = rect.height * (window.devicePixelRatio || 1);
    const W = canvas.width, H = canvas.height;
    // Initialize positions randomly in center area
    _dgNodes.forEach(n => {
        n.x = W / 2 + (Math.random() - 0.5) * W * 0.6;
        n.y = H / 2 + (Math.random() - 0.5) * H * 0.6;
        n.vx = 0; n.vy = 0;
    });
}

function _dgStartSimulation(canvas) {
    if (_dgAnim) cancelAnimationFrame(_dgAnim);
    let alpha = 1.0;
    const alphaDecay = 0.02, alphaMin = 0.001;
    const dpr = window.devicePixelRatio || 1;

    function tick() {
        if (alpha < alphaMin) { _dgDraw(canvas, dpr); return; }
        _dgSimulate(alpha);
        _dgDraw(canvas, dpr);
        alpha *= (1 - alphaDecay);
        _dgAnim = requestAnimationFrame(tick);
    }
    tick();
}

function _dgSimulate(alpha) {
    const W = _dgNodes.length ? document.getElementById('dep-graph-canvas').width : 900;
    const H = _dgNodes.length ? document.getElementById('dep-graph-canvas').height : 500;
    const cx = W / 2, cy = H / 2;
    const N = _dgNodes.length;
    if (!N) return;

    // Build adjacency
    const adj = new Map();
    _dgNodes.forEach(n => adj.set(n.id, []));
    _dgEdges.forEach(e => {
        if (adj.has(e.source)) adj.get(e.source).push(e.target);
        if (adj.has(e.target)) adj.get(e.target).push(e.source); // undirected for layout
    });

    // Repulsion (Barnes-Hut simplified: brute force for < 500 nodes)
    const repulse = 800 * alpha;
    for (let i = 0; i < N; i++) {
        for (let j = i + 1; j < N; j++) {
            let dx = _dgNodes[j].x - _dgNodes[i].x;
            let dy = _dgNodes[j].y - _dgNodes[i].y;
            let dist = Math.sqrt(dx * dx + dy * dy) || 1;
            let force = repulse / (dist * dist);
            let fx = (dx / dist) * force;
            let fy = (dy / dist) * force;
            _dgNodes[i].vx -= fx; _dgNodes[i].vy -= fy;
            _dgNodes[j].vx += fx; _dgNodes[j].vy += fy;
        }
    }

    // Attraction (edges = springs)
    const edgeIds = new Map();
    _dgNodes.forEach((n, i) => edgeIds.set(n.id, i));
    const springLen = Math.min(W, H) / (Math.sqrt(N) + 1);
    const springStrength = 0.05 * alpha;
    _dgEdges.forEach(e => {
        const si = edgeIds.get(e.source), ti = edgeIds.get(e.target);
        if (si === undefined || ti === undefined) return;
        let dx = _dgNodes[ti].x - _dgNodes[si].x;
        let dy = _dgNodes[ti].y - _dgNodes[si].y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 1;
        let force = (dist - springLen) * springStrength;
        let fx = (dx / dist) * force;
        let fy = (dy / dist) * force;
        _dgNodes[si].vx += fx; _dgNodes[si].vy += fy;
        _dgNodes[ti].vx -= fx; _dgNodes[ti].vy -= fy;
    });

    // Gravity toward center
    _dgNodes.forEach(n => {
        n.vx += (cx - n.x) * 0.003 * alpha;
        n.vy += (cy - n.y) * 0.003 * alpha;
    });

    // Apply velocity with damping
    const damping = 0.6;
    _dgNodes.forEach(n => {
        n.vx *= damping;
        n.vy *= damping;
        n.x += n.vx;
        n.y += n.vy;
        // Keep in bounds
        const pad = 30;
        n.x = Math.max(pad, Math.min(W - pad, n.x));
        n.y = Math.max(pad, Math.min(H - pad, n.y));
    });
}

function _dgDraw(canvas, dpr) {
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);

    // Build position lookup
    const pos = {};
    _dgNodes.forEach(n => pos[n.id] = n);

    // Draw edges
    ctx.strokeStyle = 'rgba(139,148,158,0.3)';
    ctx.lineWidth = 1.2 * dpr;
    ctx.beginPath();
    _dgEdges.forEach(e => {
        const s = pos[e.source], t = pos[e.target];
        if (!s || !t) return;
        ctx.moveTo(s.x, s.y);
        ctx.lineTo(t.x, t.y);
    });
    ctx.stroke();

    // Draw arrowheads
    _dgEdges.forEach(e => {
        const s = pos[e.source], t = pos[e.target];
        if (!s || !t) return;
        const dx = t.x - s.x, dy = t.y - s.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const nr = 14 * dpr; // node radius offset
        const ax = t.x - (dx / dist) * nr;
        const ay = t.y - (dy / dist) * nr;
        const angle = Math.atan2(dy, dx);
        ctx.fillStyle = 'rgba(139,148,158,0.5)';
        ctx.beginPath();
        ctx.moveTo(ax, ay);
        ctx.lineTo(ax - 8 * dpr * Math.cos(angle - 0.4), ay - 8 * dpr * Math.sin(angle - 0.4));
        ctx.lineTo(ax - 8 * dpr * Math.cos(angle + 0.4), ay - 8 * dpr * Math.sin(angle + 0.4));
        ctx.closePath();
        ctx.fill();
    });

    // Draw nodes
    _dgNodes.forEach(n => {
        const r = 12 * dpr;
        // Circle
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = '#161b22';
        ctx.fill();
        const cat = (n.category || '').toLowerCase();
        let strokeColor = '#58a6ff'; // default blue
        if (cat.includes('auth') || cat.includes('admin')) strokeColor = '#f85149';
        else if (cat.includes('api') || cat.includes('data')) strokeColor = '#3fb950';
        else if (cat.method === 'POST' || n.method === 'POST') strokeColor = '#d29922';
        ctx.strokeStyle = strokeColor;
        ctx.lineWidth = 2 * dpr;
        ctx.stroke();

        // Label
        const label = n.label || n.id || '';
        const short = label.length > 18 ? label.slice(0, 16) + '..' : label;
        ctx.fillStyle = '#c9d1d9';
        ctx.font = `${10 * dpr}px sans-serif`;
        ctx.textAlign = 'center';
        ctx.fillText(short, n.x, n.y + r + 12 * dpr);
    });
}

// Drag interaction
(function() {
    const container = document.getElementById('dep-graph-container');
    const canvas = document.getElementById('dep-graph-canvas');
    if (!canvas) return;

    function getMousePos(e) {
        const rect = canvas.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;
        return {
            x: (e.clientX - rect.left) * dpr,
            y: (e.clientY - rect.top) * dpr,
        };
    }

    function findNode(pos) {
        for (let i = _dgNodes.length - 1; i >= 0; i--) {
            const n = _dgNodes[i];
            const dx = n.x - pos.x, dy = n.y - pos.y;
            if (dx * dx + dy * dy < 225) return n; // 15px radius hit
        }
        return null;
    }

    canvas.addEventListener('mousedown', e => {
        const pos = getMousePos(e);
        const node = findNode(pos);
        if (node) {
            _dgDrag = { node, offsetX: node.x - pos.x, offsetY: node.y - pos.y };
            canvas.style.cursor = 'grabbing';
            if (_dgAnim) cancelAnimationFrame(_dgAnim);
        }
    });

    canvas.addEventListener('mousemove', e => {
        const pos = getMousePos(e);
        if (_dgDrag) {
            _dgDrag.node.x = pos.x + _dgDrag.offsetX;
            _dgDrag.node.y = pos.y + _dgDrag.offsetY;
            _dgDrag.node.vx = 0;
            _dgDrag.node.vy = 0;
            const dpr = window.devicePixelRatio || 1;
            _dgDraw(canvas, dpr);
        } else {
            // Tooltip
            const node = findNode(pos);
            const tip = document.getElementById('dep-graph-tooltip');
            if (node && tip) {
                tip.style.display = 'block';
                tip.style.left = (e.clientX - container.getBoundingClientRect().left + 12) + 'px';
                tip.style.top = (e.clientY - container.getBoundingClientRect().top - 8) + 'px';
                tip.textContent = (node.id || '') + (node.method ? ` [${node.method}]` : '');
            } else if (tip) {
                tip.style.display = 'none';
            }
        }
    });

    canvas.addEventListener('mouseup', () => {
        if (_dgDrag) {
            _dgDrag = null;
            canvas.style.cursor = 'grab';
            // Resume simulation briefly
            _dgStartSimulation(canvas);
        }
    });

    canvas.addEventListener('mouseleave', () => {
        const tip = document.getElementById('dep-graph-tooltip');
        if (tip) tip.style.display = 'none';
    });
})();

function depGraphStopFit() {
    const canvas = document.getElementById('dep-graph-canvas');
    if (canvas && _dgNodes.length) {
        _dgInitLayout(canvas);
        _dgStartSimulation(canvas);
    }
}

// ===== Login Sessions =====
let currentWinId = null;

async function openLoginWindow() {
    const urlEl = document.getElementById('session-url');
    const nameEl = document.getElementById('session-name');
    const url = (urlEl.value || '').trim();
    const name = (nameEl.value || '').trim();
    if (!url) { showToast('请输入网站地址', 'error'); return; }
    try {
        const res = await apiCall('/api/sessions/open', { method: 'POST', body: JSON.stringify({ url, name }) });
        if (res.success) {
            currentWinId = res.win_id;
            document.getElementById('session-status').style.display = '';
            document.getElementById('session-status-text').textContent = `浏览器窗口已打开 - 请在窗口中登录 ${res.domain || url}`;
            showToast(res.message, 'info');
        } else {
            showToast(res.error || '打开窗口失败', 'error');
        }
    } catch (e) { showToast(e.message, 'error'); }
}

async function captureSession() {
    if (!currentWinId) { showToast('没有活动的登录窗口', 'error'); return; }
    document.getElementById('session-status-text').textContent = '正在捕获会话...';
    try {
        const res = await apiCall(`/api/sessions/capture/${currentWinId}`, { method: 'POST' });
        if (res.success) {
            showToast(res.message, 'success');
            currentWinId = null;
            document.getElementById('session-status').style.display = 'none';
            loadSessions();
        } else {
            showToast(res.error || '捕获失败', 'error');
            document.getElementById('session-status-text').textContent = res.error || '捕获失败';
        }
    } catch (e) {
        showToast(e.message, 'error');
        document.getElementById('session-status-text').textContent = '捕获失败: ' + e.message;
    }
}

async function cancelLoginWindow() {
    if (currentWinId) {
        try { await apiCall(`/api/sessions/close/${currentWinId}`, { method: 'POST' }); } catch(e) {}
    }
    currentWinId = null;
    document.getElementById('session-status').style.display = 'none';
}

async function loadSessions() {
    const container = document.getElementById('sessions-list');
    if (!container) return;
    try {
        const data = await apiCall('/api/sessions');
        const sessions = data.sessions || [];
        if (!sessions.length) {
            container.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:20px 0;text-align:center;">暂无保存的会话</div>';
            return;
        }
        let html = '<div class="table-wrap"><table class="data-table"><thead><tr><th>名称</th><th>域名</th><th>Cookie数</th><th>时间</th><th>操作</th></tr></thead><tbody>';
        sessions.forEach(s => {
            const cookieCount = Array.isArray(s.cookies) ? s.cookies.length : 0;
            const time = s.created_at ? new Date(s.created_at * 1000).toLocaleString() : '';
            html += `<tr>
                <td>${escHtml(s.name)}</td>
                <td><code>${escHtml(s.domain)}</code></td>
                <td>${cookieCount}</td>
                <td style="font-size:12px;color:var(--text-muted)">${time}</td>
                <td>
                    <button class="btn btn-sm btn-outline" onclick="viewSessionDetail(${s.id})" style="margin-right:4px;">详情</button>
                    <button class="btn btn-sm btn-outline" onclick="deleteSession(${s.id})" style="color:var(--danger)">删除</button>
                </td>
            </tr>`;
        });
        html += '</tbody></table></div>';
        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = '<div style="color:var(--danger);font-size:13px;">加载失败</div>';
    }
}

async function viewSessionDetail(id) {
    try {
        const data = await apiCall('/api/sessions');
        const s = (data.sessions || []).find(x => x.id === id);
        if (!s) { showToast('会话不存在', 'error'); return; }
        let body = `<h4>${escHtml(s.name)}</h4>`;
        body += `<p style="font-size:12px;color:var(--text-muted)">域名: ${escHtml(s.domain)} | URL: ${escHtml(s.url || '-')}</p>`;
        const cookies = Array.isArray(s.cookies) ? s.cookies : [];
        if (cookies.length) {
            body += '<h4 style="margin-top:12px">Cookies:</h4>';
            body += '<div class="table-wrap"><table class="data-table"><thead><tr><th>名称</th><th>值</th></tr></thead><tbody>';
            cookies.forEach(c => {
                body += `<tr><td><code>${escHtml(c.name)}</code></td><td style="font-size:11px;font-family:monospace;word-break:break-all;max-width:400px;overflow:hidden;text-overflow:ellipsis;">${escHtml(c.value)}</td></tr>`;
            });
            body += '</tbody></table></div>';
        }
        const ls = s.local_storage || {};
        const lsKeys = Object.keys(ls);
        if (lsKeys.length) {
            body += '<h4 style="margin-top:12px">LocalStorage:</h4>';
            body += '<div class="table-wrap"><table class="data-table"><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>';
            lsKeys.forEach(k => {
                body += `<tr><td><code>${escHtml(k)}</code></td><td style="font-size:11px;font-family:monospace;word-break:break-all;max-width:400px;overflow:hidden;text-overflow:ellipsis;">${escHtml(ls[k])}</td></tr>`;
            });
            body += '</tbody></table></div>';
        }
        document.getElementById('modal-body').innerHTML = body;
        document.getElementById('detail-modal').classList.add('active');
    } catch (e) { showToast(e.message, 'error'); }
}

async function deleteSession(id) {
    if (!confirm('确定删除此会话？')) return;
    try {
        await apiCall(`/api/sessions/${id}`, { method: 'DELETE' });
        showToast('已删除', 'success');
        loadSessions();
    } catch (e) { showToast(e.message, 'error'); }
}

// ===== WAF Detection =====
async function startWafDetect() {
    const urlEl = document.getElementById('waf-url');
    const url = urlEl ? urlEl.value.trim() : '';
    if (!url) { showToast('请输入目标URL', 'error'); return; }

    const btn = document.getElementById('btn-waf-detect');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 检测中...'; }

    try {
        const result = await apiCall('/api/waf/detect', {
            method: 'POST',
            body: JSON.stringify({ url }),
        });
        const resDiv = document.getElementById('waf-result');
        const content = document.getElementById('waf-result-content');
        if (resDiv) resDiv.style.display = 'block';

        if (result.detected) {
            let html = `<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;">
                <span class="risk-badge risk-high" style="font-size:14px;padding:4px 12px;">WAF 已部署</span>
                <strong>${escHtml(result.waf_name)}</strong>
                <span style="color:var(--text-muted);font-size:13px;">厂商: ${escHtml(result.vendor)}</span>
                <span style="color:var(--text-muted);font-size:13px;">置信度: ${result.confidence}%</span>
            </div>`;
            if (result.evidence && result.evidence.length) {
                html += '<div style="margin-bottom:8px;"><strong>证据:</strong><ul style="margin:4px 0;padding-left:20px;font-size:13px;">';
                result.evidence.forEach(e => { html += `<li>${escHtml(e)}</li>`; });
                html += '</ul></div>';
            }
            if (result.bypass_suggestions && result.bypass_suggestions.length) {
                html += '<div><strong>建议绕过策略:</strong><ul style="margin:4px 0;padding-left:20px;font-size:13px;color:var(--accent);">';
                result.bypass_suggestions.forEach(s => { html += `<li>${escHtml(s)}</li>`; });
                html += '</ul></div>';
            }
            if (content) content.innerHTML = html;
        } else {
            if (content) content.innerHTML = '<span class="risk-badge risk-info">未检测到 WAF</span> <span style="font-size:13px;color:var(--text-muted);">目标可能未部署 WAF，或使用了无法识别的 WAF</span>';
        }
    } catch (e) {
        showToast('WAF 检测失败: ' + (e.message || ''), 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/></svg> 检测 WAF'; }
    }
}

// ===== Tech Fingerprint =====
async function startTechFingerprint() {
    const urlEl = document.getElementById('tech-url');
    const url = urlEl ? urlEl.value.trim() : '';
    if (!url) { showToast('请输入目标URL', 'error'); return; }

    const btn = document.getElementById('btn-tech-fp');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 识别中...'; }

    try {
        const result = await apiCall('/api/tech/fingerprint', {
            method: 'POST',
            body: JSON.stringify({ url }),
        });
        const resDiv = document.getElementById('tech-result');
        const content = document.getElementById('tech-result-content');
        if (resDiv) resDiv.style.display = 'block';

        const techs = result.technologies || [];
        if (techs.length) {
            let html = '<table class="data-table"><thead><tr><th>技术</th><th>版本</th><th>类别</th><th>置信度</th><th>证据</th></tr></thead><tbody>';
            techs.forEach(t => {
                const conf = Math.round((t.confidence || 0) * 100);
                const badge = conf >= 80 ? 'risk-high' : conf >= 50 ? 'risk-medium' : 'risk-info';
                html += `<tr>
                    <td><strong>${escHtml(t.name)}</strong></td>
                    <td>${escHtml(t.version || '-')}</td>
                    <td>${escHtml(t.category || '-')}</td>
                    <td><span class="risk-badge ${badge}">${conf}%</span></td>
                    <td style="font-size:12px;">${escHtml(t.evidence || '-')}</td>
                </tr>`;
            });
            html += '</tbody></table>';
            if (content) content.innerHTML = html;
        } else {
            if (content) content.innerHTML = '<div style="color:var(--text-muted);padding:12px 0;">未识别到明确的技术栈信息</div>';
        }
    } catch (e) {
        showToast('技术栈识别失败: ' + (e.message || ''), 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg> 识别技术栈'; }
    }
}

// ===== Payload Evasion =====
async function startEvasionTest() {
    const payloadEl = document.getElementById('evasion-payload');
    const wafNameEl = document.getElementById('evasion-waf-name');
    const payload = payloadEl ? payloadEl.value.trim() : '';
    if (!payload) { showToast('请输入 payload', 'error'); return; }

    const wafName = wafNameEl ? wafNameEl.value.trim() : '';
    const btn = document.getElementById('btn-evasion');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 生成中...'; }

    try {
        const body = { payload };
        if (wafName) {
            body.waf_info = { detected: true, waf_name: wafName };
        }
        const result = await apiCall('/api/evasion/test', {
            method: 'POST',
            body: JSON.stringify(body),
        });
        const resDiv = document.getElementById('evasion-result');
        const content = document.getElementById('evasion-result-content');
        if (resDiv) resDiv.style.display = 'block';

        const evaded = result.evaded || [];
        if (evaded.length) {
            let html = `<div style="margin-bottom:8px;font-size:13px;color:var(--text-muted);">原始 Payload: <code>${escHtml(result.payload)}</code></div>`;
            html += '<table class="data-table"><thead><tr><th>策略</th><th>编码后的 Payload</th><th>说明</th></tr></thead><tbody>';
            evaded.forEach(e => {
                html += `<tr>
                    <td><strong>${escHtml(e.strategy)}</strong></td>
                    <td><code style="word-break:break-all;font-size:12px;">${escHtml(e.payload)}</code></td>
                    <td style="font-size:12px;">${escHtml(e.description || '')}</td>
                </tr>`;
            });
            html += '</tbody></table>';
            if (content) content.innerHTML = html;
        } else {
            if (content) content.innerHTML = '<div style="color:var(--text-muted);padding:12px 0;">无可生成的绕过变体</div>';
        }
    } catch (e) {
        showToast('绕过测试失败: ' + (e.message || ''), 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '生成绕过 Payload'; }
    }
}

// ===== Backup Scanner =====
let backupPollTimer = null;
async function startBackupScan() {
    const url = document.getElementById('backup-url')?.value.trim();
    if (!url) { showToast('请输入目标URL', 'error'); return; }
    const btn = document.getElementById('btn-backup');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 探测中...'; }
    try {
        await apiCall('/api/backup/scan', { method: 'POST', body: JSON.stringify({ url }) });
        const prog = document.getElementById('backup-progress');
        if (prog) prog.style.display = 'block';
        if (backupPollTimer) clearInterval(backupPollTimer);
        backupPollTimer = setInterval(async () => {
            try {
                const s = await apiCall('/api/backup/progress');
                const fill = document.getElementById('backup-progress-fill');
                const msg = document.getElementById('backup-progress-msg');
                if (fill) fill.style.width = (s.progress || 0) + '%';
                if (msg) msg.textContent = s.message || '';
                if (!s.active) {
                    clearInterval(backupPollTimer);
                    if (btn) { btn.disabled = false; btn.innerHTML = '探测备份文件'; }
                    renderBackupResults(s.results);
                }
            } catch (e) {}
        }, 1500);
    } catch (e) {
        showToast(e.message, 'error');
        if (btn) { btn.disabled = false; btn.innerHTML = '探测备份文件'; }
    }
}

function renderBackupResults(data) {
    const div = document.getElementById('backup-result');
    const content = document.getElementById('backup-result-content');
    if (!div || !data) return;
    div.style.display = 'block';
    const findings = data.findings || [];
    if (!findings.length) {
        content.innerHTML = '<div style="color:var(--text-muted);padding:8px 0;">未发现备份文件泄露</div>';
        return;
    }
    let html = `<div style="margin-bottom:8px;font-size:13px;">发现 <strong>${findings.length}</strong> 个备份文件</div>`;
    html += '<table class="data-table"><thead><tr><th>路径</th><th>状态码</th><th>大小</th><th>严重程度</th><th>说明</th></tr></thead><tbody>';
    findings.forEach(f => {
        html += `<tr><td title="${escHtml(f.url)}">${escHtml(f.path)}</td><td>${f.status_code}</td><td>${f.size}</td>
            <td><span class="risk-badge risk-${f.severity}">${f.severity}</span></td><td style="font-size:12px;">${escHtml(f.description)}</td></tr>`;
    });
    html += '</tbody></table>';
    content.innerHTML = html;
}

// ===== Cloud Storage Scanner =====
async function startCloudScan() {
    const url = document.getElementById('cloud-url')?.value.trim();
    if (!url) { showToast('请输入目标URL', 'error'); return; }
    const btn = document.getElementById('btn-cloud');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 检测中...'; }
    try {
        const data = await apiCall('/api/cloud/scan', { method: 'POST', body: JSON.stringify({ url }) });
        const div = document.getElementById('cloud-result');
        const content = document.getElementById('cloud-result-content');
        if (div) div.style.display = 'block';
        const findings = data.findings || [];
        if (!findings.length) {
            content.innerHTML = '<div style="color:var(--text-muted);padding:8px 0;">未发现云存储泄露</div>';
        } else {
            let html = `<div style="margin-bottom:8px;font-size:13px;">发现 <strong>${findings.length}</strong> 个云存储引用</div>`;
            html += '<table class="data-table"><thead><tr><th>提供商</th><th>桶名</th><th>公开访问</th><th>详情</th><th>严重程度</th></tr></thead><tbody>';
            findings.forEach(f => {
                const pubBadge = f.public ? '<span class="risk-badge risk-critical">公开</span>' : '<span class="risk-badge risk-info">受限</span>';
                html += `<tr><td>${escHtml(f.provider)}</td><td title="${escHtml(f.url)}">${escHtml(f.bucket)}</td><td>${pubBadge}</td>
                    <td style="font-size:12px;">${escHtml(f.details)}</td><td><span class="risk-badge risk-${f.severity}">${f.severity}</span></td></tr>`;
            });
            html += '</tbody></table>';
            content.innerHTML = html;
        }
    } catch (e) { showToast(e.message, 'error'); }
    finally { if (btn) { btn.disabled = false; btn.innerHTML = '检测云存储'; } }
}

// ===== 403 Bypass =====
let forbiddenPollTimer = null;
async function startForbiddenBypass() {
    const url = document.getElementById('forbidden-url')?.value.trim();
    if (!url) { showToast('请输入目标URL', 'error'); return; }
    const btn = document.getElementById('btn-forbidden');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 测试中...'; }
    try {
        await apiCall('/api/forbidden/scan', { method: 'POST', body: JSON.stringify({ url }) });
        const prog = document.getElementById('forbidden-progress');
        if (prog) prog.style.display = 'block';
        if (forbiddenPollTimer) clearInterval(forbiddenPollTimer);
        forbiddenPollTimer = setInterval(async () => {
            try {
                const s = await apiCall('/api/forbidden/progress');
                const fill = document.getElementById('forbidden-progress-fill');
                const msg = document.getElementById('forbidden-progress-msg');
                if (fill) fill.style.width = (s.progress || 0) + '%';
                if (msg) msg.textContent = s.message || '';
                if (!s.active) {
                    clearInterval(forbiddenPollTimer);
                    if (btn) { btn.disabled = false; btn.innerHTML = '测试绕过'; }
                    renderForbiddenResults(s.results);
                }
            } catch (e) {}
        }, 1500);
    } catch (e) {
        showToast(e.message, 'error');
        if (btn) { btn.disabled = false; btn.innerHTML = '测试绕过'; }
    }
}

function renderForbiddenResults(data) {
    const div = document.getElementById('forbidden-result');
    const content = document.getElementById('forbidden-result-content');
    if (!div || !data) return;
    div.style.display = 'block';
    const bypasses = data.bypasses || [];
    let html = `<div style="margin-bottom:8px;font-size:13px;">原始状态码: <strong>${data.original_status}</strong> | 可行绕过: <strong>${bypasses.length}</strong></div>`;
    if (!bypasses.length) {
        html += '<div style="color:var(--text-muted);padding:8px 0;">未发现可行的绕过策略</div>';
    } else {
        html += '<table class="data-table"><thead><tr><th>策略</th><th>状态码</th><th>方法</th><th>响应大小</th></tr></thead><tbody>';
        bypasses.forEach(b => {
            html += `<tr><td><span class="risk-badge risk-high">绕过成功</span> ${escHtml(b.strategy)}</td>
                <td><strong>${b.status_code}</strong></td><td>${b.method}</td><td>${b.body_size}</td></tr>`;
        });
        html += '</tbody></table>';
    }
    content.innerHTML = html;
}

// ===== Wayback Scanner =====
let waybackPollTimer = null;
async function startWaybackScan() {
    const url = document.getElementById('wayback-url')?.value.trim();
    if (!url) { showToast('请输入目标域名', 'error'); return; }
    const btn = document.getElementById('btn-wayback');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 查询中...'; }
    try {
        await apiCall('/api/wayback/scan', { method: 'POST', body: JSON.stringify({ url }) });
        const prog = document.getElementById('wayback-progress');
        if (prog) prog.style.display = 'block';
        if (waybackPollTimer) clearInterval(waybackPollTimer);
        waybackPollTimer = setInterval(async () => {
            try {
                const s = await apiCall('/api/wayback/progress');
                const fill = document.getElementById('wayback-progress-fill');
                const msg = document.getElementById('wayback-progress-msg');
                if (fill) fill.style.width = (s.progress || 0) + '%';
                if (msg) msg.textContent = s.message || '';
                if (!s.active) {
                    clearInterval(waybackPollTimer);
                    if (btn) { btn.disabled = false; btn.innerHTML = '查询历史接口'; }
                    renderWaybackResults(s.results);
                }
            } catch (e) {}
        }, 2000);
    } catch (e) {
        showToast(e.message, 'error');
        if (btn) { btn.disabled = false; btn.innerHTML = '查询历史接口'; }
    }
}

function renderWaybackResults(data) {
    const div = document.getElementById('wayback-result');
    const content = document.getElementById('wayback-result-content');
    if (!div || !data) return;
    div.style.display = 'block';
    let html = `<div style="margin-bottom:8px;font-size:13px;">
        历史 URL 总数: <strong>${data.total_urls}</strong> |
        API 端点: <strong>${(data.api_urls||[]).length}</strong> |
        敏感路径: <strong>${(data.sensitive_urls||[]).length}</strong>
    </div>`;
    const apis = (data.api_urls || []).slice(0, 50);
    if (apis.length) {
        html += '<div style="margin-bottom:12px;"><strong>发现的 API 端点:</strong><div style="max-height:200px;overflow-y:auto;margin-top:4px;font-size:12px;font-family:monospace;background:var(--bg-secondary);padding:8px;border-radius:4px;">';
        apis.forEach(u => { html += `<div style="padding:2px 0;">${escHtml(u)}</div>`; });
        html += '</div></div>';
    }
    const sensitive = (data.sensitive_urls || []).slice(0, 20);
    if (sensitive.length) {
        html += '<div><strong>敏感路径:</strong><div style="max-height:150px;overflow-y:auto;margin-top:4px;font-size:12px;font-family:monospace;background:var(--bg-secondary);padding:8px;border-radius:4px;">';
        sensitive.forEach(u => { html += `<div style="padding:2px 0;color:var(--danger);">${escHtml(u)}</div>`; });
        html += '</div></div>';
    }
    content.innerHTML = html;
}

// ===== OAST 带外检测 =====
let oastPollTimer = null;
async function startOastScan() {
    const url = document.getElementById('oast-url')?.value.trim();
    const param = document.getElementById('oast-param')?.value.trim() || 'id';
    const method = document.getElementById('oast-method')?.value || 'GET';
    if (!url) { showToast('请输入目标URL', 'error'); return; }
    const btn = document.getElementById('btn-oast');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 检测中...'; }
    try {
        await apiCall('/api/oast/scan', { method: 'POST', body: JSON.stringify({ url, param, method }) });
        const prog = document.getElementById('oast-progress');
        if (prog) prog.style.display = 'block';
        if (oastPollTimer) clearInterval(oastPollTimer);
        oastPollTimer = setInterval(async () => {
            try {
                const s = await apiCall('/api/oast/progress');
                const fill = document.getElementById('oast-progress-fill');
                const msg = document.getElementById('oast-progress-msg');
                if (fill) fill.style.width = (s.progress || 0) + '%';
                if (msg) msg.textContent = s.message || '';
                if (!s.active) {
                    clearInterval(oastPollTimer);
                    if (btn) { btn.disabled = false; btn.innerHTML = '开始检测'; }
                    renderOastResults(s.results);
                }
            } catch (e) {}
        }, 2000);
    } catch (e) {
        showToast(e.message, 'error');
        if (btn) { btn.disabled = false; btn.innerHTML = '开始检测'; }
    }
}

function renderOastResults(data) {
    const div = document.getElementById('oast-result');
    const content = document.getElementById('oast-result-content');
    if (!div || !data) return;
    div.style.display = 'block';
    let html = `<div style="margin-bottom:8px;font-size:13px;">
        回调域名: <strong>${escHtml(data.callback_base || '')}</strong> |
        已发出 Token: <strong>${(data.issued_tokens || []).length}</strong>
    </div>`;
    if (data.note) html += `<p style="font-size:13px;color:var(--warning);margin-bottom:8px;">${escHtml(data.note)}</p>`;
    const tokens = data.issued_tokens || [];
    if (tokens.length) {
        html += '<div style="font-size:12px;font-family:monospace;background:var(--bg-secondary);padding:8px;border-radius:4px;max-height:200px;overflow-y:auto;">';
        tokens.forEach(t => {
            html += `<div style="padding:2px 0;">[${escHtml(t.type || '')}] ${escHtml(t.url || '')}?${escHtml(t.param || '')}=...</div>`;
        });
        html += '</div>';
    }
    content.innerHTML = html;
}

// ===== 模板引擎 =====
async function startTemplateScan() {
    const url = document.getElementById('template-url')?.value.trim();
    if (!url) { showToast('请输入目标URL', 'error'); return; }
    const btn = document.getElementById('btn-template');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 执行中...'; }
    try {
        const data = await apiCall('/api/templates/run', { method: 'POST', body: JSON.stringify({ url }) });
        const div = document.getElementById('template-result');
        const content = document.getElementById('template-result-content');
        if (div) div.style.display = 'block';
        let html = `<div style="margin-bottom:8px;font-size:13px;">
            执行模板: <strong>${data.total_templates || 0}</strong> |
            命中: <strong style="color:var(--danger);">${data.matched_count || 0}</strong>
        </div>`;
        const results = data.results || [];
        const matched = results.filter(r => r.matched);
        if (matched.length) {
            matched.forEach(r => {
                html += `<div class="card" style="margin-bottom:6px;padding:10px;border-left:3px solid var(--danger);">
                    <div style="font-weight:600;font-size:14px;">${escHtml(r.name || r.template_id)}</div>
                    <div style="font-size:12px;color:var(--text-muted);margin-bottom:4px;">严重程度: ${escHtml(r.severity || '')}</div>`;
                (r.matches || []).forEach(m => {
                    html += `<div style="font-size:12px;padding:2px 0;font-family:monospace;">${escHtml(m.url)} [${m.status_code}]</div>`;
                });
                html += '</div>';
            });
        } else {
            html += '<p style="color:var(--success);font-size:13px;">未发现匹配项</p>';
        }
        if (content) content.innerHTML = html;
        showToast(`模板检测完成，${matched.length} 项命中`, matched.length ? 'warning' : 'success');
    } catch (e) {
        showToast(e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '执行全部模板'; }
    }
}

// ===== 威胁情报 =====
let intelPollTimer = null;
async function startIntelQuery() {
    const domain = document.getElementById('intel-domain')?.value.trim();
    if (!domain) { showToast('请输入目标域名', 'error'); return; }
    const btn = document.getElementById('btn-intel');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 查询中...'; }
    const body = {
        domain,
        shodan_key: document.getElementById('intel-shodan-key')?.value.trim() || '',
        censys_id: document.getElementById('intel-censys-id')?.value.trim() || '',
        censys_secret: document.getElementById('intel-censys-secret')?.value.trim() || '',
        fofa_email: document.getElementById('intel-fofa-email')?.value.trim() || '',
        fofa_key: document.getElementById('intel-fofa-key')?.value.trim() || '',
    };
    try {
        await apiCall('/api/intel/query', { method: 'POST', body: JSON.stringify(body) });
        const prog = document.getElementById('intel-progress');
        if (prog) prog.style.display = 'block';
        if (intelPollTimer) clearInterval(intelPollTimer);
        intelPollTimer = setInterval(async () => {
            try {
                const s = await apiCall('/api/intel/progress');
                const fill = document.getElementById('intel-progress-fill');
                const msg = document.getElementById('intel-progress-msg');
                if (fill) fill.style.width = (s.progress || 0) + '%';
                if (msg) msg.textContent = s.message || '';
                if (!s.active) {
                    clearInterval(intelPollTimer);
                    if (btn) { btn.disabled = false; btn.innerHTML = '查询情报'; }
                    renderIntelResults(s.results);
                }
            } catch (e) {}
        }, 2000);
    } catch (e) {
        showToast(e.message, 'error');
        if (btn) { btn.disabled = false; btn.innerHTML = '查询情报'; }
    }
}

function renderIntelResults(data) {
    const div = document.getElementById('intel-result');
    const content = document.getElementById('intel-result-content');
    if (!div || !data) return;
    div.style.display = 'block';
    let html = `<div style="margin-bottom:8px;font-size:13px;">
        域名: <strong>${escHtml(data.domain || '')}</strong> |
        总结果: <strong>${data.total_findings || 0}</strong>
    </div>`;
    (data.sources || []).forEach(src => {
        html += `<div class="card" style="margin-bottom:8px;padding:10px;">
            <div style="font-weight:600;font-size:14px;margin-bottom:4px;">${escHtml(src.source || '')}</div>`;
        if (src.error) html += `<div style="font-size:12px;color:var(--danger);">${escHtml(src.error)}</div>`;
        const results = src.results || [];
        if (results.length) {
            html += '<div style="max-height:150px;overflow-y:auto;font-size:12px;font-family:monospace;background:var(--bg-secondary);padding:6px;border-radius:4px;">';
            results.slice(0, 20).forEach(r => {
                if (r.type === 'subdomain') html += `<div>${escHtml(r.value)}</div>`;
                else if (r.type === 'dns_record') html += `<div>[${escHtml(r.record_type)}] ${escHtml(r.value)}</div>`;
                else if (r.type === 'host') html += `<div>${escHtml(r.ip || r.url || '')}:${escHtml(r.port || '')} - ${escHtml(r.service || r.title || '')}</div>`;
                else if (r.type === 'info') html += `<div style="color:var(--text-muted);">${escHtml(r.value)}</div>`;
            });
            html += '</div>';
        } else if (!src.error) {
            html += '<div style="font-size:12px;color:var(--text-muted);">无结果</div>';
        }
        html += '</div>';
    });
    if (content) content.innerHTML = html;
}

// ===== JARM TLS 指纹 =====
async function startJarmFingerprint() {
    const host = document.getElementById('jarm-host')?.value.trim();
    if (!host) { showToast('请输入目标主机或URL', 'error'); return; }
    const btn = document.getElementById('btn-jarm');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 分析中...'; }
    try {
        const data = await apiCall('/api/jarm/fingerprint', { method: 'POST', body: JSON.stringify({ host }) });
        const div = document.getElementById('jarm-result');
        const content = document.getElementById('jarm-result-content');
        if (div) div.style.display = 'block';
        let html = '<div class="detail-grid">';
        html += kv('主机', data.host || host);
        html += kv('端口', data.port || 443);
        html += kv('JARM 哈希', data.jarm_hash || '-');
        html += kv('匹配服务', data.matched_service || '未匹配');
        if (data.details) {
            html += kv('探测发送', data.details.probes_sent || 0);
            html += kv('探测响应', data.details.probes_responded || 0);
        }
        html += '</div>';
        if (content) content.innerHTML = html;
        showToast('JARM 指纹分析完成', 'success');
    } catch (e) {
        showToast(e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '分析指纹'; }
    }
}

// ===== 智能扫描 (一键串联 WAF 检测 → 绕过 → 安全扫描) =====
async function startSmartScan() {
    const url = document.getElementById('security-url')?.value.trim();
    if (!url) { showToast('请先在漏洞扫描中输入目标 URL', 'error'); return; }
    showToast('智能扫描启动: WAF 检测 → 绕过策略 → 安全扫描', 'info');

    try {
        // Step 1: WAF 检测
        showToast('Step 1/3: 正在检测 WAF...', 'info');
        const wafData = await apiCall('/api/waf/detect', { method: 'POST', body: JSON.stringify({ url }) });

        if (wafData.detected) {
            showToast(`检测到 WAF: ${wafData.waf_name} (置信度 ${wafData.confidence}%)`, 'warning');
        } else {
            showToast('未检测到 WAF，将使用标准扫描', 'success');
        }

        // Step 2: 自动选择绕过策略
        if (wafData.detected) {
            showToast('Step 2/3: 生成绕过 Payload...', 'info');
            const evasionData = await apiCall('/api/evasion/test', {
                method: 'POST',
                body: JSON.stringify({ payload: "' OR 1=1 --", waf_name: wafData.waf_name }),
            });
            if (evasionData.results && evasionData.results.length > 0) {
                showToast(`已生成 ${evasionData.results.length} 种绕过策略`, 'success');
            }
        }

        // Step 3: 启动安全扫描
        showToast('Step 3/3: 启动安全扫描...', 'info');
        await apiCall('/api/security/scan', {
            method: 'POST',
            body: JSON.stringify({ url, use_endpoints: true }),
        });
        startSecurityPolling();
        showToast('智能扫描已启动', 'success');
    } catch (e) {
        showToast('智能扫描失败: ' + e.message, 'error');
    }
}

// ===== 一键侦察 (子域名 → 威胁情报 → 历史接口) =====
async function startReconFlow() {
    const domain = document.getElementById('subdomain-domain')?.value.trim();
    if (!domain) { showToast('请输入目标域名', 'error'); return; }
    showToast('一键侦察启动: 子域名 + 威胁情报 + 历史接口并行收集', 'info');

    const results = { subdomain: 0, intel: 0, wayback: 0 };

    // 并行执行三个侦察模块
    const tasks = [
        apiCall('/api/subdomain/enum', { method: 'POST', body: JSON.stringify({ domain, bruteforce: false }) })
            .then(d => { results.subdomain = (d.subdomains || []).length; })
            .catch(() => {}),
        apiCall('/api/intel/query', { method: 'POST', body: JSON.stringify({ domain }) })
            .then(d => { results.intel = (d.results || []).length; })
            .catch(() => {}),
        apiCall('/api/wayback/scan', { method: 'POST', body: JSON.stringify({ domain, max_urls: 200 }) })
            .then(d => { results.wayback = (d.urls || []).length; })
            .catch(() => {}),
    ];

    await Promise.all(tasks);
    showToast(`侦察完成: 子域名 ${results.subdomain} | 情报 ${results.intel} | 历史接口 ${results.wayback}`, 'success');

    // 自动刷新子域名结果
    try {
        const data = await apiCall('/api/subdomain/results');
        const div = document.getElementById('subdomain-result');
        const content = document.getElementById('subdomain-result-content');
        if (div) div.style.display = 'block';
        if (content && data.subdomains) {
            let html = `<p style="margin-bottom:8px;">共发现 <strong>${data.subdomains.length}</strong> 个子域名</p>`;
            html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>子域名</th><th>IP</th><th>状态</th></tr></thead><tbody>';
            for (const s of data.subdomains.slice(0, 50)) {
                html += `<tr><td>${escHtml(s.subdomain || s)}</td><td>${escHtml(s.ip || '-')}</td><td>${s.alive ? '<span class="badge badge-success">存活</span>' : '-'}</td></tr>`;
            }
            html += '</tbody></table></div>';
            content.innerHTML = html;
        }
    } catch (e) {}
}

// ===== Favicon 指纹识别 =====
async function startFaviconFp() {
    const url = document.getElementById('favicon-url')?.value.trim();
    if (!url) { showToast('请输入目标URL', 'error'); return; }
    const btn = document.getElementById('btn-favicon-fp');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> 识别中...'; }
    try {
        const data = await apiCall('/api/favicon/fingerprint', { method: 'POST', body: JSON.stringify({ url }) });
        const div = document.getElementById('favicon-result');
        const content = document.getElementById('favicon-result-content');
        if (div) div.style.display = 'block';
        let html = '<div class="detail-grid">';
        html += kv('URL', data.url || url);
        html += kv('MMH3 Hash', data.mmh3_hash || '-');
        html += kv('MD5 Hash', data.md5_hash || '-');
        html += kv('匹配框架', data.matched_framework || '未匹配');
        if (data.all_matches && data.all_matches.length > 0) {
            html += '<div style="grid-column:1/-1;"><strong>所有匹配:</strong><ul style="margin:4px 0;padding-left:20px;">';
            for (const m of data.all_matches) {
                html += `<li>${escHtml(m.framework || m.name || m)} (hash: ${escHtml(m.hash || '-')})</li>`;
            }
            html += '</ul></div>';
        }
        html += '</div>';
        if (content) content.innerHTML = html;
        showToast('Favicon 指纹识别完成', 'success');
    } catch (e) {
        showToast(e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '识别 Favicon'; }
    }
}

// ===== SARIF 导出 =====
function exportSarif() {
    window.open(API_BASE + '/api/export/sarif/file', '_blank');
}

// ===== Helpers =====
function escHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ===== Initialize =====
document.addEventListener('DOMContentLoaded', () => { loadDashboard(); });
