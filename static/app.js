const state = {
  data: null,
  changes: new Map(),
  provider: 'all',
  search: '',
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const titles = {
  dashboard: ['总览', '本机服务、出口、Proxmox 接入模型和近期 proxy 使用情况'],
  board: ['分配看板', '拖拽 VM 到目标 proxy，生成待发布变更草稿'],
  vms: ['VM 清单', '按 DHCP、租约和 mihomo 规则判断接入状态'],
  policies: ['策略与发布', '查看流量节省策略，预览或发布变更'],
};

function toast(message) {
  const node = $('#toast');
  node.textContent = message;
  node.classList.add('show');
  setTimeout(() => node.classList.remove('show'), 2600);
}

async function loadState(options = {}) {
  const { toastMessage = '已刷新当前状态' } = options;
  $('#pageSubtitle').textContent = '正在读取 live 配置...';
  const response = await fetch('/api/state', { cache: 'no-store' });
  if (!response.ok) throw new Error(`状态读取失败: ${response.status}`);
  state.data = await response.json();
  renderAll();
  if (toastMessage) toast(toastMessage);
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function renderAll() {
  renderMode();
  renderDashboard();
  renderBoard();
  renderPve1Provision();
  renderVmTable();
  renderChanges();
  renderDraftTopBar();
  renderProxyHistory();
  renderDomainBypass();
  const active = $('.nav-item.active')?.dataset.view || 'dashboard';
  setTitle(active);
}

function renderMode() {
  const badge = $('#modeBadge');
  badge.textContent = state.data.readOnly ? '只读预览' : '允许发布';
  badge.classList.toggle('write', !state.data.readOnly);
}

function renderDashboard() {
  const summary = state.data.summary;
  $('#metricProxy').textContent = summary.proxyCount;
  $('#metricManaged').textContent = summary.managedVmCount;
  $('#metricPartial').textContent = summary.partialVmCount;
  $('#metricLeases').textContent = summary.leaseCount;
  $('#generatedAt').textContent = `生成 ${new Date(state.data.generatedAt).toLocaleString()}`;

  const services = state.data.router.services || {};
  const defaultRoute = (state.data.router.routes || []).find((row) => row.startsWith('default')) || '未检测到 default route';
  $('#routerStatus').innerHTML = [
    ['mihomo', services.mihomo],
    ['dnsmasq', services.dnsmasq],
    ['nginx', services.nginx],
    ['主机名', state.data.router.hostname],
    ['默认出口', defaultRoute],
    ['配置模式', state.data.readOnly ? '只读预览' : '可发布'],
  ].map(([label, value]) => `<div class="status-pill ${value === 'active' ? 'ok' : ''}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value || '-')}</strong></div>`).join('');

  $('#hostList').innerHTML = state.data.proxmoxHosts.map((host) => `
    <article class="host-card">
      <strong>${escapeHtml(host.name)} <span>${escapeHtml(host.address)}</span></strong>
      <span>管理桥：${escapeHtml(host.managementBridge)} ｜ 代理桥：${escapeHtml(host.proxyBridge)} ｜ ${escapeHtml(host.proxySubnet)}</span>
    </article>
  `).join('');

  const maxHits = Math.max(1, ...state.data.proxies.map((proxy) => proxy.usageHits1h || 0));
  $('#usageChart').innerHTML = state.data.proxies
    .filter((proxy) => proxy.usageHits1h > 0)
    .sort((a, b) => b.usageHits1h - a.usageHits1h)
    .slice(0, 18)
    .map((proxy) => `
      <div class="bar-row">
        <strong>${escapeHtml(proxy.name)}</strong>
        <div class="bar-track"><div class="bar-fill" style="width:${Math.max(2, proxy.usageHits1h / maxHits * 100)}%"></div></div>
        <span>${proxy.usageHits1h}</span>
      </div>
    `).join('') || '<div class="warning empty">暂无最近一小时命中数据</div>';

  const warnings = state.data.warnings || [];
  $('#warnings').innerHTML = warnings.length
    ? warnings.slice(0, 24).map((item) => `<div class="warning ${item.level === 'critical' ? 'critical' : ''}">${escapeHtml(item.message)}</div>`).join('')
    : '<div class="warning empty">没有发现配置冲突。未接入 proxy 的 VM 按初始状态处理。</div>';
}

function renderBoard() {
  const board = $('#proxyBoard');
  const search = state.search.toLowerCase();
  const vmsByProxy = new Map();
  for (const vm of state.data.vms) {
    const proxyName = getVmEffectiveProxy(vm);
    if (!proxyName) continue;
    if (!vmsByProxy.has(proxyName)) vmsByProxy.set(proxyName, []);
    vmsByProxy.get(proxyName).push(vm);
  }
  const proxies = state.data.proxies
    .filter((proxy) => state.provider === 'all' || proxy.provider === state.provider)
    .filter((proxy) => !search || proxy.name.toLowerCase().includes(search) || (vmsByProxy.get(proxy.name) || []).some((vm) => vmMatches(vm, search)))
    .sort((a, b) => Number(Boolean(a.archived)) - Number(Boolean(b.archived)) || proxyNameSort(a.name, b.name));

  board.innerHTML = proxies.map((proxy, index) => {
    const vms = (vmsByProxy.get(proxy.name) || []).filter((vm) => !search || vmMatches(vm, search) || proxy.name.toLowerCase().includes(search));
    const archiveDivider = proxy.archived && !proxies[index - 1]?.archived ? '<div class="board-section-divider">已归档 proxy</div>' : '';
    return `
      ${archiveDivider}
      <section class="proxy-lane ${proxy.archived ? 'archived' : ''}" data-proxy="${escapeAttr(proxy.name)}">
        <header class="proxy-head">
          <div class="proxy-title"><strong>${escapeHtml(proxy.name)}</strong><span class="badge">${proxy.archived ? '已归档' : escapeHtml(proxy.provider)}</span></div>
          <div class="proxy-title">
            <span class="health-badge ${escapeAttr(healthStatus(proxy))}" title="${escapeAttr(healthTitle(proxy))}">${escapeHtml(healthLabel(proxy))}</span>
            <button class="mini-btn check-proxy-btn" data-proxy="${escapeAttr(proxy.name)}" title="立即检测 ${escapeAttr(proxy.name)}">检测</button>
            ${canArchiveProxy(proxy) ? `<button class="mini-btn delete-proxy-btn" data-proxy="${escapeAttr(proxy.name)}" title="归档不可用 proxy，仅影响管理界面，不修改底层配置">归档</button>` : ''}
          </div>
          <div class="proxy-meta">${escapeHtml(proxy.type)} ｜ ${escapeHtml(proxy.server || '-')}</div>
          <div class="proxy-stats"><span>VM ${vms.length}</span><span>1h ${proxy.usageHits1h || 0}</span></div>
        </header>
        <div class="vm-stack">
          ${vms.length ? vms.map(renderVmCard).join('') : '<div class="empty-lane">没有已接入 VM</div>'}
        </div>
      </section>
    `;
  }).join('');
  wireDragAndDrop();
  wireHealthButtons();
  wireDeleteProxyButtons();
}

function proxyNameSort(a, b) {
  const left = proxyNumber(a);
  const right = proxyNumber(b);
  if (left !== right) return left - right;
  return String(a).localeCompare(String(b));
}

function proxyNumber(name) {
  const match = String(name).match(/^proxy-(\d+)$/);
  if (match) return Number(match[1]);
  return String(name).startsWith('direct-') ? 9000 : 8000;
}

function canArchiveProxy(proxy) {
  return !proxy.archived && ['down', 'degraded'].includes(healthStatus(proxy)) && proxy.type !== 'direct';
}

function healthStatus(proxy) {
  return proxy.health?.status || 'unknown';
}

function healthLabel(proxy) {
  const status = healthStatus(proxy);
  const labels = { healthy: '健康', degraded: '不稳', down: '不可用', unknown: '未检测' };
  const mbps = proxy.health?.downloadMbps;
  return mbps == null ? labels[status] || '未检测' : `${labels[status] || status} ${mbps}Mbps`;
}

function healthTitle(proxy) {
  const health = proxy.health || {};
  const checkedAt = health.checkedAt ? new Date(health.checkedAt).toLocaleString() : '暂无检测记录';
  return [
    `状态: ${healthLabel(proxy)}`,
    `上次检测: ${checkedAt}`,
    `并发: ${health.concurrency || '-'} ｜ 成功: ${health.successCount ?? '-'} ｜ 失败: ${health.failureCount ?? '-'}`,
    `成功率: ${health.successRate ?? '-'}% ｜ 平均耗时: ${health.latencyMs ?? '-'}ms ｜ 总耗时: ${health.durationMs ?? '-'}ms`,
    `下载速度: ${health.downloadMbps ?? '-'} Mbps`,
    `结果: ${health.message || '等待主动探测'}`,
  ].join('\n');
}

function wireHealthButtons() {
  $$('.check-proxy-btn').forEach((button) => {
    button.addEventListener('click', async (event) => {
      event.stopPropagation();
      button.disabled = true;
      button.textContent = '检测中';
      try {
        await runHealthCheck(button.dataset.proxy);
      } finally {
        button.disabled = false;
        button.textContent = '检测';
      }
    });
  });
}

function wireDeleteProxyButtons() {
  $$('.delete-proxy-btn').forEach((button) => {
    button.addEventListener('click', (event) => {
      event.stopPropagation();
      deleteProxy(button.dataset.proxy).catch((error) => toast(error.message));
    });
  });
}

function renderVmCard(vm) {
  const effectiveProxy = getVmEffectiveProxy(vm);
  const draft = state.changes.get(vm.ip);
  const draftClass = draft ? 'draft' : '';
  const label = vm.label || (vm.vmId ? `${vm.host}:vm${vm.vmId}` : vm.name);
  return `
    <article class="vm-card ${vm.status} ${draftClass}" draggable="true" data-ip="${escapeAttr(vm.ip)}" data-proxy="${escapeAttr(effectiveProxy || '')}">
      <strong><span>${escapeHtml(label)}</span><span>${escapeHtml(vm.host)}</span></strong>
      <small>${escapeHtml(vm.ip)} ｜ ${escapeHtml(vm.name || '-')}</small>
      <small>${escapeHtml(vm.proxy || '未接入 proxy')}${draft ? ` → ${escapeHtml(draft.toProxy)}` : ''}</small>
      ${draft ? `<div class="vm-actions"><span class="draft-label">草稿未生效</span><button class="mini-btn apply-one-btn" data-ip="${escapeAttr(vm.ip)}">生效此项</button></div>` : ''}
    </article>
  `;
}

function renderVmTable() {
  const search = state.search.toLowerCase();
  $('#vmTable').innerHTML = state.data.vms
    .filter((vm) => !search || vmMatches(vm, search) || String(vm.proxy || '').toLowerCase().includes(search))
    .map((vm) => {
      const label = vm.label || (vm.vmId ? `${vm.host}:vm${vm.vmId}` : vm.name);
      const proxyHits = vm.assignedProxyHits1h ?? vm.usageHits1h;
      const statusLabel = vm.host === 'pve1' && vm.proxy && proxyHits > 0
        ? '已验证 proxy'
        : vm.host === 'pve1' && vm.proxy
          ? '等待 proxy 验证'
          : vm.host === 'pve1'
            ? '未配置 proxy'
            : vm.status === 'managed' ? '已接入 proxy' : vm.status === 'partial' ? '接入不完整' : '未接入 proxy';
      return `
        <tr class="${vm.status}">
          <td>${escapeHtml(label)}</td>
          <td>${escapeHtml(vm.ip)}</td>
          <td>${escapeHtml(vm.host)}</td>
          <td>${escapeHtml(getVmEffectiveProxy(vm) || '未分配')}</td>
          <td>${vm.hasDhcp ? '是' : '否'}</td>
          <td>${vm.hasLease ? '在线/有租约' : '无'}</td>
          <td><span class="status-chip ${vm.status}">${statusLabel}</span></td>
        </tr>
      `;
    }).join('');
}

function renderPve1Provision() {
  const list = $('#pve1ProvisionList');
  if (!list || !state.data) return;
  const proxies = state.data.proxies
    .filter((proxy) => !proxy.archived && proxy.type !== 'direct')
    .sort((a, b) => proxyNameSort(a.name, b.name));
  const pve1Vms = state.data.vms
    .filter((vm) => vm.host === 'pve1' && Number(vm.vmId) >= 101 && Number(vm.vmId) <= 140)
    .sort((a, b) => Number(a.vmId) - Number(b.vmId));
  if (!pve1Vms.length) {
    list.textContent = '暂无 pve1 VM101-140 数据';
    return;
  }
  list.innerHTML = pve1Vms.map((vm) => {
    const expectedIp = vm.ip || `172.16.101.${Number(vm.vmId) + 79}`;
    const label = vm.label || `pve1:vm${vm.vmId}`;
    const proxyOptions = ['<option value="">选择 proxy</option>'].concat(proxies.map((proxy) => `<option value="${escapeAttr(proxy.name)}" ${vm.proxy === proxy.name ? 'selected' : ''}>${escapeHtml(proxy.name)} ${escapeHtml(healthLabel(proxy))}</option>`)).join('');
    const proxyHits = vm.assignedProxyHits1h ?? vm.usageHits1h;
    const verifyLabel = vm.proxy
      ? (vm.hasLease && proxyHits > 0 ? `已验证 ${vm.proxy} / ${proxyHits}` : vm.hasLease ? '已配置，等待 proxy 流量验证' : '已配置，等待租约')
      : '未配置';
    return `
      <div class="provision-item ${vm.proxy ? 'configured' : ''}">
        <div>
          <strong>${escapeHtml(label)} ${escapeHtml(vm.name || '')}</strong>
          <small>${escapeHtml(expectedIp)} ｜ ${escapeHtml(vm.bridge || '未配置网桥')} ｜ ${escapeHtml(vm.proxmoxStatus || vm.status)}</small>
        </div>
        <span class="status-chip ${vm.proxy && vm.hasLease && proxyHits > 0 ? '' : 'partial'}">${escapeHtml(verifyLabel)}</span>
        <select class="pve1-proxy-select" data-vm="${escapeAttr(vm.vmId)}">${proxyOptions}</select>
        <button class="mini-btn configure-pve1-btn" data-vm="${escapeAttr(vm.vmId)}">配置此 VM</button>
        <pre class="pve1-detail" data-vm="${escapeAttr(vm.vmId)}" hidden></pre>
      </div>
    `;
  }).join('');
  wirePve1ConfigureButtons();
}

function formatPve1Result(result) {
  const lines = [];
  if (result.message) lines.push(result.message);
  if (result.errors?.length) lines.push('错误:', ...result.errors.map((item) => `- ${item}`));
  if (result.steps?.length) lines.push('已执行:', ...result.steps.map((item) => `- ${item}`));
  if (result.tests) {
    lines.push('验证:', ...Object.entries(result.tests).map(([key, value]) => `- ${key}: ${value}`));
  }
  return lines.filter(Boolean).join('\n') || JSON.stringify(result, null, 2);
}

function showPve1Detail(vmId, result) {
  const detail = $(`.pve1-detail[data-vm="${CSS.escape(String(vmId))}"]`);
  if (!detail) return;
  detail.textContent = formatPve1Result(result);
  detail.hidden = false;
}

function findPve1Vm(vmId) {
  return state.data?.vms.find((vm) => vm.host === 'pve1' && String(vm.vmId) === String(vmId));
}

function pve1VmReady(vm, proxy) {
  if (!vm || vm.proxy !== proxy || !vm.hasLease) return false;
  return (vm.assignedProxyHits1h ?? vm.usageHits1h ?? 0) > 0 || vm.hasLease;
}

async function refreshPve1VmAfterConfigure(vmId, proxy, button) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    if (attempt > 0) {
      button.textContent = `等待租约 ${attempt}`;
      await delay(1500);
    }
    await loadState({ toastMessage: '' });
    const vm = findPve1Vm(vmId);
    if (pve1VmReady(vm, proxy)) return vm;
  }
  return findPve1Vm(vmId);
}

function wirePve1ConfigureButtons() {
  $$('.configure-pve1-btn').forEach((button) => {
    if (button.dataset.bound === '1') return;
    button.dataset.bound = '1';
    button.addEventListener('click', async () => {
      const vmId = button.dataset.vm;
      const select = $(`.pve1-proxy-select[data-vm="${CSS.escape(vmId)}"]`);
      const proxy = select?.value;
      if (!proxy) return toast('请先选择 proxy');
      button.disabled = true;
      button.textContent = '配置中';
      try {
        const result = await configurePve1Vm(vmId, proxy);
        $('#diffOutput').textContent = [result.message, ...(result.steps || []), ...(result.errors || [])].filter(Boolean).join('\n');
        if (result.configured) {
          await refreshPve1VmAfterConfigure(vmId, proxy, button);
        } else if (result.ok) {
          await loadState({ toastMessage: '' });
        }
        showPve1Detail(vmId, result);
        const vm = findPve1Vm(vmId);
        toast(result.ok ? (result.verified ? '配置并验证成功' : '配置完成，等待流量验证') : vm?.hasLease ? '配置完成，租约已生效' : '配置失败，请查看详情');
      } catch (error) {
        toast(error.message);
      } finally {
        button.disabled = false;
        button.textContent = '配置此 VM';
      }
    });
  });
}

async function configurePve1Vm(vmId, proxy) {
  const response = await fetch('/api/pve1/configure-vm', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ vmId, proxy }),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.errors?.join('\n') || '配置失败');
  return result;
}

function wireDragAndDrop() {
  $$('.vm-card').forEach((card) => {
    card.addEventListener('dragstart', (event) => {
      card.classList.add('dragging');
      event.dataTransfer.setData('application/json', JSON.stringify({ ip: card.dataset.ip, fromProxy: card.dataset.proxy }));
    });
    card.addEventListener('dragend', () => card.classList.remove('dragging'));
  });
  $$('.proxy-lane').forEach((lane) => {
    lane.addEventListener('dragover', (event) => {
      event.preventDefault();
      lane.classList.add('drag-over');
    });
    lane.addEventListener('dragleave', () => lane.classList.remove('drag-over'));
    lane.addEventListener('drop', (event) => {
      event.preventDefault();
      lane.classList.remove('drag-over');
      const payload = JSON.parse(event.dataTransfer.getData('application/json') || '{}');
      const toProxy = lane.dataset.proxy;
      const vm = state.data.vms.find((item) => item.ip === payload.ip);
      const targetProxy = state.data.proxies.find((proxy) => proxy.name === toProxy);
      if (targetProxy?.archived) {
        toast('已归档 proxy 不能作为新的分配目标');
        return;
      }
      if (!payload.ip || !toProxy || !vm) return;
      const fromProxy = state.changes.get(payload.ip)?.fromProxy || vm.proxy || payload.fromProxy;
      if (fromProxy === toProxy) {
        if (state.changes.delete(payload.ip)) {
          renderAll();
          toast(`${payload.ip} 已恢复为当前生效配置`);
        }
        return;
      }
      state.changes.set(payload.ip, { ip: payload.ip, fromProxy, toProxy });
      renderAll();
      toast(`${payload.ip} 已加入变更草稿`);
    });
  });
  wireApplyOneButtons();
}

function wireApplyOneButtons() {
  $$('.apply-one-btn').forEach((button) => {
    if (button.dataset.bound === '1') return;
    button.dataset.bound = '1';
    button.addEventListener('click', (event) => {
      event.stopPropagation();
      applyOneChange(button.dataset.ip).catch((error) => toast(error.message));
    });
  });
}

function renderChanges() {
  const changes = Array.from(state.changes.values());
  $('#changeCount').textContent = `${changes.length} 项`;
  if (!changes.length) {
    $('#changeList').className = 'change-list empty';
    $('#changeList').textContent = '暂无变更';
    $('#diffOutput').textContent = '';
    return;
  }
  $('#changeList').className = 'change-list';
  $('#changeList').innerHTML = changes.map((change) => `
    <div class="change-item draft">
      <strong>${escapeHtml(change.ip)}</strong>
      <div>${escapeHtml(change.fromProxy)} → ${escapeHtml(change.toProxy)}</div>
      <div class="change-actions">
        <button class="mini-btn apply-one-btn" data-ip="${escapeAttr(change.ip)}">生效此项</button>
        <button class="mini-btn discard-one-btn" data-ip="${escapeAttr(change.ip)}">放弃此项</button>
      </div>
    </div>
  `).join('');
  wireApplyOneButtons();
  wireDiscardOneButtons();
}

function renderDraftTopBar() {
  const changes = Array.from(state.changes.values());
  const bar = $('#draftTopBar');
  bar.classList.toggle('hidden', changes.length === 0);
  $('#draftTopCount').textContent = `${changes.length} 项变更草稿`;
}

function renderProxyHistory() {
  const list = $('#proxyHistoryList');
  if (!list) return;
  const history = state.data.proxyHistory || [];
  if (!history.length) {
    list.textContent = '暂无归档记录';
    return;
  }
  list.innerHTML = history.slice().reverse().slice(0, 30).map((item) => `
    <div class="history-item">
      <strong>${escapeHtml(item.proxy)}</strong>
      <span>${escapeHtml(item.action === 'archive' ? '已归档' : item.action)} ｜ ${escapeHtml(item.archivedAt || item.deletedAt || '')}</span>
      <small>影响 VM: ${escapeHtml(item.affectedVmCount ?? 0)}</small>
    </div>
  `).join('');
}

function renderDomainBypass() {
  const list = $('#domainBypassList');
  if (!list || !state.data) return;

  // Populate VM dropdown while preserving selection
  const vmSelect = $('#domainVmSelect');
  if (vmSelect) {
    const prev = vmSelect.value;
    const managedVms = (state.data.vms || []).filter((vm) => vm.ip && (vm.status === 'managed' || vm.status === 'partial'));
    vmSelect.innerHTML = '<option value="">全部 VM</option>' +
      managedVms.map((vm) => `<option value="${escapeAttr(vm.ip)}">${escapeHtml(vm.label || vm.ip)} (${escapeHtml(vm.ip)})</option>`).join('');
    if (prev) vmSelect.value = prev;
  }

  const rules = state.data.domainBypassRules || [];
  if (!rules.length) {
    list.innerHTML = '<div class="warning empty">暂无域名直连规则</div>';
    return;
  }

  list.innerHTML = rules.map((rule) => {
    const scope = rule.vmIp ? `VM ${escapeHtml(rule.vmIp)}` : '全部 VM';
    const ruleText = rule.vmIp
      ? `AND,((SRC-IP-CIDR,${escapeHtml(rule.vmIp)}/32),(${escapeHtml(rule.ruleType.replace('AND-', ''))},${escapeHtml(rule.domain)})),${escapeHtml(rule.target)}`
      : `${escapeHtml(rule.ruleType)},${escapeHtml(rule.domain)},${escapeHtml(rule.target)}`;
    const isReject = rule.target === 'REJECT' || rule.target === 'REJECT-DROP';
    const canDelete = !state.data.readOnly;
    return `
      <div class="domain-bypass-item ${rule.managed ? (isReject ? 'reject' : '') : 'system'}">
        <code class="domain-rule-text">${ruleText}</code>
        <span class="badge ${isReject ? 'badge-reject' : ''}">${scope}</span>
        ${isReject ? `<span class="domain-action-badge reject-badge">${escapeHtml(rule.target)}</span>` : ''}
        ${!rule.managed ? '<span class="domain-sys-badge">系统规则</span>' : ''}
        ${canDelete ? `<button class="mini-btn remove-domain-btn" data-line="${escapeAttr(String(rule.line))}" title="删除此规则">删除</button>` : ''}
      </div>
    `;
  }).join('');

  $$('.remove-domain-btn').forEach((button) => {
    button.addEventListener('click', () => {
      const isSystem = button.closest('.domain-bypass-item')?.classList.contains('system');
      const msg = isSystem
        ? `这是系统规则，删除后可能影响相关服务。确认删除第 ${button.dataset.line} 行？`
        : `确认删除第 ${button.dataset.line} 行的域名直连规则？`;
      if (!window.confirm(msg)) return;
      removeDomainBypassRule(Number(button.dataset.line)).catch((error) => toast(error.message));
    });
  });
}

async function addDomainBypassRule() {
  const domain = $('#domainInput')?.value.trim();
  if (!domain) return toast('请输入域名');
  const ruleType = $('#domainRuleType')?.value || 'DOMAIN-SUFFIX';
  const target = $('#domainTarget')?.value || 'DIRECT';
  const vmIp = $('#domainVmSelect')?.value || null;
  const response = await fetch('/api/domain-bypass/add', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ domain, ruleType, target, vmIp }),
  });
  const result = await response.json();
  if (result.ok) {
    $('#domainInput').value = '';
    await loadState({ toastMessage: result.message || '规则已添加' });
  } else {
    toast(result.errors?.join('\n') || '添加失败');
    $('#diffOutput').textContent = result.errors?.join('\n') || '';
  }
}

async function removeDomainBypassRule(lineNumber) {
  const response = await fetch('/api/domain-bypass/remove', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ line: lineNumber }),
  });
  const result = await response.json();
  if (result.ok) {
    await loadState({ toastMessage: result.message || '规则已删除' });
  } else {
    toast(result.errors?.join('\n') || '删除失败');
  }
}

function wireDiscardOneButtons() {
  $$('.discard-one-btn').forEach((button) => {
    button.addEventListener('click', (event) => {
      event.stopPropagation();
      state.changes.delete(button.dataset.ip);
      renderAll();
      toast('已放弃此项草稿');
    });
  });
}

function getVmEffectiveProxy(vm) {
  return state.changes.get(vm.ip)?.toProxy || vm.proxy;
}

function vmMatches(vm, search) {
  return [vm.id, vm.label, vm.ip, vm.vmId, vm.name, vm.host, vm.mac, vm.note, vm.comment].some((value) => String(value || '').toLowerCase().includes(search));
}

async function previewPlan() {
  const changes = Array.from(state.changes.values());
  if (!changes.length) return toast('没有待预览的变更');
  const response = await fetch('/api/plan', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ changes }),
  });
  const result = await response.json();
  $('#diffOutput').textContent = result.errors?.length ? result.errors.join('\n') : result.diff || '没有产生 diff';
  toast(result.ok ? 'diff 已生成' : '变更存在问题');
}

async function runHealthCheck(proxyName = null) {
  toast(proxyName ? `正在检测 ${proxyName}` : '正在集中探测 proxy');
  const response = await fetch('/api/health/check', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(proxyName ? { proxy: proxyName } : {}),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.errors?.join('\n') || '探测失败');
  await loadState();
  toast(proxyName ? `${proxyName} 检测完成` : `集中探测完成: ${result.count} 个`);
}

async function deleteProxy(proxyName) {
  if (!proxyName) return;
  const planResponse = await fetch('/api/proxies/delete-plan', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ proxy: proxyName }),
  });
  const plan = await planResponse.json();
  $('#diffOutput').textContent = plan.errors?.length ? plan.errors.join('\n') : plan.message || '归档不会修改 mihomo 配置';
  document.querySelector('[data-view="policies"]').click();
  if (!plan.ok) {
    toast(`无法删除 ${proxyName}`);
    return;
  }
  const message = `${proxyName} 将在管理界面归档，不修改 mihomo 底层配置。受影响 VM: ${plan.affectedVmCount}。是否继续？`;
  if (!window.confirm(message)) return;
  const response = await fetch('/api/proxies/delete', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ proxy: proxyName }),
  });
  const result = await response.json();
  $('#diffOutput').textContent = result.errors?.length ? result.errors.join('\n') : result.message || '';
  if (result.ok) await loadState();
  toast(result.ok ? `${proxyName} 已归档` : `${proxyName} 归档未执行`);
}

async function applyChanges() {
  const changes = Array.from(state.changes.values());
  if (!changes.length) return toast('没有待发布的变更');
  return applyChangeSet(changes, true);
}

async function applyOneChange(ip) {
  const change = state.changes.get(ip);
  if (!change) return toast('没有找到此项草稿');
  return applyChangeSet([change], false);
}

async function applyChangeSet(changes, clearAll) {
  const response = await fetch('/api/apply', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ changes }),
  });
  const result = await response.json();
  $('#diffOutput').textContent = result.errors?.length ? result.errors.join('\n') : result.message || result.diff || '';
  if (result.ok) {
    if (clearAll) {
      state.changes.clear();
    } else {
      for (const change of changes) state.changes.delete(change.ip);
    }
    await loadState();
  }
  toast(result.ok ? '发布完成' : applyErrorMessage(result));
}

function applyErrorMessage(result) {
  if (!result.errors?.length) return '发布失败，请查看详情';
  if (result.errors.some((item) => item.includes('read-only') || item.includes('PROXY_MANAGER_ALLOW_WRITE'))) {
    return '当前没有启用写入';
  }
  return result.errors[0];
}

function setTitle(view) {
  $('#pageTitle').textContent = titles[view][0];
  $('#pageSubtitle').textContent = titles[view][1];
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[char]));
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/'/g, '&#39;');
}

$$('.nav-item').forEach((button) => {
  button.addEventListener('click', () => {
    $$('.nav-item').forEach((item) => item.classList.remove('active'));
    $$('.view').forEach((view) => view.classList.remove('active'));
    button.classList.add('active');
    $(`#${button.dataset.view}`).classList.add('active');
    setTitle(button.dataset.view);
  });
});

$('#refreshBtn').addEventListener('click', () => loadState().catch((error) => toast(error.message)));
$('#searchInput').addEventListener('input', (event) => {
  state.search = event.target.value.trim();
  if (!state.data) return;
  renderBoard();
  renderVmTable();
});
$('#providerFilter').addEventListener('click', (event) => {
  if (!event.target.matches('button')) return;
  $$('#providerFilter button').forEach((button) => button.classList.remove('selected'));
  event.target.classList.add('selected');
  state.provider = event.target.dataset.provider;
  renderBoard();
});
$('#planBtn').addEventListener('click', () => previewPlan().catch((error) => toast(error.message)));
$('#applyBtn').addEventListener('click', () => applyChanges().catch((error) => toast(error.message)));
$('#clearChangesBtn').addEventListener('click', () => {
  state.changes.clear();
  renderAll();
  toast('已清空变更草稿');
});
$('#checkAllBtn').addEventListener('click', () => runHealthCheck().catch((error) => toast(error.message)));
$('#addDomainBypassBtn').addEventListener('click', () => addDomainBypassRule().catch((error) => toast(error.message)));
$('#topPlanBtn').addEventListener('click', () => previewPlan().catch((error) => toast(error.message)));
$('#topApplyBtn').addEventListener('click', () => applyChanges().catch((error) => toast(error.message)));
$('#topClearBtn').addEventListener('click', () => {
  state.changes.clear();
  renderAll();
  toast('已清空变更草稿');
});

loadState().catch((error) => {
  $('#pageSubtitle').textContent = error.message;
  toast(error.message);
});
