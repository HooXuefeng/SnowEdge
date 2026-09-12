// Migrate local display preferences to the SnowEdge namespace.
try { for (const key of Object.keys(localStorage)) { if (key.startsWith('aipw:')) { const next='snowedge:'+key.slice(5); if(localStorage.getItem(next)===null)localStorage.setItem(next,localStorage.getItem(key)); } } } catch (_) {}
(() => {
  const $ = (s, r=document) => r.querySelector(s);
  const $$ = (s, r=document) => [...r.querySelectorAll(s)];
  const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));

  $$("[data-open-modal]").forEach(b => b.addEventListener("click", () => {
    const m = document.getElementById(b.dataset.openModal); if (m) m.classList.add("open");
  }));
  $$("[data-close-modal]").forEach(b => b.addEventListener("click", () => {
    const m = b.closest(".modal"); if (m) m.classList.remove("open");
  }));

  const globalFilter = $("#globalFilter");
  if (globalFilter) {
    const applyFilter = () => {
      const q = globalFilter.value.toLowerCase().trim();
      $$(".filter-row").forEach(row => row.style.display = row.innerText.toLowerCase().includes(q) ? "" : "none");
    };
    globalFilter.addEventListener("input", applyFilter);
    document.addEventListener("keydown", e => {
      if (e.key === "/" && !["INPUT","TEXTAREA"].includes(document.activeElement.tagName)) {
        e.preventDefault(); globalFilter.focus();
      }
    });
  }



  const skillFilters = $$("[data-skill-filter]");
  if (skillFilters.length) {
    skillFilters.forEach(button => button.addEventListener("click", () => {
      skillFilters.forEach(x => x.classList.remove("active"));
      button.classList.add("active");
      const mode = button.dataset.skillFilter;
      $$("#skillGrid .skill-card").forEach(card => {
        const show =
          mode === "all" ||
          (mode === "enabled" && card.dataset.enabled === "1") ||
          (mode === "builtin" && card.dataset.source === "builtin") ||
          (mode === "external" && card.dataset.source === "external");
        card.style.display = show ? "" : "none";
      });
    }));
  }

  const authzType = $("#authzTestType");
  const comparisonIdentity = $("#comparisonIdentity");
  if (authzType && comparisonIdentity) {
    const syncAuthzForm = () => {
      const anonymousMode = authzType.value === "unauthenticated";
      if (anonymousMode) {
        comparisonIdentity.value = "anonymous";
        comparisonIdentity.disabled = true;
      } else {
        comparisonIdentity.disabled = false;
        if (comparisonIdentity.value === "anonymous") {
          const firstIdentity = [...comparisonIdentity.options].find(o => o.value && o.value !== "anonymous");
          if (firstIdentity) comparisonIdentity.value = firstIdentity.value;
        }
      }
    };
    authzType.addEventListener("change", syncAuthzForm);
    syncAuthzForm();
  }

  const authzForm = $("#authzForm");
  if (authzForm) {
    authzForm.addEventListener("submit", () => {
      if (comparisonIdentity) comparisonIdentity.disabled = false;
      const btn = authzForm.querySelector('button[type="submit"]');
      if (btn) { btn.disabled = true; btn.textContent = "Running differential test…"; }
    });
  }

  const scopeBtn = $("#scopeCheckBtn");
  if (scopeBtn && window.PROJECT_ID) {
    scopeBtn.addEventListener("click", async () => {
      const input = $("#scanTarget"), out = $("#scopeCheckResult"), target = input.value.trim();
      if (!target) { out.className="scope-check bad"; out.textContent="Target required."; return; }
      out.className="scope-check"; out.textContent="Checking scope…";
      try {
        const r = await fetch(`/api/projects/${window.PROJECT_ID}/scope-check?target=${encodeURIComponent(target)}`);
        const data = await r.json();
        out.className = `scope-check ${data.allowed ? "ok" : "bad"}`;
        out.textContent = data.allowed ? "✓ Authorized target" : "✕ Outside authorized scope";
      } catch { out.className="scope-check bad"; out.textContent="Scope check failed."; }
    });
  }

  const scanForm = $("#scanForm");
  if (scanForm) scanForm.addEventListener("submit", () => {
    const btn = scanForm.querySelector('button[type="submit"]');
    if (btn) { btn.disabled = true; btn.textContent = "Queued"; }
  });

  $$(".tab").forEach(tab => tab.addEventListener("click", () => {
    $$(".tab").forEach(x => x.classList.remove("active"));
    $$(".tab-pane").forEach(x => x.classList.remove("active"));
    tab.classList.add("active");
    const pane = document.querySelector(`[data-tab-pane="${tab.dataset.tabTarget}"]`);
    if (pane) pane.classList.add("active");
  }));

  $$(".context-item").forEach(item => item.addEventListener("click", () => {
    $("#contextTitle").textContent = item.dataset.title || "Selected item";
    $("#contextKind").textContent = item.dataset.kind || "observation";
    $("#contextDetail").textContent = item.dataset.detail || "No additional context.";
  }));

  $$(".evidence-select").forEach(item => item.addEventListener("click", () => {
    $("#evidenceTitle").textContent = `${item.dataset.kind} · #${item.dataset.id}`;
    $("#evidenceContent").textContent = item.dataset.content || "";
  }));

  function taskRow(t) {
    const div = document.createElement("div");
    div.className = "activity-row";
    div.innerHTML = `<span class="run-state ${esc(t.status)}">${esc(t.status)}</span><div><b>${esc(t.action)}</b><small>${esc(t.target)}</small></div>`;
    return div;
  }

  function agentEvents(agent) {
    const target = $("#agentEventStream") || $("#agentMiniTimeline");
    if (!target || !agent) return;
    target.innerHTML = "";
    (agent.events || []).forEach(e => {
      if (target.id === "agentMiniTimeline") {
        const row = document.createElement("div");
        row.innerHTML = `<span class="event-dot ${esc(e.status)}"></span><p><b>${esc(e.title)}</b><small>${esc(e.detail)}</small></p>`;
        target.appendChild(row);
      } else {
        const row = document.createElement("div");
        row.className = "event-row";
        row.innerHTML = `<div class="event-marker ${esc(e.status)}"></div><div class="event-meta"><span>${esc(e.stage)}</span><small>${esc(e.event_type)}</small></div><div class="event-copy"><b>${esc(e.title)}</b><p>${esc(e.detail)}</p></div><span class="policy-tag">${esc(e.policy_class)}</span>`;
        target.appendChild(row);
      }
    });
  }

  async function poll() {
    if (!window.PROJECT_ID) return;
    try {
      const r = await fetch(`/api/projects/${window.PROJECT_ID}/status`, {cache:"no-store"});
      if (!r.ok) return;
      const data = await r.json();
      $$("[data-stat]").forEach(el => {
        if (Object.prototype.hasOwnProperty.call(data.stats, el.dataset.stat)) el.textContent = data.stats[el.dataset.stat];
      });
      const live = $("#liveTaskList");
      if (live) {
        live.innerHTML = "";
        if (data.tasks.length) data.tasks.slice(0,10).forEach(t => live.appendChild(taskRow(t)));
        else live.innerHTML = '<div class="empty small">No tool runs.</div>';
      }
      if (window.ENABLE_AGENT_POLLING || window.ENABLE_PROJECT_POLLING) agentEvents(data.agent);
    } catch {}
  }

  if (window.ENABLE_PROJECT_POLLING || window.ENABLE_TASK_PAGE_POLLING || window.ENABLE_AGENT_POLLING) {
    poll(); setInterval(poll, 2200);
  }

  $$("[data-browser-filter]").forEach(btn => btn.addEventListener("click", () => {
    $$("[data-browser-filter]").forEach(x => x.classList.remove("active"));
    btn.classList.add("active");
    const kind = btn.dataset.browserFilter;
    $$(".browser-event-row").forEach(row => {
      row.style.display = (kind === "all" || row.dataset.browserKind === kind) ? "" : "none";
    });
  }));

  const browserForm = $("#browserStartForm");
  if (browserForm) {
    browserForm.addEventListener("submit", () => {
      const btn = browserForm.querySelector('button[type="submit"]');
      if (btn) { btn.disabled = true; btn.textContent = "Starting browser…"; }
    });
  }

  async function pollBrowserSession() {
    const cfg = window.BROWSER_SESSION;
    if (!cfg || !["queued","running"].includes(cfg.status)) return;
    try {
      const r = await fetch(`/api/projects/${cfg.projectId}/browser-sessions/${cfg.sessionId}`, {cache:"no-store"});
      if (!r.ok) return;
      const data = await r.json();
      if (!["queued","running"].includes(data.status)) {
        window.location.reload();
      }
    } catch {}
  }
  if (window.BROWSER_SESSION && ["queued","running"].includes(window.BROWSER_SESSION.status)) {
    setInterval(pollBrowserSession, 1800);
  }


  function renderKnowledgeGraph() {
    const host = document.getElementById("knowledgeGraphCanvas");
    const data = window.KNOWLEDGE_GRAPH_DATA;
    if (!host || !data || !Array.isArray(data.nodes)) return;

    const nodes = data.nodes.slice(0, 120);
    const nodeMap = new Map(nodes.map(n => [n.id, n]));
    const groupFor = type => {
      if (["project","asset","service"].includes(type)) return "Foundation";
      if (["endpoint","web_artifact","route","browser_session","browser_event","request"].includes(type)) return "Web Surface";
      if (["identity","authorization_case"].includes(type)) return "Identity / Authz";
      if (["finding","proof_capsule","evidence"].includes(type)) return "Evidence / Findings";
      return "Execution";
    };
    const groups = ["Foundation","Web Surface","Identity / Authz","Evidence / Findings","Execution"];
    const buckets = new Map(groups.map(g => [g, []]));
    nodes.forEach(n => buckets.get(groupFor(n.type)).push(n));

    const width = Math.max(980, host.clientWidth || 980);
    const maxRows = Math.max(...groups.map(g => buckets.get(g).length), 1);
    const height = Math.max(620, 90 + maxRows * 42);
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("width", "100%");
    svg.setAttribute("height", String(height));

    const pos = new Map();
    groups.forEach((g, gi) => {
      const x = 90 + gi * ((width - 180) / Math.max(groups.length - 1, 1));
      const label = document.createElementNS(ns, "text");
      label.setAttribute("x", String(x));
      label.setAttribute("y", "28");
      label.setAttribute("text-anchor", "middle");
      label.setAttribute("class", "kg-lane-label");
      label.textContent = g.toUpperCase();
      svg.appendChild(label);
      buckets.get(g).forEach((n, ri) => {
        pos.set(n.id, {x, y: 65 + ri * 42});
      });
    });

    (data.edges || []).forEach(e => {
      if (!pos.has(e.source) || !pos.has(e.target)) return;
      const a = pos.get(e.source), b = pos.get(e.target);
      const line = document.createElementNS(ns, "line");
      line.setAttribute("x1", String(a.x));
      line.setAttribute("y1", String(a.y));
      line.setAttribute("x2", String(b.x));
      line.setAttribute("y2", String(b.y));
      line.setAttribute("class", `kg-edge ${e.strength === "evidence" ? "evidence" : ""}`);
      svg.appendChild(line);
    });

    nodes.forEach(n => {
      const p = pos.get(n.id);
      const g = document.createElementNS(ns, "g");
      g.setAttribute("class", `kg-node ${n.type}`);
      g.style.cursor = "pointer";
      g.addEventListener("click", () => {
        window.location.href = `/projects/${window.KNOWLEDGE_GRAPH_PROJECT_ID}/knowledge-graph?selected=${n.id}`;
      });

      const circle = document.createElementNS(ns, "circle");
      circle.setAttribute("cx", String(p.x));
      circle.setAttribute("cy", String(p.y));
      circle.setAttribute("r", n.type === "project" ? "8" : "6");
      g.appendChild(circle);

      const text = document.createElementNS(ns, "text");
      text.setAttribute("x", String(p.x + 10));
      text.setAttribute("y", String(p.y + 3));
      const label = String(n.label || n.key || "").replace(/\s+/g, " ");
      text.textContent = label.length > 28 ? `${label.slice(0, 27)}…` : label;
      g.appendChild(text);

      const title = document.createElementNS(ns, "title");
      title.textContent = `${n.type}: ${n.label}`;
      g.appendChild(title);
      svg.appendChild(g);
    });

    host.innerHTML = "";
    host.appendChild(svg);
  }

  renderKnowledgeGraph();


  async function pollAgentTeamRun() {
    const cfg = window.AGENT_TEAM_RUN;
    if (!cfg || !["queued","running"].includes(cfg.status)) return;
    try {
      const r = await fetch(`/api/projects/${cfg.projectId}/agent-team/${cfg.runId}`, {cache:"no-store"});
      if (!r.ok) return;
      const data = await r.json();
      if (!["queued","running"].includes(data.status)) window.location.reload();
    } catch {}
  }
  if (window.AGENT_TEAM_RUN && ["queued","running"].includes(window.AGENT_TEAM_RUN.status)) {
    setInterval(pollAgentTeamRun, 1800);
  }


  const copilotForm = $("#copilotForm");
  if (copilotForm) copilotForm.addEventListener("submit", () => {
    const btn = copilotForm.querySelector('button[type="submit"]');
    if (btn) { btn.disabled = true; btn.textContent = "Queuing…"; }
  });

  async function pollCopilotQuery() {
    const cfg = window.COPILOT_QUERY;
    if (!cfg || !["queued","running"].includes(cfg.status)) return;
    try {
      const r = await fetch(`/api/projects/${cfg.projectId}/copilot/${cfg.queryId}`, {cache:"no-store"});
      if (!r.ok) return;
      const data = await r.json();
      if (!["queued","running"].includes(data.status)) window.location.reload();
    } catch {}
  }
  if (window.COPILOT_QUERY && ["queued","running"].includes(window.COPILOT_QUERY.status)) {
    setInterval(pollCopilotQuery, 1800);
  }

  const retestForm = $("#remediationRetestForm");
  if (retestForm) retestForm.addEventListener("submit", () => {
    const btn = retestForm.querySelector('button[type="submit"]');
    if (btn) { btn.disabled = true; btn.textContent = "Queueing retest…"; }
  });

  async function pollRemediationRetest() {
    const cfg = window.REMEDIATION_RETEST;
    if (!cfg || !["queued","running"].includes(cfg.status)) return;
    try {
      const r = await fetch(`/api/projects/${cfg.projectId}/remediation/${cfg.lifecycleId}`, {cache:"no-store"});
      if (!r.ok) return;
      const data = await r.json();
      if (!["queued","running"].includes(data.retest_status)) window.location.reload();
    } catch {}
  }
  if (window.REMEDIATION_RETEST && ["queued","running"].includes(window.REMEDIATION_RETEST.status)) {
    setInterval(pollRemediationRetest, 1800);
  }



// V1.6.3 Ctrl+K：全局搜索 + 中文命令面板。服务端搜索结果仍只包含脱敏元数据。
const globalSearchTrigger = $("#globalSearchTrigger");
const globalSearchModal = $("#globalSearchModal");
const globalSearchInput = $("#globalSearchInput");
const globalSearchResults = $("#globalSearchResults");
let globalSearchTimer = null;
let paletteIndex = -1;
const commands = Array.isArray(window.WORKSPACE_COMMANDS) ? window.WORKSPACE_COMMANDS : [];

const paletteItems = () => [...(globalSearchResults?.querySelectorAll("[data-palette-item]") || [])];
const syncPaletteActive = () => {
  paletteItems().forEach((x,i) => x.classList.toggle("active", i === paletteIndex));
  paletteItems()[paletteIndex]?.scrollIntoView({block:"nearest"});
};
const executePaletteItem = item => {
  if (!item) return;
  const url = item.dataset.url;
  const post = item.dataset.post;
  if (post) {
    const form=document.createElement("form");
    form.method="post"; form.action=post; document.body.appendChild(form); form.submit();
    return;
  }
  if (url) window.location.href=url;
};
const renderCommands = q => {
  if (!globalSearchResults) return;
  const needle=String(q||"").replace(/^>\s*/,"").toLowerCase().trim();
  const rows=commands.filter(c => !needle || `${c.title} ${c.keywords||""}`.toLowerCase().includes(needle)).slice(0,18);
  if (!rows.length) {
    globalSearchResults.innerHTML='<div class="empty small">没有匹配命令。</div>';
    paletteIndex=-1; return;
  }
  globalSearchResults.innerHTML =
    '<div class="palette-section-title">工作台命令</div>' +
    rows.map(c => `<button class="global-search-result command-result" type="button" data-palette-item data-url="${esc(c.url||"")}" data-post="${esc(c.post||"")}"><span>命令</span><div><b>${esc(c.title)}</b><small>工作台导航命令</small></div><em>↵</em></button>`).join("");
  paletteIndex=0; syncPaletteActive();
};
const openGlobalSearch = () => {
  if (!globalSearchModal) return;
  globalSearchModal.hidden = false;
  if (globalSearchInput && !globalSearchInput.value.trim()) renderCommands("");
  setTimeout(() => globalSearchInput?.focus(), 0);
};
const closeGlobalSearch = () => {
  if (!globalSearchModal) return;
  globalSearchModal.hidden = true;
  paletteIndex=-1;
};
globalSearchTrigger?.addEventListener("click", openGlobalSearch);
$$('[data-global-search-close]').forEach(x => x.addEventListener('click', closeGlobalSearch));
document.addEventListener("keydown", e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openGlobalSearch(); return; }
  if (!globalSearchModal || globalSearchModal.hidden) return;
  if (e.key === "Escape") { e.preventDefault(); closeGlobalSearch(); return; }
  if (e.key === "ArrowDown") { e.preventDefault(); const items=paletteItems(); if(items.length){paletteIndex=(paletteIndex+1)%items.length;syncPaletteActive();} return; }
  if (e.key === "ArrowUp") { e.preventDefault(); const items=paletteItems(); if(items.length){paletteIndex=(paletteIndex-1+items.length)%items.length;syncPaletteActive();} return; }
  if (e.key === "Enter" && paletteIndex >= 0) { e.preventDefault(); executePaletteItem(paletteItems()[paletteIndex]); }
});
globalSearchResults?.addEventListener("click", e => {
  const item=e.target.closest("[data-palette-item]");
  if(item) executePaletteItem(item);
});
const renderSearch = rows => {
  if (!globalSearchResults) return;
  if (!rows.length) { globalSearchResults.innerHTML = '<div class="empty small">没有匹配结果。可以输入“>”查看工作台命令。</div>'; paletteIndex=-1; return; }
  globalSearchResults.innerHTML =
    '<div class="palette-section-title">搜索结果 · 已脱敏</div>' +
    rows.map(r => `<a class="global-search-result" data-palette-item href="${esc(r.url)}" data-url="${esc(r.url)}"><span>${esc(r.kind)}</span><div><b>${esc(r.title)}</b><small>${esc(r.subtitle)}</small></div><em>→</em></a>`).join("");
  paletteIndex=0; syncPaletteActive();
};
let globalSearchSequence = 0;
globalSearchInput?.addEventListener("input", () => {
  const sequence = ++globalSearchSequence;
  clearTimeout(globalSearchTimer);
  const q = globalSearchInput.value.trim();
  if (!q || q.startsWith(">")) { renderCommands(q); return; }
  if (q.length < 2) { globalSearchResults.innerHTML = '<div class="empty small">请输入至少 2 个字符，或输入“>”查看命令。</div>'; paletteIndex=-1; return; }
  globalSearchTimer = setTimeout(async () => {
    try {
      const pid = window.PROJECT_ID ? `&project_id=${encodeURIComponent(window.PROJECT_ID)}` : "";
      const r = await fetch(`/api/global-search?q=${encodeURIComponent(q)}${pid}`, {cache:"no-store"});
      if (!r.ok) throw new Error();
      const data = await r.json();
      if (sequence === globalSearchSequence) renderSearch(data.results || []);
    } catch { if (sequence !== globalSearchSequence) return; globalSearchResults.innerHTML = '<div class="empty small">搜索暂时不可用。</div>'; paletteIndex=-1; }
  }, 180);
});

// V1.6 encrypted Request draft autosave. No localStorage/sessionStorage is used.
const requestEditForm = $("#requestEditForm");
if (requestEditForm) {
  const projectId = requestEditForm.dataset.projectId;
  const requestId = requestEditForm.dataset.requestId;
  const draftBar = $("#requestDraftBar");
  const draftTime = $("#requestDraftTime");
  const draftState = $("#draftSaveState");
  let currentDraft = null;
  let draftTimer = null;
  let dirty = false;
  let saving = false;
  let retryDelay = 1500;
  let submitting = false;
  const fields = ["name","method","url","headers_text","body","change_note"];
  const collectDraft = () => Object.fromEntries(fields.map(name => [name, requestEditForm.elements[name]?.value || ""]));
  const applyDraft = data => fields.forEach(name => { if (requestEditForm.elements[name] && Object.prototype.hasOwnProperty.call(data,name)) requestEditForm.elements[name].value = data[name] ?? ""; });
  const discardDraft = async () => {
    if (saving) { if (draftState) draftState.textContent = "请等待当前保存完成后再丢弃草稿"; return; }
    const response = await fetch(`/api/projects/${projectId}/requests/${requestId}/draft`, {method:"DELETE"});
    if (!response.ok) { if (draftState) draftState.textContent = "草稿删除失败，请重试"; return; }
    clearTimeout(draftTimer); dirty = false;
    currentDraft = null; if (draftBar) draftBar.hidden = true; if (draftState) draftState.textContent = "自动保存：无草稿";
  };
  const loadDraft = async () => {
    try {
      const r = await fetch(`/api/projects/${projectId}/requests/${requestId}/draft`, {cache:"no-store"});
      if (!r.ok) return;
      const data = await r.json(); currentDraft = data.draft;
      if (currentDraft && draftBar) { draftBar.hidden = false; if (draftTime) draftTime.textContent = `保存于 ${currentDraft.updated_at || ""}`; }
    } catch {}
  };
  const persistDraft = async () => {
    if (!dirty || saving) return;
    saving = true;
    dirty = false; if (draftState) draftState.textContent = "自动保存：保存中…";
    try {
      const r = await fetch(`/api/projects/${projectId}/requests/${requestId}/draft`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(collectDraft())});
      if (!r.ok) throw new Error();
      const data = await r.json(); retryDelay = 1500; if (draftState) draftState.textContent = dirty ? "自动保存：有新修改待保存" : "自动保存：已加密保存";
      if (draftTime) draftTime.textContent = `保存于 ${data.updated_at || ""}`;
    } catch { dirty = true; retryDelay = Math.min(retryDelay * 2, 30000); if (draftState) draftState.textContent = "自动保存：失败，将重试"; }
    finally { saving = false; if (dirty && !submitting) { clearTimeout(draftTimer); draftTimer = setTimeout(persistDraft, retryDelay); } }
  };
  requestEditForm.addEventListener("input", () => { dirty = true; clearTimeout(draftTimer); draftTimer = setTimeout(persistDraft, 900); });
  $("#restoreRequestDraft")?.addEventListener("click", () => { if (currentDraft?.content) { applyDraft(currentDraft.content); dirty = true; if (draftBar) draftBar.hidden = true; if (draftState) draftState.textContent = "自动保存：已恢复草稿"; } });
  $("#discardRequestDraft")?.addEventListener("click", () => discardDraft().catch(() => { if (draftState) draftState.textContent = "草稿删除失败，请重试"; }));
  requestEditForm.addEventListener("submit", event => {
    if (saving) { event.preventDefault(); if (draftState) draftState.textContent = "草稿保存中，请稍后再提交"; return; }
    submitting = true; clearTimeout(draftTimer);
  });
  window.addEventListener('beforeunload', event => { if ((dirty || saving) && !submitting) { event.preventDefault(); event.returnValue = ''; } });
  window.addEventListener('online', () => { if (dirty && !submitting) persistDraft(); });
  loadDraft();
}


// V1.6.3 统一数据表：文本筛选、快捷筛选、排序、多选、列设置、CSV、保存视图和键盘导航。
$$('[data-datagrid]').forEach(grid => {
  const toolbar = document.querySelector(`[data-grid-toolbar="${grid.id}"]`);
  const search = toolbar?.querySelector('[data-grid-search]');
  const exportBtn = toolbar?.querySelector('[data-grid-export]');
  const saveBtn = toolbar?.querySelector('[data-grid-save-view]');
  const columnsBtn = toolbar?.querySelector('[data-grid-columns]');
  const quickBtns = [...(toolbar?.querySelectorAll('[data-grid-quick]') || [])];
  const count = toolbar?.querySelector('.grid-count');
  const selectAll = grid.querySelector('[data-grid-select-all]');
  const storageKey = `snowedge:grid:${grid.dataset.gridKey || grid.id}`;
  let sortKey = '', sortDir = 1, quickKey = '', quickValue = '', hiddenColumns = [];
  const rows = () => [...grid.querySelectorAll('[data-grid-row]')];
  const visibleRows = () => rows().filter(r => r.style.display !== 'none');
  const normalize = v => String(v ?? '').toLowerCase().trim();

  const applyColumns = () => {
    const allRows=[grid.querySelector('.dense-head'),...rows()].filter(Boolean);
    allRows.forEach(row => [...row.children].forEach((cell,i) => {
      cell.classList.toggle('grid-column-hidden', hiddenColumns.includes(i));
    }));
  };

  const apply = () => {
    const q = normalize(search?.value);
    rows().forEach(row => {
      const textOk = !q || normalize(row.innerText).includes(q);
      const quickOk = !quickKey || normalize(row.dataset[quickKey]) === normalize(quickValue);
      row.style.display = textOk && quickOk ? '' : 'none';
    });
    if (sortKey) {
      const parent = rows()[0]?.parentElement;
      if (parent) rows().sort((a,b) => {
        const av = a.dataset[sortKey] ?? '', bv = b.dataset[sortKey] ?? '';
        const an = Number(av), bn = Number(bv);
        const cmp = Number.isFinite(an) && Number.isFinite(bn) && av !== '' && bv !== '' ? an-bn : String(av).localeCompare(String(bv), 'zh-CN', {numeric:true});
        return cmp * sortDir;
      }).forEach(r => parent.appendChild(r));
    }
    applyColumns();
    if (count) count.textContent = `显示 ${visibleRows().length} / ${rows().length} 条`;
  };

  search?.addEventListener('input', apply);
  quickBtns.forEach(btn => btn.addEventListener('click', () => {
    quickBtns.forEach(x => x.classList.remove('active')); btn.classList.add('active');
    quickKey=btn.dataset.filterKey||''; quickValue=btn.dataset.filterValue||'';
    apply();
  }));
  grid.querySelectorAll('[data-sort-key]').forEach(btn => btn.addEventListener('click', () => {
    const key = btn.dataset.sortKey;
    sortDir = sortKey === key ? -sortDir : 1; sortKey = key;
    grid.querySelectorAll('[data-sort-key]').forEach(x => x.classList.toggle('sorted', x === btn));
    apply();
  }));
  selectAll?.addEventListener('change', () => visibleRows().forEach(r => {
    const cb=r.querySelector('[data-grid-select-row]'); if(cb) cb.checked=selectAll.checked;
  }));

  columnsBtn?.addEventListener('click', () => {
    const old=toolbar.querySelector('.grid-column-menu'); if(old){old.remove();return;}
    const head=grid.querySelector('.dense-head'); if(!head)return;
    const menu=document.createElement('div'); menu.className='grid-column-menu';
    [...head.children].forEach((cell,i) => {
      if(i===0 || i===head.children.length-1) return;
      const label=(cell.innerText||`第 ${i+1} 列`).trim();
      const row=document.createElement('label');
      row.innerHTML=`<input type="checkbox" ${hiddenColumns.includes(i)?'':'checked'}> <span>${esc(label)}</span>`;
      row.querySelector('input').addEventListener('change', e => {
        hiddenColumns=e.target.checked ? hiddenColumns.filter(x=>x!==i) : [...new Set([...hiddenColumns,i])];
        applyColumns();
      });
      menu.appendChild(row);
    });
    toolbar.appendChild(menu);
  });

  exportBtn?.addEventListener('click', () => {
    const selected = rows().filter(r => r.querySelector('[data-grid-select-row]')?.checked);
    const source = selected.length ? selected : visibleRows();
    const lines = source.map(r => [...r.children]
      .filter((c,i) => !hiddenColumns.includes(i) && !c.querySelector('input[type=checkbox]') && !c.classList.contains('grid-actions-cell'))
      .map(c => `"${String(c.innerText||'').replace(/"/g,'""').replace(/\n+/g,' · ')}"`).join(','));
    const blob = new Blob(['\ufeff'+lines.join('\n')], {type:'text/csv;charset=utf-8'});
    const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=`${grid.dataset.gridKey || grid.id}.csv`; a.click(); URL.revokeObjectURL(a.href);
  });
  saveBtn?.addEventListener('click', () => {
    localStorage.setItem(storageKey, JSON.stringify({q:search?.value||'',sortKey,sortDir,quickKey,quickValue,hiddenColumns}));
    saveBtn.textContent='视图已保存'; setTimeout(()=>saveBtn.textContent='保存视图',1200);
  });

  try {
    const saved=JSON.parse(localStorage.getItem(storageKey)||'null');
    if(saved){
      if(search) search.value=saved.q||'';
      sortKey=saved.sortKey||''; sortDir=saved.sortDir||1;
      quickKey=saved.quickKey||''; quickValue=saved.quickValue||'';
      hiddenColumns=Array.isArray(saved.hiddenColumns)?saved.hiddenColumns:[];
      if(quickKey) quickBtns.forEach(btn => btn.classList.toggle('active',btn.dataset.filterKey===quickKey && btn.dataset.filterValue===quickValue));
    }
  } catch {}

  rows().forEach(row => {
    row.tabIndex=0;
    row.addEventListener('keydown', e => {
      const list=visibleRows(), idx=list.indexOf(row);
      if(e.key==='ArrowDown' && idx>=0 && idx<list.length-1){e.preventDefault();list[idx+1].focus();}
      if(e.key==='ArrowUp' && idx>0){e.preventDefault();list[idx-1].focus();}
      if(e.key==='Enter' && row.classList.contains('inspector-source')){e.preventDefault();openEntityInspector(row);}
    });
  });
  apply();
});

$$('[data-copy-text]').forEach(btn => btn.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(btn.dataset.copyText || ''); btn.textContent='已复制'; setTimeout(()=>btn.textContent='复制',900); } catch {}
}));


// 可折叠左侧导航：按中文分组保存个人偏好。
$$('.sidebar .nav-section').forEach((section,index) => {
  const caption=section.querySelector('.nav-caption');
  if(!caption) return;
  caption.setAttribute('role','button'); caption.tabIndex=0;
  const key=`snowedge:nav:${caption.textContent.trim() || index}`;
  let saved = null; try { saved = localStorage.getItem(key); } catch {}
  if (!section.querySelector('.side-link.active') && (saved === 'collapsed' || (saved === null && caption.dataset.defaultCollapsed))) section.classList.add('collapsed');
  caption.setAttribute('aria-expanded', String(!section.classList.contains('collapsed')));
  const toggle=() => {
    section.classList.toggle('collapsed');
    caption.setAttribute('aria-expanded', String(!section.classList.contains('collapsed')));
    try { localStorage.setItem(key,section.classList.contains('collapsed')?'collapsed':'open'); } catch {}
  };
  caption.addEventListener('click',toggle);
  caption.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();toggle();}});
});

// 统一右侧详情 Inspector。
const entityInspector=$("#entityInspector");
const openEntityInspector = source => {
  if(!entityInspector || !source) return;
  $("#inspectorKind").textContent=source.dataset.inspectorKind||"详情";
  $("#inspectorTitle").textContent=source.dataset.inspectorTitle||"对象详情";
  $("#inspectorSubtitle").textContent=source.dataset.inspectorSubtitle||"";
  const meta=$("#inspectorMeta"); meta.innerHTML="";
  String(source.dataset.inspectorMeta||"").split("｜").filter(Boolean).forEach(x=>{
    const span=document.createElement("span"); span.textContent=x.trim(); meta.appendChild(span);
  });
  const actions=$("#inspectorActions"); actions.innerHTML="";
  const addLink=(label,url,primary=false)=>{
    if(!url)return; const a=document.createElement("a");a.className=`btn ${primary?'primary':''}`;a.textContent=label||"打开";a.href=url;actions.appendChild(a);
  };
  if(source.dataset.inspectorPrimaryPost){
    const form=document.createElement("form");form.method="post";form.action=source.dataset.inspectorPrimaryPost;
    const b=document.createElement("button");b.type="submit";b.className="btn primary";b.textContent=source.dataset.inspectorPrimaryLabel||"执行";form.appendChild(b);actions.appendChild(form);
  } else addLink(source.dataset.inspectorPrimaryLabel,source.dataset.inspectorPrimaryUrl,true);
  addLink(source.dataset.inspectorSecondaryLabel,source.dataset.inspectorSecondaryUrl,false);
  entityInspector.classList.add("open"); entityInspector.setAttribute("aria-hidden","false");
};
window.openEntityInspector=openEntityInspector;
$$('.inspector-source').forEach(row => row.addEventListener('click', e => {
  if(e.target.closest('a,button,input,select,textarea,details,summary,form')) return;
  openEntityInspector(row);
}));
$$('[data-inspector-close]').forEach(x => x.addEventListener('click',()=>{
  entityInspector?.classList.remove('open');entityInspector?.setAttribute("aria-hidden","true");
}));
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&entityInspector?.classList.contains('open'))entityInspector.classList.remove('open');});

// Request Workspace 中文快捷键。
const requestTabs=['requestRaw','requestStructured','responseRaw','requestHistory'];
const activateRequestTab=index=>{
  const target=requestTabs[index]; if(!target)return;
  document.querySelector(`.request-tabs [data-tab-target="${target}"]`)?.click();
};
document.addEventListener('keydown',e=>{
  if(!document.querySelector('.request-v2-layout')) return;
  if(e.altKey && ['1','2','3','4'].includes(e.key)){e.preventDefault();activateRequestTab(Number(e.key)-1);return;}
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='s'&&requestEditForm){
    e.preventDefault();
    document.querySelector('.request-tabs [data-tab-target="requestStructured"]')?.click();
    requestEditForm.requestSubmit();
    return;
  }
  if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){
    const form=$("#requestReplayForm");
    const submit=form?.querySelector('button[type="submit"]:not([disabled])');
    if(form&&submit){e.preventDefault();form.requestSubmit();}
  }
});

})();
