(() => {
  const $ = id => document.getElementById(id);
  const tabs = [...document.querySelectorAll('[data-stage]')];
  const selectStage = tab => {
    tabs.forEach(item => { const active = item === tab; item.setAttribute('aria-selected', String(active)); item.tabIndex = active ? 0 : -1; $('stagePanel-' + item.dataset.stage).hidden = !active; });
  };
  tabs.forEach((tab, index) => { tab.addEventListener('click', () => selectStage(tab)); tab.addEventListener('keydown', event => { let next; if (event.key === 'ArrowRight') next = (index + 1) % tabs.length; if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length; if (event.key === 'Home') next = 0; if (event.key === 'End') next = tabs.length - 1; if (next !== undefined) { event.preventDefault(); selectStage(tabs[next]); tabs[next].focus(); } }); });
  const drawer = $('assistantDrawer'); if (!drawer) return;
  const pid = drawer.dataset.projectId;
  let previousFocus, timer, generation = 0, currentId, sending = false;
  const status = message => $('assistantStatus').textContent = message;
  const setBusy = busy => { sending = busy; $('assistantSubmit').disabled = busy; $('assistantSubmit').textContent = busy ? '处理中…' : '发送问题'; };
  const render = data => {
    const query = data.query; if (!query) return;
    currentId = query.id;
    $('assistantMode').textContent = query.provider === 'mock' ? '当前为演示模式。连接 AI 服务后可获得实际模型分析。' : `AI 服务：${query.provider}`;
    $('assistantResponse').hidden = false; $('assistantAsked').textContent = query.question;
    $('assistantAnswer').textContent = query.answer?.answer || '';
    $('assistantGaps').replaceChildren();
    (query.answer?.gaps || []).forEach(gap => { const p = document.createElement('p'); p.textContent = gap; $('assistantGaps').append(p); });
    $('assistantCitations').replaceChildren();
    (data.citations || []).forEach(citation => { const a = document.createElement('a'); a.href = citation.url; a.textContent = `${citation.ref} · ${citation.label}`; $('assistantCitations').append(a); });
    if (query.status === 'done' && !(data.citations || []).length) { const p = document.createElement('p'); p.textContent = '本次回答未提供可追溯引用，请结合原始记录核对。'; $('assistantCitations').append(p); }
    $('assistantFull').href = data.url;
  };
  async function refresh(token, attempt = 0) {
    try {
      const response = await fetch(`/api/projects/${pid}/assistant${currentId ? '?query_id=' + currentId : ''}`, {cache:'no-store'});
      if (!response.ok) throw new Error('暂时无法读取分析结果，请稍后重试。');
      const data = await response.json(); if (token !== generation) return;
      render(data);
      const pending = ['queued','running'].includes(data.query?.status);
      setBusy(pending);
      if (pending && attempt < 90 && !drawer.hidden) { status('正在分析当前项目证据…'); timer = setTimeout(() => refresh(token, attempt + 1), 2000); }
      else { setBusy(false); status(pending ? '分析仍在后台进行，可到完整问答或任务中心查看。' : data.query?.status === 'error' ? '分析未完成，请检查 AI 配置后重试。' : data.query ? '分析已完成，请结合引用核对结论。' : '选择一个方向，或输入你自己的问题。'); }
    } catch (error) { if (token === generation) { setBusy(false); status(error.message); } }
  }
  function open(question) {
    if (drawer.hidden) { previousFocus = document.activeElement; drawer.hidden = false; $('assistantBackdrop').hidden = false; document.querySelector('.shell').inert = true; document.body.classList.add('assistant-open'); clearTimeout(timer); refresh(++generation); }
    if (question) $('assistantQuestion').value = question;
    $('assistantQuestion').focus();
  }
  function close() { drawer.hidden = true; $('assistantBackdrop').hidden = true; document.querySelector('.shell').inert = false; document.body.classList.remove('assistant-open'); clearTimeout(timer); generation++; currentId = null; previousFocus?.focus(); }
  document.addEventListener('click', event => { const button = event.target.closest('[data-assistant-open],[data-assistant-question]'); if (button) { event.preventDefault(); open(button.dataset.assistantQuestion); } });
  $('assistantClose').addEventListener('click', close); $('assistantBackdrop').addEventListener('click', close);
  document.addEventListener('keydown', event => {
    if (drawer.hidden) return;
    if (event.key === 'Escape') { event.preventDefault(); close(); }
    if (event.key === 'Tab') { const focusable = [...drawer.querySelectorAll('button:not([disabled]),a[href],textarea')].filter(el => el.getClientRects().length); const first = focusable[0], last = focusable.at(-1); if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); } else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); } }
  });
  $('assistantForm').addEventListener('submit', async event => {
    event.preventDefault(); if (sending) return;
    clearTimeout(timer); const token = ++generation; setBusy(true); status('正在提交问题…');
    try {
      const response = await fetch(`/api/projects/${pid}/assistant`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({question:$('assistantQuestion').value})});
      const data = await response.json(); if (token !== generation) return;
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : '问题提交失败，请重试。');
      currentId = data.id; $('assistantResponse').hidden = true; await refresh(token);
    } catch (error) { if (token === generation) { setBusy(false); status(error.message); } }
  });
  const evidence = new URLSearchParams(location.search).get('ask_evidence');
  if (evidence && /^\d{1,12}$/.test(evidence)) open(`请解读诊断证据 utility:${evidence}，区分事实、风险线索和需要补充的验证。`);
})();
