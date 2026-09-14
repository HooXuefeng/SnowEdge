(() => {
  const $ = id => document.getElementById(id);
  let selected, result, asset, evidenceId, controller, sequence = 0;
  let networkTarget = '';
  const localInputs = new Map();
  const status = (message, error = false) => { $('toolStatus').textContent = message; $('toolStatus').classList.toggle('tool-error', error); };
  function reset() {
    controller?.abort(); sequence++; result = null; asset = null;
    $('toolResult').replaceChildren();
    ['toolCopy', 'toolDownload', 'toolNext', 'toolHandoff'].forEach(id => $(id).hidden = true);
    evidenceId = null;
    $('toolRun').disabled = false; $('toolRun').textContent = '运行工具'; $('toolOutput').setAttribute('aria-busy', 'false');
  }
  document.querySelectorAll('[data-tool]').forEach(button => button.addEventListener('click', () => {
    if (selected?.network === 'true') networkTarget = $('toolValue').value;
    else if (selected) localInputs.set(selected.tool, $('toolValue').value);
    reset(); selected = button.dataset;
    document.querySelectorAll('[data-tool]').forEach(b => { b.classList.toggle('active', b === button); b.setAttribute('aria-pressed', String(b === button)); });
    $('toolTitle').textContent = selected.name; $('toolDescription').textContent = selected.description;
    $('toolValue').value = selected.network === 'true' ? networkTarget : (localInputs.get(selected.tool) || ''); $('toolValue').placeholder = selected.placeholder;
    $('toolProjectField').hidden = selected.network !== 'true'; $('toolProject').required = selected.network === 'true';
    $('toolValueLabel').textContent = selected.network === 'true' ? '目标地址' : '待处理内容';
    $('toolPrivacy').textContent = selected.network === 'true' ? '脱敏诊断结果会保存为项目证据，便于回看和 AI 解读' : '在本机工作台处理，输入和结果不写入历史记录';
    status('准备就绪。输入内容后运行。');
  }));
  ['toolValue', 'toolProject'].forEach(id => $(id).addEventListener('input', () => { reset(); status('内容已更新，请重新运行。'); }));
  $('utilityForm').addEventListener('submit', async event => {
    event.preventDefault(); reset(); const current = sequence;
    controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), 16000);
    $('toolRun').disabled = true; $('toolRun').textContent = '正在运行…'; $('toolOutput').setAttribute('aria-busy', 'true'); status('正在处理，请稍候…');
    try {
      const response = await fetch('/api/tools/run', {method: 'POST', headers: {'Content-Type': 'application/json'}, signal: controller.signal, body: JSON.stringify({kind: selected.tool, value: $('toolValue').value, project_id: Number($('toolProject').value) || null})});
      const data = await response.json(); if (current !== sequence) return;
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : '输入内容不符合要求。');
      result = data.result;
      Object.entries(result).forEach(([label, value]) => {
        const row = document.createElement('div'); row.className = 'tool-result-row';
        const key = document.createElement('b'); key.textContent = label;
        const content = document.createElement('pre'); content.textContent = typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);
        row.append(key, content); $('toolResult').append(row);
      });
      status('处理完成'); $('toolCopy').hidden = false; $('toolDownload').hidden = false;
      if (data.asset_target) { asset = {kind: selected.tool, value: data.asset_target, project_id: data.project_id}; $('toolNext').hidden = false; $('toolSave').disabled = false; $('toolSave').textContent = '加入项目资产'; $('toolAssets').href = `/projects/${data.project_id}/attack-surface`; }
      if (data.evidence_id) {
        evidenceId = data.evidence_id; $('toolHandoff').hidden = false; $('toolEvidence').href = data.evidence_url; $('toolRequest').disabled = false;
        const question = `请解读诊断证据 utility:${evidenceId}，区分事实、风险线索和需要补充的验证。`;
        $('toolAi').href = `/projects/${data.project_id}/workbench?ask_evidence=${evidenceId}`;
        if ($('assistantDrawer')?.dataset.projectId === String(data.project_id)) $('toolAi').dataset.assistantQuestion = question;
        else delete $('toolAi').dataset.assistantQuestion;
      }
    } catch (error) { if (current === sequence) status(error.name === 'AbortError' ? '处理超时，请检查网络后重试。' : error.message, true); }
    finally { clearTimeout(timeout); if (current === sequence) { $('toolRun').disabled = false; $('toolRun').textContent = '重新运行'; $('toolOutput').setAttribute('aria-busy', 'false'); } }
  });
  $('toolCopy').addEventListener('click', async () => { try { await navigator.clipboard.writeText(JSON.stringify(result, null, 2)); status('结果已复制'); } catch { status('无法访问剪贴板，可以下载 JSON。', true); } });
  $('toolDownload').addEventListener('click', () => { const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], {type: 'application/json'})); const a = document.createElement('a'); a.href = url; a.download = `${selected.tool}-result.json`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); });
  $('toolSave').addEventListener('click', async () => {
    const current = sequence;
    $('toolSave').disabled = true;
    try { const response = await fetch('/api/tools/save-asset', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(asset)}); const data = await response.json(); if (current !== sequence) return; if (!response.ok) throw new Error(data.detail); $('toolSave').textContent = '已加入资产'; status(data.message); }
    catch (error) { if (current === sequence) { status(error.message, true); $('toolSave').disabled = false; } }
  });
  $('toolRequest').addEventListener('click', async () => {
    const current = sequence; $('toolRequest').disabled = true;
    try { const response = await fetch(`/api/projects/${asset.project_id}/diagnostics/${evidenceId}/request`, {method:'POST'}); const data = await response.json(); if (current !== sequence) return; if (!response.ok) throw new Error(data.detail); location.href = data.url; }
    catch (error) { if (current === sequence) { status(error.message, true); $('toolRequest').disabled = false; } }
  });
  $('toolSearch').addEventListener('input', () => {
    const query = $('toolSearch').value.trim().toLowerCase(); let matches = 0;
    document.querySelectorAll('[data-tool]').forEach(button => { button.hidden = !`${button.dataset.name} ${button.dataset.description} ${button.dataset.tool}`.toLowerCase().includes(query); if (!button.hidden) matches++; });
    document.querySelectorAll('.tool-catalog h2').forEach(heading => heading.hidden = !!query);
    $('toolSearchEmpty').hidden = matches > 0;
  });
  const desired = new URLSearchParams(location.search).get('tool') || (location.hash === '#local' ? 'json' : 'dns');
  ([...document.querySelectorAll('[data-tool]')].find(button => button.dataset.tool === desired) || document.querySelector('[data-tool]'))?.click();
})();
