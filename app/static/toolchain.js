(() => {
  const root=document.getElementById('toolchainApp');if(!root)return;
  const base=`/api/projects/${root.dataset.project}/toolchain`;
  const grid=document.getElementById('toolchainGrid'),summary=document.getElementById('toolchainSummary');
  const select=document.getElementById('toolRunId'),portsLabel=document.getElementById('toolPortsLabel'),status=document.getElementById('toolRunStatus');
  const runsRoot=document.getElementById('toolchainRuns');
  let tools=[];
  let selectedPlan='';
  async function api(url,method='GET',body){const r=await fetch(url,{method,headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});const data=await r.json();if(!r.ok)throw Error(data.detail||'请求失败');return data;}
  const el=(tag,text='',className='')=>{const node=document.createElement(tag);node.textContent=text;if(className)node.className=className;return node;};
  function render(){
    const installed=tools.filter(t=>t.installed).length;summary.replaceChildren(el('span',`已安装 ${installed}`),el('span',`待配置 ${tools.length-installed}`),el('span',`适配器 ${tools.length}`));grid.replaceChildren();select.replaceChildren();
    for(const tool of tools){
      const option=el('option',`${tool.name}${tool.installed?'':'（未安装）'}`);option.value=tool.id;option.disabled=!tool.installed;option.dataset.ports=String(tool.accepts_ports);select.append(option);
      const card=el('article','', 'panel tool-card');const head=el('div','', 'tool-card-head');const title=el('div');title.append(el('h2',tool.name),el('div',tool.phase,'tool-phase'));head.append(title,el('span',tool.installed?'已就绪':'未检测到',`tool-state${tool.installed?' ready':''}`));card.append(head,el('p',tool.description,'tool-description'));
      const results=el('div','', 'tool-results');tool.result_types.forEach(x=>results.append(el('span',x)));card.append(results,el('div',tool.version||'尚未读取版本','tool-version'),el('div',tool.executable||'未配置可执行文件','tool-path'));
      const form=el('form','', 'tool-path-form');const input=el('input');input.placeholder='自定义可执行文件绝对路径';input.value=tool.executable||'';const save=el('button','保存路径','btn');save.type='submit';form.append(input,save);form.addEventListener('submit',async e=>{e.preventDefault();save.disabled=true;try{await api(`${base}/${tool.id}/path`,'POST',{path:input.value});await refresh();}catch(err){status.textContent=err.message;}finally{save.disabled=false;}});card.append(form);const docs=el('a','官方文档 →','tool-doc');docs.href=tool.homepage;docs.target='_blank';docs.rel='noopener noreferrer';card.append(docs);grid.append(card);
    }
    const first=[...select.options].find(x=>!x.disabled);if(first){select.value=first.value;portsLabel.hidden=first.dataset.ports!=='true';}else{select.append(el('option','请先安装或配置工具'));}
  }
  async function refresh(){tools=await api(base);render();}
  const stateText={queued:'等待',pending:'等待',queueing:'正在创建任务',running:'执行中',done:'完成',error:'失败',cancelled:'已取消',skipped:'已跳过'};
  async function refreshRuns(){
    const runs=await api(`/api/projects/${root.dataset.project}/toolchain-runs`);runsRoot.replaceChildren();
    if(!runs.length){runsRoot.append(el('div','暂无流程记录。','empty small'));return;}
    for(const run of runs){
      const article=el('article','',`flow-run ${run.status}`),head=el('div','', 'flow-head'),heading=el('div');
      heading.append(el('h3',`#${run.id} ${run.name}`),el('small',`${run.target} · ${stateText[run.status]||run.status}`));head.append(heading);
      const steps=el('div','', 'flow-steps');run.steps.forEach((step,index)=>{if(index)steps.append(el('i','→','flow-arrow'));const box=el('div','',`flow-step ${step.status}`);box.append(el('span',`${step.position}. ${step.name} · ${stateText[step.status]||step.status}`));if(step.status==='error'){const retry=el('button','重试','flow-retry');retry.type='button';retry.addEventListener('click',async()=>{retry.disabled=true;try{await api(`/api/projects/${root.dataset.project}/toolchain-runs/${run.id}/steps/${step.id}/retry`,'POST',{});await refreshRuns();}catch(err){status.textContent=err.message;}finally{retry.disabled=false;}});box.append(retry);}steps.append(box);});
      article.append(head,steps);if(run.error)article.append(el('div',run.error,'flow-error'));runsRoot.append(article);
    }
  }
  select.addEventListener('change',()=>{const option=select.selectedOptions[0];portsLabel.hidden=!option||option.dataset.ports!=='true';});
  document.querySelectorAll('[data-plan]').forEach(button=>button.addEventListener('click',()=>{selectedPlan=button.dataset.plan;document.getElementById('toolRunTitle').textContent=`运行流程：${button.closest('.tool-plan').querySelector('h2').textContent}`;document.getElementById('toolSelectLabel').hidden=true;document.getElementById('singleToolMode').hidden=false;document.getElementById('toolRunButton').textContent='启动一键流程';document.getElementById('toolRunTarget').focus();}));
  document.getElementById('singleToolMode').addEventListener('click',()=>{selectedPlan='';document.getElementById('toolRunTitle').textContent='运行单个工具';document.getElementById('toolSelectLabel').hidden=false;document.getElementById('singleToolMode').hidden=true;document.getElementById('toolRunButton').textContent='加入任务队列';const option=select.selectedOptions[0];portsLabel.hidden=!option||option.dataset.ports!=='true';});
  document.getElementById('toolRunForm').addEventListener('submit',async e=>{e.preventDefault();const button=e.submitter;button.disabled=true;try{const payload={target:document.getElementById('toolRunTarget').value,ports:document.getElementById('toolRunPorts').value};if(selectedPlan){const result=await api(`/api/projects/${root.dataset.project}/toolchain-plans/${selectedPlan}/run`,'POST',payload);status.textContent=`流程 #${result.id} 已启动，共 ${result.total_steps} 步${result.skipped.length?'，未配置 '+result.skipped.map(x=>x.tool).join('、'):''}`;await refreshRuns();}else{const result=await api(`${base}/${select.value}/run`,'POST',payload);status.textContent=`任务 #${result.id} 已加入队列：${result.tool} → ${result.target}`;}}catch(err){status.textContent=err.message;}finally{button.disabled=false;}});
  document.getElementById('refreshRuns').addEventListener('click',()=>refreshRuns().catch(err=>{status.textContent=err.message;}));
  refresh().catch(err=>{grid.replaceChildren(el('div',err.message,'panel tool-loading'));});
  refreshRuns().catch(err=>{runsRoot.replaceChildren(el('div',err.message,'empty small'));});
  window.setInterval(()=>{if(!document.hidden)refreshRuns().catch(()=>{});},4000);
})();
