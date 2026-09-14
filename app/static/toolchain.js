(() => {
  const root=document.getElementById('toolchainApp');if(!root)return;
  const base=`/api/projects/${root.dataset.project}/toolchain`;
  const grid=document.getElementById('toolchainGrid'),summary=document.getElementById('toolchainSummary');
  const select=document.getElementById('toolRunId'),portsLabel=document.getElementById('toolPortsLabel'),status=document.getElementById('toolRunStatus');
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
  select.addEventListener('change',()=>{const option=select.selectedOptions[0];portsLabel.hidden=!option||option.dataset.ports!=='true';});
  document.querySelectorAll('[data-plan]').forEach(button=>button.addEventListener('click',()=>{selectedPlan=button.dataset.plan;document.getElementById('toolRunTitle').textContent=`运行流程：${button.closest('.tool-plan').querySelector('h2').textContent}`;document.getElementById('toolSelectLabel').hidden=true;document.getElementById('singleToolMode').hidden=false;document.getElementById('toolRunButton').textContent='启动一键流程';document.getElementById('toolRunTarget').focus();}));
  document.getElementById('singleToolMode').addEventListener('click',()=>{selectedPlan='';document.getElementById('toolRunTitle').textContent='运行单个工具';document.getElementById('toolSelectLabel').hidden=false;document.getElementById('singleToolMode').hidden=true;document.getElementById('toolRunButton').textContent='加入任务队列';const option=select.selectedOptions[0];portsLabel.hidden=!option||option.dataset.ports!=='true';});
  document.getElementById('toolRunForm').addEventListener('submit',async e=>{e.preventDefault();const button=e.submitter;button.disabled=true;try{const payload={target:document.getElementById('toolRunTarget').value,ports:document.getElementById('toolRunPorts').value};if(selectedPlan){const result=await api(`/api/projects/${root.dataset.project}/toolchain-plans/${selectedPlan}/run`,'POST',payload);status.textContent=`${result.name} 已创建 ${result.jobs.length} 个任务${result.skipped.length?'，跳过 '+result.skipped.map(x=>x.tool).join('、'):''}`;}else{const result=await api(`${base}/${select.value}/run`,'POST',payload);status.textContent=`任务 #${result.id} 已加入队列：${result.tool} → ${result.target}`;}}catch(err){status.textContent=err.message;}finally{button.disabled=false;}});
  refresh().catch(err=>{grid.replaceChildren(el('div',err.message,'panel tool-loading'));});
})();
