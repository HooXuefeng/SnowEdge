(async()=>{
 const pages=document.querySelector('#reportPages'),status=document.querySelector('#previewStatus'),number=document.querySelector('#previewPage'),go=document.querySelector('#previewGo');
 if(!pages)return;
 const zoom=document.querySelector('#previewZoom');zoom.addEventListener('input',()=>{pages.style.setProperty('--page-width',`${794*Number(zoom.value)/100}px`);document.querySelector('#previewZoomValue').value=zoom.value+'%';});
 try{
  const response=await fetch(pages.dataset.url);const result=await response.json();if(!response.ok)throw new Error(result.detail||'页面生成失败');
  number.max=result.pages;number.disabled=false;go.disabled=false;status.textContent=`共 ${result.pages} 页，滚动查看或输入页码跳转。`;
  for(let i=1;i<=result.pages;i++){
   const figure=document.createElement('figure');figure.id='report-page-'+i;
   const img=document.createElement('img');img.alt=`正式报告第 ${i} 页`;img.loading=i===1?'eager':'lazy';img.src=pages.dataset.url+'/'+i;
   const caption=document.createElement('figcaption');caption.textContent=`第 ${i} 页 / 共 ${result.pages} 页`;
   img.addEventListener('error',()=>{figure.classList.add('preview-page-error');caption.textContent=`第 ${i} 页加载失败，请刷新后重试。`;});
   figure.append(img,caption);pages.append(figure);
  }
  go.addEventListener('click',()=>{const n=Math.max(1,Math.min(result.pages,Number(number.value)||1));number.value=n;const target=document.getElementById('report-page-'+n);pages.scrollTo({top:target.offsetTop-pages.offsetTop-24,behavior:'smooth'});});
 }catch(error){status.textContent='预览未生成：'+error.message+'。可先导出 HTML、JSON、CSV 或 DOCX。';}
})();
