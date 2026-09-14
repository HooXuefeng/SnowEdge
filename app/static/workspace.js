(() => {
  if (/^#evidence-\d+$/.test(location.hash)) document.getElementById(location.hash.slice(1))?.click();
  const toggle = document.getElementById('navToggle');
  const close = () => { document.body.classList.remove('navigation-open'); toggle?.setAttribute('aria-expanded', 'false'); };
  toggle?.addEventListener('click', () => { const open = document.body.classList.toggle('navigation-open'); toggle.setAttribute('aria-expanded', String(open)); });
  document.addEventListener('keydown', event => { if (event.key === 'Escape') close(); });
  document.addEventListener('click', event => { if (!event.target.closest('.sidebar, #navToggle')) close(); });
  document.querySelector('.side-link.active')?.setAttribute('aria-current', 'page');
  document.querySelectorAll('.inspector-source').forEach(row => row.addEventListener('keydown', event => {
    if (event.target === row && (event.key === 'Enter' || event.key === ' ')) { event.preventDefault(); window.openEntityInspector(row); }
  }));
})();
