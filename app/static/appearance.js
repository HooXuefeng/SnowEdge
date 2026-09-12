(() => {
  const picker = document.getElementById('displayScale');
  if (!picker) return;
  const choices = ['1', '1.1', '1.2'];
  const apply = value => {
    const scale = choices.includes(value) ? value : '1';
    picker.value = scale;
    document.documentElement.style.zoom = scale;
  };
  try { apply(localStorage.getItem('snowedge-display-scale')); } catch { apply('1'); }
  picker.addEventListener('change', () => {
    apply(picker.value);
    try { localStorage.setItem('snowedge-display-scale', picker.value); } catch {}
  });
})();
