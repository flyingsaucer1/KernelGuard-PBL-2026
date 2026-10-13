setInterval(() => {
  const editingFilter = document.querySelector('input:focus, select:focus');
  if (document.visibilityState === 'visible' && !editingFilter) {
    window.location.reload();
  }
}, 15000);
