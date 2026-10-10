try {
  const saved = localStorage.getItem('aihax_theme');
  const theme = saved === 'light' || saved === 'dark' || saved === 'system' ? saved : 'dark';
  document.documentElement.classList.remove('light', 'dark');
  document.documentElement.classList.add(
    theme === 'system' ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme,
  );
} catch {
  // Keep the default dark theme when storage is unavailable.
}
