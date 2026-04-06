// es-prefs.js — Preferences load/save
'use strict';

function initPrefs() {
  // Theme (light/dark) — stored in localStorage as UI pref only
  const saved = localStorage.getItem('es_theme');
  if (saved === 'light') _applyTheme('light');

  const btn = document.getElementById('themeToggle');
  if (btn) btn.addEventListener('click', () => {
    const next = document.documentElement.classList.contains('light') ? 'dark' : 'light';
    _applyTheme(next);
    localStorage.setItem('es_theme', next);
  });
}

function _applyTheme(theme) {
  const html = document.documentElement;
  const btn  = document.getElementById('themeToggle');
  if (theme === 'light') {
    html.classList.add('light');
    if (btn) btn.textContent = '\u263c Dark';
  } else {
    html.classList.remove('light');
    if (btn) btn.textContent = '\u263c Light';
  }
  // Redraw any visible canvas charts
  _redrawVisibleCharts();
}

function _redrawVisibleCharts() {
  // Re-trigger the active tab's render so canvas charts pick up new themeC() values
  const active = document.querySelector('.tab.active');
  if (active && active.dataset.tab) switchTab(active.dataset.tab);
}

function savePrefs() {}
function loadPrefs() {}
