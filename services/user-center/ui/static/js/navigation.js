(function () {
  const Pero = window.Pero;
  const api = window.PeroNavigation = {};

  function initMobileNav() {
    const toggle = Pero.$('[data-nav-toggle]');
    const sidebar = Pero.$('[data-sidebar]');
    const backdrop = Pero.$('[data-nav-backdrop]');
    if (!toggle || !sidebar || !backdrop) return;

    toggle.addEventListener('click', () => {
      sidebar.classList.add('is-open');
      backdrop.classList.add('is-open');
    });
    backdrop.addEventListener('click', () => {
      sidebar.classList.remove('is-open');
      backdrop.classList.remove('is-open');
    });
  }

  function initUserMenu() {
    Pero.$$('[data-user-menu]').forEach((menu) => {
      const trigger = menu.querySelector('.header-user-trigger');
      const dropdown = menu.querySelector('[data-user-dropdown]');
      if (!trigger || !dropdown) return;

      trigger.addEventListener('click', () => {
        const isOpen = dropdown.classList.toggle('is-open');
        trigger.setAttribute('aria-expanded', isOpen);
      });
      document.addEventListener('click', (event) => {
        if (!menu.contains(event.target)) {
          dropdown.classList.remove('is-open');
          trigger.setAttribute('aria-expanded', 'false');
        }
      });
    });
  }

  function parseTimestamp(raw) {
    const value = String(raw || '').trim();
    if (!value) return null;

    const match = value.match(/^(\d{4})-(\d{1,2})-(\d{1,2})[T ](\d{1,2}):(\d{1,2}):(\d{1,2})(\.\d+)?(?:\s*(Z|UTC|[+-]\d{2}:\d{2}(?::\d{2})?))?$/i);
    if (match) {
      const fraction = match[7] ? match[7].slice(1, 4).padEnd(3, '0') : '0';
      const zone = match[8] || 'Z';
      let offsetMs = 0;

      if (zone !== 'Z' && zone.toUpperCase() !== 'UTC') {
        const offset = zone.match(/^([+-])(\d{2}):(\d{2})(?::(\d{2}))?$/);
        if (!offset) return null;
        const sign = offset[1] === '-' ? -1 : 1;
        const totalSeconds = Number(offset[2]) * 3600 + Number(offset[3]) * 60 + Number(offset[4] || 0);
        offsetMs = sign * totalSeconds * 1000;
      }

      const utcMs = Date.UTC(
        Number(match[1]),
        Number(match[2]) - 1,
        Number(match[3]),
        Number(match[4]),
        Number(match[5]),
        Number(match[6]),
        Number(fraction)
      ) - offsetMs;
      const date = new Date(utcMs);
      return Number.isNaN(date.getTime()) ? null : date;
    }

    const fallback = new Date(value);
    return Number.isNaN(fallback.getTime()) ? null : fallback;
  }

  function formatLocalTimestamp(raw) {
    const value = String(raw || '').trim();
    if (!value) return '';

    const ts = parseTimestamp(value);
    if (!ts) return value;
    var pad = function (v) { return String(v).padStart(2, '0'); };
    return ts.getFullYear() + '-' + pad(ts.getMonth() + 1) + '-' + pad(ts.getDate()) + ' ' + pad(ts.getHours()) + ':' + pad(ts.getMinutes());
  }

  api.formatLocalTimestamp = formatLocalTimestamp;

  function initLocalTimestamps() {
    Pero.$$('[data-local-ts]').forEach((el) => {
      const raw = el.getAttribute('data-local-ts') || '';
      const rendered = formatLocalTimestamp(raw);
      if (rendered) el.textContent = rendered;
    });
  }

  api.init = function init() {
    initMobileNav();
    initUserMenu();
    initLocalTimestamps();
  };
})();
