(function () {
  const Pero = window.Pero;
  const api = window.PeroNavigation = {};

  function initTabs() {
    Pero.$$('[data-tabs]').forEach((root) => {
      Pero.$$('[data-tab]', root).forEach((tab) => {
        tab.addEventListener('click', () => {
          const target = tab.dataset.tab;
          Pero.$$('[data-tab]', root).forEach((item) => item.classList.toggle('is-active', item === tab));
          Pero.$$('[data-tab-panel]').forEach((panel) => panel.classList.toggle('hidden', panel.dataset.tabPanel !== target));
        });
      });
    });
  }

  function initVerification() {
    Pero.$$('[data-verification]').forEach((root) => {
      const applyStatus = (status) => {
        root.dataset.activeStatus = status;
        Pero.$$('[data-state-panel]', root).forEach((panel) => {
          panel.classList.toggle('is-active', panel.dataset.statePanel === status);
        });
        Pero.$$('[data-status-switch]', root).forEach((button) => {
          button.classList.toggle('is-active', button.dataset.statusSwitch === status);
        });
      };

      applyStatus(root.dataset.activeStatus || 'success');
      Pero.$$('[data-status-switch]', root).forEach((button) => {
        button.addEventListener('click', () => applyStatus(button.dataset.statusSwitch));
      });
      Pero.$$('[data-scene]', root).forEach((button) => {
        button.addEventListener('click', () => {
          Pero.$$('[data-scene]', root).forEach((item) => item.classList.toggle('is-active', item === button));
          Pero.toast(button.textContent.trim());
        });
      });
    });
  }

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

  function initLocalTimestamps() {
    Pero.$$('[data-local-ts]').forEach((el) => {
      const raw = el.getAttribute('data-local-ts');
      if (!raw) return;
      const ts = new Date(raw.replace(' ', 'T'));
      if (Number.isNaN(ts.getTime())) return;
      const pad = (value) => String(value).padStart(2, '0');
      el.textContent = `${ts.getFullYear()}-${pad(ts.getMonth() + 1)}-${pad(ts.getDate())} ${pad(ts.getHours())}:${pad(ts.getMinutes())}`;
    });
  }

  api.init = function init() {
    initTabs();
    initVerification();
    initMobileNav();
    initUserMenu();
    initLocalTimestamps();
  };
})();
