(function () {
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const dict = window.PERO_I18N || {};

  function currentLang() {
    return localStorage.getItem('pero.lang') || 'zh';
  }

  function tKey(key, params) {
    let text = (dict[currentLang()] || {})[key] || key;
    if (params) {
      for (const k of Object.keys(params)) {
        text = text.replaceAll('{{' + k + '}}', params[k]);
      }
    }
    return text;
  }

  const SERVER_ERROR_KEYS = {
    invalid_credentials: 'server.auth.invalid_credentials',
    session_expired: 'server.auth.session_expired',
    password_mismatch: 'server.auth.password_mismatch',
    password_reset: 'server.auth.password_reset',
  };

  function toast(message) {
    const el = $('[data-toast]');
    if (!el) return;
    el.textContent = message || tKey('toast.done');
    el.classList.add('is-visible');
    window.clearTimeout(el._timer);
    el._timer = window.setTimeout(() => el.classList.remove('is-visible'), 2600);
  }

  function setLang(lang) {
    if (!dict[lang]) lang = 'zh';
    document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
    document.body.dataset.langCurrent = lang;
    localStorage.setItem('pero.lang', lang);

    $$('[data-i18n]').forEach((node) => {
      const value = dict[lang][node.dataset.i18n];
      if (value) node.textContent = value;
    });
    $$('[data-i18n-placeholder]').forEach((node) => {
      const value = dict[lang][node.dataset.i18nPlaceholder];
      if (value) node.setAttribute('placeholder', value);
    });
    $$('[data-server-message]').forEach((node) => {
      const slug = node.dataset.serverMessage;
      const key = SERVER_ERROR_KEYS[slug];
      if (key) {
        const value = dict[lang][key];
        if (value) node.textContent = value;
      }
    });
    $$('[data-lang]').forEach((button) => {
      button.classList.toggle('is-active', button.dataset.lang === lang);
    });
  }

  function initLanguage() {
    setLang(currentLang());
    $$('[data-lang]').forEach((button) => {
      button.addEventListener('click', () => setLang(button.dataset.lang));
    });
  }

  function initPasswordToggles() {
    $$('[data-toggle-password]').forEach((button) => {
      button.addEventListener('click', () => {
        const input = button.parentElement.querySelector('input');
        if (!input) return;
        input.type = input.type === 'password' ? 'text' : 'password';
        button.textContent = input.type === 'password' ? '👁' : '🙈';
      });
    });
  }

  function passwordLevel(value) {
    let level = 0;
    if (value.length >= 8) level += 1;
    if (/[A-Z]/.test(value) && /[a-z]/.test(value)) level += 1;
    if (/\d/.test(value)) level += 1;
    if (/[^A-Za-z0-9]/.test(value)) level += 1;
    return Math.min(level, 4);
  }

  function initPasswordStrength() {
    $$('[data-password-strength]').forEach((input) => {
      const form = input.closest('form') || document;
      const scope = form.parentElement || form;
      const meter = $('[data-password-meter]', scope) || $('[data-password-meter]', form);
      const text = $('[data-strength-text]', scope) || $('[data-strength-text]', form);
      input.addEventListener('input', () => {
        const level = passwordLevel(input.value);
        if (meter) meter.className = `password-meter level-${level}`;
        if (text) text.textContent = tKey('password.strength' + level);
      });
    });
  }

  function ensureValidForm(form) {
    if (!form.checkValidity()) {
      form.reportValidity();
      return false;
    }

    const password = $('[name="password"], [name="new_password"]', form);
    const confirm = $('[name="confirm_password"]', form);
    if (confirm && password && password.value !== confirm.value) {
      toast(tKey('toast.passwordMismatch'));
      confirm.focus();
      return false;
    }
    return true;
  }

  async function postForm(action, formData) {
    const params = new URLSearchParams();
    if (formData instanceof FormData) {
      formData.forEach((value, key) => params.append(key, value));
    }

    const response = await fetch(action, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
      credentials: 'same-origin',
    });

    const text = await response.text();
    let payload = null;
    if (text) {
      try { payload = JSON.parse(text); } catch (_) { payload = null; }
    }

    if (!response.ok) {
      const message = (payload && payload.message) || tKey('toast.requestFailed');
      throw new Error(message);
    }
    return payload || { message: tKey('toast.done') };
  }

  function initForms() {
    $$('form[data-password-confirm]').forEach((form) => {
      form.addEventListener('submit', (event) => {
        if (!ensureValidForm(form)) event.preventDefault();
      });
    });

    $$('form[data-ajax-form], form[data-ajax-row]').forEach((form) => {
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!ensureValidForm(form)) return;

        try {
          const data = await postForm(form.action || window.location.pathname, new FormData(form));
          const success = $('[data-form-success]', form);
          if (success) success.classList.remove('hidden');
          if (form.matches('[data-ajax-row]')) form.closest('tr, [data-provider-row]')?.remove();
          const toastKey = form.dataset.toastI18n;
          toast(toastKey ? tKey(toastKey) : (data.message || tKey('toast.done')));
          if (form.dataset.ajaxForm !== undefined && !form.matches('[data-ajax-row]')) {
            setTimeout(() => window.location.reload(), 600);
          }
        } catch (error) {
          toast(error.message || tKey('toast.error'));
        }
      });
    });
  }

  function initPostButtons() {
    $$('[data-post-action]:not([data-bulk-action])').forEach((button) => {
      button.addEventListener('click', async () => {
        const formData = new FormData();
        if (button.dataset.postField) {
          formData.append(button.dataset.postField, button.dataset.postValue || '');
        }

        try {
          const data = await postForm(button.dataset.postAction, formData);
          if (button.dataset.redirect) {
            window.location.href = button.dataset.redirect;
          } else {
            toast(button.dataset.toastI18n ? tKey(button.dataset.toastI18n) : (button.dataset.toastMessage || data.message || tKey('toast.done')));
          }
        } catch (error) {
          toast(error.message || tKey('toast.error'));
        }
      });
    });
  }

  function initToastButtons() {
    $$('[data-toast-message]:not([data-post-action])').forEach((button) => {
      button.addEventListener('click', () => {
        const key = button.dataset.toastI18n;
        const msg = key ? tKey(key) : button.dataset.toastMessage;
        toast(msg);
      });
    });
  }

  function initTabs() {
    $$('[data-tabs]').forEach((root) => {
      $$('[data-tab]', root).forEach((tab) => {
        tab.addEventListener('click', () => {
          const target = tab.dataset.tab;
          $$('[data-tab]', root).forEach((item) => item.classList.toggle('is-active', item === tab));
          $$('[data-tab-panel]').forEach((panel) => panel.classList.toggle('hidden', panel.dataset.tabPanel !== target));
        });
      });
    });
  }

  function initVerification() {
    $$('[data-verification]').forEach((root) => {
      const applyStatus = (status) => {
        root.dataset.activeStatus = status;
        $$('[data-state-panel]', root).forEach((panel) => {
          panel.classList.toggle('is-active', panel.dataset.statePanel === status);
        });
        $$('[data-status-switch]', root).forEach((button) => {
          button.classList.toggle('is-active', button.dataset.statusSwitch === status);
        });
      };

      applyStatus(root.dataset.activeStatus || 'success');
      $$('[data-status-switch]', root).forEach((button) => {
        button.addEventListener('click', () => applyStatus(button.dataset.statusSwitch));
      });
      $$('[data-scene]', root).forEach((button) => {
        button.addEventListener('click', () => {
          $$('[data-scene]', root).forEach((item) => item.classList.toggle('is-active', item === button));
          toast(button.textContent.trim());
        });
      });
    });
  }

  function initBulkTables() {
    ['authz', 'sessions'].forEach((scope) => {
      const selectAll = $(`[data-select-all="${scope}"]`);
      const countEl = $(`[data-selected-count="${scope}"]`);
      const action = $(`[data-bulk-action="${scope}"]`);
      const checkboxes = () => $$(`[data-row-checkbox="${scope}"]`).filter((box) => !box.disabled);

      const update = () => {
        const items = checkboxes();
        const selected = items.filter((box) => box.checked).length;
        if (countEl) countEl.textContent = String(selected);
        if (action) action.disabled = selected === 0;
        if (selectAll) selectAll.checked = items.length > 0 && selected === items.length;
      };

      if (selectAll) {
        selectAll.addEventListener('change', () => {
          checkboxes().forEach((box) => { box.checked = selectAll.checked; });
          update();
        });
      }

      checkboxes().forEach((box) => box.addEventListener('change', update));
      if (action) {
        action.addEventListener('click', async () => {
          const checked = checkboxes().filter((box) => box.checked);
          const field = action.dataset.postField;
          const endpoint = action.dataset.postAction;

          try {
            for (const box of checked) {
              const formData = new FormData();
              formData.append(field, box.value);
              await postForm(endpoint, formData);
              box.closest('tr')?.remove();
            }
            toast(scope === 'sessions' ? tKey('toast.sessionsTerminated') : tKey('toast.authorizationsRevoked'));
          } catch (error) {
            toast(error.message || tKey('toast.error'));
          } finally {
            update();
          }
        });
      }

      update();
    });
  }

  function initSocialActions() {
    $$('[data-bind]').forEach((button) => {
      button.addEventListener('click', () => {
        const provider = button.closest('[data-provider-row]')?.dataset.providerRow;
        if (provider) window.location.href = `/sso/social/${provider}/login`;
      });
    });

    $$('[data-unbind]').forEach((button) => {
      button.addEventListener('click', async () => {
        const row = button.closest('[data-provider-row]');
        const provider = row?.dataset.providerRow;
        if (!provider) return;

        const formData = new FormData();
        formData.append('provider', provider);
        try {
          const data = await postForm('/account/social/unbind', formData);
          row.remove();
          toast(tKey('toast.providerUnbound'));
        } catch (error) {
          toast(error.message || tKey('toast.error'));
        }
      });
    });
  }

  function initAvatar() {
    const preview = $('[data-avatar-preview]');
    const input = $('[data-avatar-url]');
    if (input && preview) {
      input.addEventListener('change', () => {
        if (!input.value) return;
        let img = preview.querySelector('img');
        if (!img) {
          img = document.createElement('img');
          preview.textContent = '';
          preview.appendChild(img);
        }
        img.src = input.value;
      });
    }

    const defaultBtn = $('[data-default-avatar]');
    if (defaultBtn && preview) {
      defaultBtn.addEventListener('click', () => {
        const img = preview.querySelector('img');
        if (img) img.remove();
        preview.textContent = preview.textContent.trim() || 'P';
        toast(tKey('toast.defaultAvatar'));
      });
    }

    const uploadBtn = $('[data-avatar-upload]');
    if (uploadBtn) {
      uploadBtn.addEventListener('click', () => toast(tKey('toast.uploadStub')));
    }
  }

  function initMobileNav() {
    const toggle = $('[data-nav-toggle]');
    const sidebar = $('[data-sidebar]');
    const backdrop = $('[data-nav-backdrop]');
    if (!toggle || !sidebar || !backdrop) return;

    const open = () => {
      sidebar.classList.add('is-open');
      backdrop.classList.add('is-open');
    };
    const close = () => {
      sidebar.classList.remove('is-open');
      backdrop.classList.remove('is-open');
    };

    toggle.addEventListener('click', open);
    backdrop.addEventListener('click', close);
  }

  function initUserMenu() {
    $$('[data-user-menu]').forEach((menu) => {
      const trigger = menu.querySelector('.header-user-trigger');
      const dropdown = menu.querySelector('[data-user-dropdown]');
      if (!trigger || !dropdown) return;

      const toggle = () => {
        const isOpen = dropdown.classList.toggle('is-open');
        trigger.setAttribute('aria-expanded', isOpen);
      };
      const close = (e) => {
        if (!menu.contains(e.target)) {
          dropdown.classList.remove('is-open');
          trigger.setAttribute('aria-expanded', 'false');
        }
      };

      trigger.addEventListener('click', toggle);
      document.addEventListener('click', close);
    });
  }

  function initLocalTimestamps() {
    $$('[data-local-ts]').forEach((el) => {
      const raw = el.getAttribute('data-local-ts');
      if (!raw) return;
      const ts = new Date(raw.replace(' ', 'T'));
      if (isNaN(ts.getTime())) return;
      const pad = (n) => String(n).padStart(2, '0');
      el.textContent = `${ts.getFullYear()}-${pad(ts.getMonth() + 1)}-${pad(ts.getDate())} ${pad(ts.getHours())}:${pad(ts.getMinutes())}`;
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    initLanguage();
    initPasswordToggles();
    initPasswordStrength();
    initTabs();
    initForms();
    initPostButtons();
    initToastButtons();
    initVerification();
    initBulkTables();
    initSocialActions();
    initAvatar();
    initMobileNav();
    initUserMenu();
    initLocalTimestamps();
  });
})();
