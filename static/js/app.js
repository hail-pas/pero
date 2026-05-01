(function () {
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const dict = window.PERO_I18N || {};

  function toast(message) {
    const el = $('[data-toast]');
    if (!el) return;
    el.textContent = message || (localStorage.getItem('pero.lang') === 'en' ? 'Done' : '操作成功');
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
      const key = node.getAttribute('data-i18n');
      if (dict[lang][key]) node.textContent = dict[lang][key];
    });
    $$('[data-i18n-placeholder]').forEach((node) => {
      const key = node.getAttribute('data-i18n-placeholder');
      if (dict[lang][key]) node.setAttribute('placeholder', dict[lang][key]);
    });
    $$('[data-lang]').forEach((button) => button.classList.toggle('is-active', button.dataset.lang === lang));
  }

  function initLanguage() {
    const saved = localStorage.getItem('pero.lang') || 'zh';
    setLang(saved);
    $$('[data-lang]').forEach((button) => button.addEventListener('click', () => setLang(button.dataset.lang)));
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
      const meter = $('[data-password-meter]', form.parentElement || form) || $('[data-password-meter]', form);
      const text = $('[data-strength-text]', form.parentElement || form) || $('[data-strength-text]', form);
      const labels = {
        zh: ['—', '弱', '一般', '中等', '强'],
        en: ['—', 'Weak', 'Fair', 'Medium', 'Strong']
      };
      input.addEventListener('input', () => {
        const level = passwordLevel(input.value);
        if (meter) {
          meter.className = `password-meter level-${level}`;
        }
        if (text) {
          const lang = localStorage.getItem('pero.lang') || 'zh';
          text.textContent = labels[lang][level];
        }
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

  function initForms() {
    $$('form[data-form]').forEach((form) => {
      form.addEventListener('submit', (event) => {
        event.preventDefault();
        const invalid = !form.checkValidity();
        if (invalid) {
          form.reportValidity();
          return;
        }
        const password = $('[name="password"]', form);
        const confirm = $('[name="confirm_password"]', form);
        if (password && confirm && password.value !== confirm.value) {
          toast(localStorage.getItem('pero.lang') === 'en' ? 'Passwords do not match.' : '两次输入的密码不一致');
          confirm.focus();
          return;
        }

        const formName = form.dataset.form;
        const isAccountForm = ['profile', 'change-password'].includes(formName);
        if (!isAccountForm) {
          const success = $('[data-form-success]', form);
          if (success) success.classList.remove('hidden');
          toast(localStorage.getItem('pero.lang') === 'en' ? 'Submitted successfully' : '提交成功');
          return;
        }

        const formData = new FormData(form);
        fetch(form.action || window.location.pathname, {
          method: 'POST',
          body: formData,
          credentials: 'same-origin',
        })
          .then((res) => res.json())
          .then((data) => {
            if (data.ok || data.message) {
              const success = $('[data-form-success]', form);
              if (success) success.classList.remove('hidden');
              toast(data.message || (localStorage.getItem('pero.lang') === 'en' ? 'Saved' : '已保存'));
            } else {
              toast(data.error || (localStorage.getItem('pero.lang') === 'en' ? 'Error' : '出错了'));
            }
          })
          .catch(() => {
            toast(localStorage.getItem('pero.lang') === 'en' ? 'Network error' : '网络错误');
          });
      });
    });
  }

  function initToastButtons() {
    $$('[data-toast-message]').forEach((button) => {
      button.addEventListener('click', () => toast(button.getAttribute('data-toast-message')));
    });
  }

  function initVerification() {
    $$('[data-verification]').forEach((root) => {
      const applyStatus = (status) => {
        root.dataset.activeStatus = status;
        $$('[data-state-panel]', root).forEach((panel) => panel.classList.toggle('is-active', panel.dataset.statePanel === status));
        $$('[data-status-switch]', root).forEach((btn) => btn.classList.toggle('is-active', btn.dataset.statusSwitch === status));
      };
      applyStatus(root.dataset.activeStatus || 'success');
      $$('[data-status-switch]', root).forEach((button) => button.addEventListener('click', () => applyStatus(button.dataset.statusSwitch)));
      $$('[data-scene]', root).forEach((button) => button.addEventListener('click', () => {
        $$('[data-scene]', root).forEach((btn) => btn.classList.toggle('is-active', btn === button));
        toast(button.textContent.trim());
      }));
    });
  }

  function initBulkTables() {
    ['authz', 'sessions'].forEach((scope) => {
      const selectAll = $(`[data-select-all="${scope}"]`);
      const checkboxes = () => $$(`[data-row-checkbox="${scope}"]`).filter((box) => !box.disabled && box.closest('tr'));
      const countEl = $(`[data-selected-count="${scope}"]`);
      const action = $(`[data-bulk-action="${scope}"]`);
      const update = () => {
        const selected = checkboxes().filter((box) => box.checked).length;
        if (countEl) countEl.textContent = String(selected);
        if (action) action.disabled = selected === 0;
        if (selectAll) selectAll.checked = selected > 0 && selected === checkboxes().length;
      };
      if (selectAll) selectAll.addEventListener('change', () => {
        checkboxes().forEach((box) => { box.checked = selectAll.checked; });
        update();
      });
      checkboxes().forEach((box) => box.addEventListener('change', update));
      if (action) action.addEventListener('click', () => {
        const checked = checkboxes().filter((box) => box.checked);
        checked.forEach((box) => {
          const row = box.closest('tr');
          const form = document.createElement('form');
          form.method = 'POST';
          form.style.display = 'none';
          if (scope === 'authz') {
            form.action = '/account/authorizations/revoke';
            const input = document.createElement('input');
            input.name = 'token_id';
            input.value = box.value || '';
            form.appendChild(input);
          } else {
            form.action = '/account/sessions/delete';
            const input = document.createElement('input');
            input.name = 'session_id';
            input.value = box.value || '';
            form.appendChild(input);
          }
          document.body.appendChild(form);
          fetch(form.action, {
            method: 'POST',
            body: new FormData(form),
            credentials: 'same-origin',
          }).catch(() => {});
          document.body.removeChild(form);
          if (row) row.remove();
        });
        update();
        toast(scope === 'sessions' ? (localStorage.getItem('pero.lang') === 'en' ? 'Sessions terminated' : '已登出所选会话') : (localStorage.getItem('pero.lang') === 'en' ? 'Authorizations revoked' : '已撤销所选授权'));
      });
      update();
    });

    $$('[data-row-remove]').forEach((button) => {
      button.addEventListener('click', () => {
        const row = button.closest('tr');
        const form = document.createElement('form');
        form.method = 'POST';
        form.style.display = 'none';
        if (row && row.querySelector('[name="token_id"]')) {
          form.action = '/account/authorizations/revoke';
        } else {
          form.action = '/account/sessions/delete';
        }
        document.body.appendChild(form);
        fetch(form.action, {
          method: 'POST',
          body: new FormData(form),
          credentials: 'same-origin',
        }).catch(() => {});
        document.body.removeChild(form);
        if (row) row.remove();
        toast(button.textContent.trim());
      });
    });
  }

  function initSocialActions() {
    $$('[data-bind]').forEach((button) => {
      button.addEventListener('click', () => {
        const row = button.closest('[data-provider-row]');
        const provider = row ? row.dataset.providerRow : '';
        if (provider) {
          window.location.href = `/sso/social/${provider}/login`;
        }
      });
    });
    $$('[data-unbind]').forEach((button) => {
      button.addEventListener('click', () => {
        const row = button.closest('[data-provider-row]');
        const provider = row ? row.dataset.providerRow : '';
        if (!provider) return;
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/account/social/unbind';
        form.style.display = 'none';
        const input = document.createElement('input');
        input.name = 'provider';
        input.value = provider;
        form.appendChild(input);
        document.body.appendChild(form);
        fetch(form.action, {
          method: 'POST',
          body: new FormData(form),
          credentials: 'same-origin',
        })
          .then((res) => res.json())
          .then(() => {
            if (row) row.remove();
            toast(localStorage.getItem('pero.lang') === 'en' ? 'Provider unbound' : '账号已解绑');
          })
          .catch(() => {
            toast(localStorage.getItem('pero.lang') === 'en' ? 'Error' : '出错了');
          });
        document.body.removeChild(form);
      });
    });
  }

  function initAvatar() {
    const preview = $('[data-avatar-preview]');
    const input = $('[data-avatar-url]');
    if (input && preview) {
      input.addEventListener('change', () => {
        if (!input.value) return;
        preview.style.backgroundImage = `url(${input.value})`;
        preview.style.backgroundSize = 'cover';
        preview.textContent = '';
      });
    }
    const defaultBtn = $('[data-default-avatar]');
    if (defaultBtn && preview) defaultBtn.addEventListener('click', () => {
      preview.removeAttribute('style');
      preview.textContent = '张';
      toast(localStorage.getItem('pero.lang') === 'en' ? 'Default avatar applied' : '已使用默认头像');
    });
    const uploadBtn = $('[data-avatar-upload]');
    if (uploadBtn) uploadBtn.addEventListener('click', () => toast(localStorage.getItem('pero.lang') === 'en' ? 'Connect this button to your upload API.' : '请接入你的上传接口'));
  }

  function initMobileNav() {
    const toggle = $('[data-nav-toggle]');
    const sidebar = $('[data-sidebar]');
    const backdrop = $('[data-nav-backdrop]');
    if (!toggle || !sidebar || !backdrop) return;
    const open = () => { sidebar.classList.add('is-open'); backdrop.classList.add('is-open'); };
    const close = () => { sidebar.classList.remove('is-open'); backdrop.classList.remove('is-open'); };
    toggle.addEventListener('click', open);
    backdrop.addEventListener('click', close);
  }

  function initLogout() {
    $$('[data-logout]').forEach((button) => {
      button.addEventListener('click', () => {
        fetch('/auth/logout', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
        })
          .then(() => {
            toast(localStorage.getItem('pero.lang') === 'en' ? 'Signed out' : '已退出登录');
            window.setTimeout(() => { window.location.href = '/login'; }, 600);
          })
          .catch(() => {
            toast(localStorage.getItem('pero.lang') === 'en' ? 'Error' : '出错了');
          });
      });
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    initLanguage();
    initPasswordToggles();
    initPasswordStrength();
    initTabs();
    initForms();
    initToastButtons();
    initVerification();
    initBulkTables();
    initSocialActions();
    initAvatar();
    initMobileNav();
    initLogout();
  });
})();
