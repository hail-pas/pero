(function () {
  const Pero = window.Pero;
  const api = window.PeroForms = {};

  function passwordLevel(value) {
    let level = 0;
    if (value.length >= 8) level += 1;
    if (/[A-Z]/.test(value) && /[a-z]/.test(value)) level += 1;
    if (/\d/.test(value)) level += 1;
    if (/[^A-Za-z0-9]/.test(value)) level += 1;
    return Math.min(level, 4);
  }

  function ensureValidForm(form) {
    if (!form.checkValidity()) {
      form.reportValidity();
      return false;
    }

    const password = Pero.$('[name="password"], [name="new_password"]', form);
    const confirm = Pero.$('[name="confirm_password"]', form);
    if (confirm && password && password.value !== confirm.value) {
      Pero.toast(Pero.t('toast.passwordMismatch'));
      confirm.focus();
      return false;
    }
    return true;
  }

  function stripEmptyOptionalFields(form) {
    if (!form.hasAttribute('data-strip-empty')) return;
    Pero.$$('input:not([required]):not([type="hidden"]),select:not([required])', form).forEach(function (input) {
      if (input.value === '' && input.name) input.disabled = true;
    });
  }

  function localizedMessage(raw, fallbackKey) {
    if (Pero.message) return Pero.message(raw, fallbackKey);
    return raw || (fallbackKey ? Pero.t(fallbackKey) : Pero.t('toast.error'));
  }

  function setButtonBusy(button, busy) {
    if (!button) return;
    if (busy) {
      if (button.dataset.busy === 'true') return;
      button.dataset.busy = 'true';
      button.dataset.wasDisabled = button.disabled ? 'true' : 'false';
      button.disabled = true;
      button.classList.add('is-loading');
      button.setAttribute('aria-busy', 'true');
      return;
    }

    const wasDisabled = button.dataset.wasDisabled === 'true';
    delete button.dataset.busy;
    delete button.dataset.wasDisabled;
    button.disabled = wasDisabled;
    button.classList.remove('is-loading');
    button.removeAttribute('aria-busy');
  }

  function setFormBusy(form, busy) {
    if (busy) {
      if (form.dataset.busy === 'true') return;
      form.dataset.busy = 'true';
      form.setAttribute('aria-busy', 'true');
      Pero.$$('button', form).forEach((button) => setButtonBusy(button, true));
      return;
    }

    delete form.dataset.busy;
    form.removeAttribute('aria-busy');
    Pero.$$('button', form).forEach((button) => setButtonBusy(button, false));
  }

  api.postForm = async function postForm(action, formData) {
    const params = new URLSearchParams();
    if (formData instanceof FormData) {
      formData.forEach((value, key) => params.append(key, value));
    }

    const csrf = readCsrfToken();
    if (csrf) params.set('csrf_token', csrf);

    const response = await fetch(action, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
      credentials: 'same-origin',
      redirect: 'error',
    });

    if (!response.headers.get('content-type')?.toLowerCase().includes('application/json')) {
      throw new Error(Pero.t('toast.requestFailed'));
    }
    let payload;
    try { payload = await response.json(); } catch (_) {
      throw new Error(Pero.t('toast.requestFailed'));
    }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new Error(Pero.t('toast.requestFailed'));
    }

    const failedCode = payload && Object.prototype.hasOwnProperty.call(payload, 'code')
      && Number(payload.code) !== 0;
    const errorMessage = payload && (payload.error || (failedCode ? payload.message : ''));
    if (!response.ok || errorMessage) {
      throw new Error(localizedMessage(errorMessage || (payload && payload.message), 'toast.requestFailed'));
    }
    return payload || { message: Pero.t('toast.done') };
  };

  function initPasswordToggles() {
    Pero.$$('[data-toggle-password]').forEach((button) => {
      button.setAttribute('aria-pressed', 'false');
      button.setAttribute('aria-label', Pero.t('common.showPassword'));
      button.addEventListener('click', () => {
        const input = button.parentElement.querySelector('input');
        if (!input) return;
        input.type = input.type === 'password' ? 'text' : 'password';
        const visible = input.type === 'text';
        button.textContent = visible ? '👁' : '🙈';
        button.setAttribute('aria-pressed', visible ? 'true' : 'false');
        button.setAttribute('aria-label', Pero.t(visible ? 'common.hidePassword' : 'common.showPassword'));
      });
    });
  }

  function initPasswordStrength() {
    Pero.$$('[data-password-strength]').forEach((input) => {
      const form = input.closest('form') || document;
      const scope = form.parentElement || form;
      const meter = Pero.$('[data-password-meter]', scope) || Pero.$('[data-password-meter]', form);
      const text = Pero.$('[data-strength-text]', scope) || Pero.$('[data-strength-text]', form);
      input.addEventListener('input', () => {
        const level = passwordLevel(input.value);
        if (meter) meter.className = `password-meter level-${level}`;
        if (text) text.textContent = Pero.t('password.strength' + level);
      });
    });
  }

  function initForms() {
    Pero.$$('form[novalidate]:not([data-ajax-form])').forEach((form) => {
      form.addEventListener('submit', (event) => {
        if (form.dataset.busy === 'true') {
          event.preventDefault();
          return;
        }
        if (!ensureValidForm(form)) {
          event.preventDefault();
          return;
        }
        const csrf = readCsrfToken();
        const csrfInput = Pero.$('[name="csrf_token"]', form);
        if (csrf && csrfInput) csrfInput.value = csrf;
        stripEmptyOptionalFields(form);
        setFormBusy(form, true);
      });
    });

    Pero.$$('form[data-ajax-form]').forEach((form) => {
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (form.dataset.busy === 'true') return;
        if (!ensureValidForm(form)) return;

        const formData = new FormData(form);
        setFormBusy(form, true);
        let willNavigate = false;
        try {
          const data = await api.postForm(form.action || window.location.pathname, formData);
          const success = Pero.$('[data-form-success]', form) || Pero.$('[data-form-success]', form.parentElement || form);
          if (success) success.classList.remove('hidden');
          const toastKey = form.dataset.toastI18n;
          Pero.toast(toastKey ? Pero.t(toastKey) : localizedMessage(data.message, 'toast.done'));
          const redirect = form.dataset.redirect;
          willNavigate = true;
          setTimeout(function () {
            if (redirect) {
              window.location.href = redirect;
            } else {
              window.location.reload();
            }
          }, 600);
        } catch (error) {
          Pero.toast(error.message || Pero.t('toast.error'));
        } finally {
          if (!willNavigate) setFormBusy(form, false);
        }
      });
    });
  }

  function readCsrfToken() {
    const match = document.cookie.match(/(?:^|;\s*)pero_csrf=([^;]*)/);
    return match ? decodeURIComponent(match[1]) : '';
  }

  function initPostButtons() {
    Pero.$$('[data-post-action]').forEach((button) => {
      button.addEventListener('click', async () => {
        if (button.dataset.busy === 'true') return;
        const formData = new FormData();
        const csrf = readCsrfToken();
        if (csrf) formData.append('csrf_token', csrf);
        if (button.dataset.postField) {
          formData.append(button.dataset.postField, button.dataset.postValue || '');
        }

        setButtonBusy(button, true);
        let willNavigate = false;
        try {
          const data = await api.postForm(button.dataset.postAction, formData);
          const key = button.dataset.toastI18n;
          if (button.dataset.redirect) {
            let url = button.dataset.redirect;
            if (data && data.nonce) {
              url += (url.indexOf('?') >= 0 ? '&' : '?') + 'nonce=' + encodeURIComponent(data.nonce);
            }
            willNavigate = true;
            window.location.href = url;
          } else if (data && data.nonce) {
            if (key) Pero.toast(Pero.t(key));
            willNavigate = true;
            setTimeout(function () {
              window.location.href = '/account/profile/verify-contact?nonce=' + encodeURIComponent(data.nonce);
            }, 300);
          } else {
            Pero.toast(key ? Pero.t(key) : (button.dataset.toastMessage || localizedMessage(data.message, 'toast.done')));
            if (button.dataset.reload !== 'false') {
              willNavigate = true;
              setTimeout(function () { window.location.reload(); }, 600);
            }
          }
        } catch (error) {
          Pero.toast(error.message || Pero.t('toast.error'));
        } finally {
          if (!willNavigate) setButtonBusy(button, false);
        }
      });
    });
  }

  function initToastButtons() {
    Pero.$$('[data-toast-message]:not([data-post-action])').forEach((button) => {
      button.addEventListener('click', () => {
        Pero.toast(button.dataset.toastI18n ? Pero.t(button.dataset.toastI18n) : button.dataset.toastMessage);
      });
    });
  }

  function initAvatar() {
    const preview = Pero.$('[data-avatar-preview]');
    const input = Pero.$('[data-avatar-url]');
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

    const defaultBtn = Pero.$('[data-default-avatar]');
    defaultBtn?.addEventListener('click', () => {
      const img = preview?.querySelector('img');
      if (img) img.remove();
      if (preview) preview.textContent = preview.dataset.avatarInitial || 'P';
      if (input) {
        input.value = '';
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }
      Pero.toast(Pero.t('toast.defaultAvatar'));
    });
  }

  function initChangeContactButtons() {
    Pero.$$('[data-change-contact]').forEach(function (button) {
      button.addEventListener('click', async function () {
        var dialogName = button.dataset.changeContact;
        var dialog = Pero.$('[data-dialog="' + dialogName + '"]');
        if (!dialog) return;

        var input = Pero.$('input[name="value"]', dialog);
        if (!input) return;

        var value = input.value.trim();
        if (!input.checkValidity() || !value) {
          input.reportValidity();
          Pero.toast(Pero.t('toast.valueRequired'));
          return;
        }

        var formData = new FormData();
        var csrf = readCsrfToken();
        if (csrf) formData.append('csrf_token', csrf);
        formData.append('value', value);

        setButtonBusy(button, true);
        let willNavigate = false;
        try {
          var data = await api.postForm(button.dataset.action, formData);
          if (window.PeroDialog) PeroDialog.close();
          if (data && data.nonce) {
            willNavigate = true;
            window.location.href = '/account/profile/verify-contact?nonce=' + encodeURIComponent(data.nonce);
          } else {
            Pero.toast(Pero.t('toast.done'));
            willNavigate = true;
            setTimeout(function () { window.location.reload(); }, 600);
          }
        } catch (error) {
          Pero.toast(error.message || Pero.t('toast.error'));
        } finally {
          if (!willNavigate) setButtonBusy(button, false);
        }
      });
    });
  }

  api.init = function init() {
    initPasswordToggles();
    initPasswordStrength();
    initForms();
    initPostButtons();
    initToastButtons();
    initAvatar();
    initChangeContactButtons();
  };
})();
