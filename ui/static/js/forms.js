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

  api.postForm = async function postForm(action, formData) {
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
      throw new Error((payload && payload.message) || Pero.t('toast.requestFailed'));
    }
    return payload || { message: Pero.t('toast.done') };
  };

  function initPasswordToggles() {
    Pero.$$('[data-toggle-password]').forEach((button) => {
      button.addEventListener('click', () => {
        const input = button.parentElement.querySelector('input');
        if (!input) return;
        input.type = input.type === 'password' ? 'text' : 'password';
        button.textContent = input.type === 'password' ? 'Show' : 'Hide';
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
    Pero.$$('form[data-password-confirm]').forEach((form) => {
      form.addEventListener('submit', (event) => {
        if (!ensureValidForm(form)) event.preventDefault();
      });
    });

    Pero.$$('form[data-ajax-form], form[data-ajax-row]').forEach((form) => {
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!ensureValidForm(form)) return;

        try {
          const data = await api.postForm(form.action || window.location.pathname, new FormData(form));
          const success = Pero.$('[data-form-success]', form);
          if (success) success.classList.remove('hidden');
          if (form.matches('[data-ajax-row]')) form.closest('tr, [data-provider-row]')?.remove();
          const toastKey = form.dataset.toastI18n;
          Pero.toast(toastKey ? Pero.t(toastKey) : (data.message || Pero.t('toast.done')));
          if (form.dataset.ajaxForm !== undefined && !form.matches('[data-ajax-row]')) {
            setTimeout(() => window.location.reload(), 600);
          }
        } catch (error) {
          Pero.toast(error.message || Pero.t('toast.error'));
        }
      });
    });
  }

  function initPostButtons() {
    Pero.$$('[data-post-action]:not([data-bulk-action])').forEach((button) => {
      button.addEventListener('click', async () => {
        const formData = new FormData();
        if (button.dataset.postField) {
          formData.append(button.dataset.postField, button.dataset.postValue || '');
        }

        try {
          const data = await api.postForm(button.dataset.postAction, formData);
          if (button.dataset.redirect) {
            window.location.href = button.dataset.redirect;
          } else {
            const key = button.dataset.toastI18n;
            Pero.toast(key ? Pero.t(key) : (button.dataset.toastMessage || data.message || Pero.t('toast.done')));
          }
        } catch (error) {
          Pero.toast(error.message || Pero.t('toast.error'));
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

  api.init = function init() {
    initPasswordToggles();
    initPasswordStrength();
    initForms();
    initPostButtons();
    initToastButtons();
  };
})();
