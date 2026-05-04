(function () {
  const Pero = window.Pero = window.Pero || {};
  const dict = window.PERO_I18N || {};

  Pero.$ = (selector, root = document) => root.querySelector(selector);
  Pero.$$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  Pero.currentLang = function currentLang() {
    return localStorage.getItem('pero.lang') || 'zh';
  };

  Pero.t = function tKey(key, params) {
    let text = (dict[Pero.currentLang()] || {})[key] || key;
    if (params) {
      Object.keys(params).forEach((name) => {
        text = text.replaceAll('{{' + name + '}}', params[name]);
      });
    }
    return text;
  };

  Pero.toast = function toast(message) {
    const el = Pero.$('[data-toast]');
    if (!el) return;
    el.textContent = message || Pero.t('toast.done');
    el.classList.add('is-visible');
    window.clearTimeout(el._timer);
    el._timer = window.setTimeout(() => el.classList.remove('is-visible'), 2600);
  };

  const serverErrorKeys = {
    invalid_credentials: 'server.auth.invalid_credentials',
    session_expired: 'server.auth.session_expired',
    password_mismatch: 'server.auth.password_mismatch',
    password_reset: 'server.auth.password_reset',
  };

  Pero.setLang = function setLang(lang) {
    if (!dict[lang]) lang = 'zh';
    document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
    document.body.dataset.langCurrent = lang;
    localStorage.setItem('pero.lang', lang);

    Pero.$$('[data-i18n]').forEach((node) => {
      const value = dict[lang][node.dataset.i18n];
      if (value) node.textContent = value;
    });
    Pero.$$('[data-i18n-placeholder]').forEach((node) => {
      const value = dict[lang][node.dataset.i18nPlaceholder];
      if (value) node.setAttribute('placeholder', value);
    });
    Pero.$$('[data-server-message]').forEach((node) => {
      const key = serverErrorKeys[node.dataset.serverMessage];
      const value = key && dict[lang][key];
      if (value) node.textContent = value;
    });
    Pero.$$('[data-lang]').forEach((button) => {
      button.classList.toggle('is-active', button.dataset.lang === lang);
    });
  };

  Pero.initLanguage = function initLanguage() {
    Pero.setLang(Pero.currentLang());
    Pero.$$('[data-lang]').forEach((button) => {
      button.addEventListener('click', () => Pero.setLang(button.dataset.lang));
    });
  };

  document.addEventListener('DOMContentLoaded', () => {
    Pero.initLanguage();
    window.PeroCsrf?.init();
    window.PeroForms?.init();
    window.PeroNavigation?.init();
    window.PeroAccountSessions?.init();
    window.PeroAccountSocial?.init();
  });
})();
