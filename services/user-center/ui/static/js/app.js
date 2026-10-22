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

  const serverMessageKeys = {
    ok: 'toast.done',
    invalid_credentials: 'server.auth.invalid_credentials',
    session_expired: 'server.auth.session_expired',
    password_mismatch: 'server.auth.password_mismatch',
    password_reset: 'server.auth.password_reset',
    password_reset_success: 'server.auth.password_reset_success',
    account_locked: 'server.auth.account_locked',
    no_password_identity: 'server.auth.no_password_identity',
    provider_already_linked: 'server.auth.provider_already_linked',
    social_identity_taken: 'server.auth.social_identity_taken',
    social_link_expired: 'server.auth.social_link_expired',
    rate_limited: 'server.generic.rate_limited',
    invalid_csrf: 'server.generic.invalid_csrf',
    unauthorized: 'server.generic.unauthorized',
    internal_error: 'server.generic.internal_error',
    update_failed: 'server.generic.update_failed',
    avatar_url_invalid: 'server.profile.avatar_url_invalid',
    avatar_url_bad_scheme: 'server.profile.avatar_url_bad_scheme',
    email_invalid: 'server.contact.email_invalid',
    phone_invalid: 'server.contact.phone_invalid',
    user_not_found: 'server.generic.user_not_found',
    not_found: 'server.generic.not_found',
    identifier_required: 'server.form.identifier_required',
    'identifier is required': 'server.form.identifier_required',
    username_taken: 'server.register.username_taken',
    email_taken: 'server.register.email_taken',
    phone_taken: 'server.register.phone_taken',
    missing_token: 'server.reset.missing_token',
    invalid_token: 'server.reset.invalid_token',
    token_already_used: 'server.reset.token_already_used',
    no_email: 'server.contact.no_email',
    no_phone: 'server.contact.no_phone',
    already_verified: 'server.contact.already_verified',
    send_failed: 'server.contact.send_failed',
    email_required: 'server.contact.email_required',
    phone_required: 'server.contact.phone_required',
    same_email: 'server.contact.same_email',
    same_phone: 'server.contact.same_phone',
    same_pending_email: 'server.contact.same_pending_email',
    same_pending_phone: 'server.contact.same_pending_phone',
    invalid_nonce: 'server.contact.invalid_nonce',
    invalid_code: 'server.contact.invalid_code',
    code_expired: 'server.contact.code_expired',
    contact_taken: 'server.contact.contact_taken',
    same_pending_value: 'server.contact.same_pending_value',
    service_unavailable: 'server.generic.service_unavailable',
    session_revoke_failed: 'server.generic.session_revoke_failed',
    'password is required': 'server.password.required',
    'password must be at least 8 characters': 'server.password.min_length',
    'password must be at most 128 characters': 'server.password.max_length',
    'password must contain an uppercase letter': 'server.password.uppercase',
    'password must contain a lowercase letter': 'server.password.lowercase',
    'password must contain a digit': 'server.password.digit',
    'password must contain a special character': 'server.password.special',
    system_app_protected: 'dash.server.system_app_protected',
    local_provider_protected: 'dash.server.local_provider_protected',
    code_and_name_required: 'dash.server.code_and_name_required',
    code_exists: 'dash.server.code_exists',
    create_failed: 'dash.server.create_failed',
    name_required: 'dash.server.name_required',
    identifier_exists: 'dash.server.identifier_exists',
    kid_and_public_key_required: 'dash.server.kid_and_public_key_required',
    invalid_app: 'dash.server.invalid_app',
    username_and_password_required: 'dash.server.username_and_password_required',
    username_exists: 'dash.server.username_exists',
    password_required: 'dash.server.password_required',
    no_password_identity: 'dash.server.no_password_identity',
    invalid_app_id: 'dash.server.invalid_app_id',
    already_granted: 'dash.server.already_granted',
    grant_failed: 'dash.server.grant_failed',
    revoke_failed: 'dash.server.revoke_failed',
    internal_error: 'dash.server.internal_error',
    invalid_settings_json: 'dash.server.invalid_settings_json',
    cannot_modify_self: 'dash.server.cannot_modify_self',
    invalid_status: 'dash.server.invalid_status',
    username_length_invalid: 'dash.server.username_length_invalid',
    invalid_redirect_uri: 'dash.server.invalid_redirect_uri',
    username_chars_invalid: 'dash.server.username_chars_invalid',
    invalid_provider_endpoint: 'dash.server.invalid_provider_endpoint',
    invalid_provider_kind: 'dash.server.invalid_provider_kind',
    unsupported_signing_algorithm: 'dash.server.unsupported_signing_algorithm',
    private_key_required_for_active_signing_key: 'dash.server.private_key_required_for_active_signing_key',
    invalid_url: 'dash.server.invalid_url',
    secret_required: 'dash.server.secret_required',
    update_failed: 'dash.server.update_failed',
    not_found: 'dash.server.not_found',
  };

  Pero.message = function message(raw, fallbackKey) {
    const value = String(raw || '');
    const lang = Pero.currentLang();
    const locale = dict[lang] || {};
    const mappedKey = serverMessageKeys[value] || value;
    return locale[mappedKey] || locale[value] || (fallbackKey ? Pero.t(fallbackKey) : '') || value;
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
      const value = Pero.message(node.dataset.serverMessage);
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
  });
})();
