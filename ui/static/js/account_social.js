(function () {
  const Pero = window.Pero;
  const api = window.PeroAccountSocial = {};

  function initSocialActions() {
    Pero.$$('[data-bind]').forEach((button) => {
      button.addEventListener('click', () => {
        const provider = button.closest('[data-provider-row]')?.dataset.providerRow;
        if (provider) window.location.href = `/account/social/${provider}/bind`;
      });
    });

    Pero.$$('[data-unbind]').forEach((button) => {
      button.addEventListener('click', async () => {
        const row = button.closest('[data-provider-row]');
        const provider = row?.dataset.providerRow;
        if (!provider) return;

        const formData = new FormData();
        formData.append('provider', provider);
        try {
          await window.PeroForms.postForm('/account/social/unbind', formData);
          row.remove();
          Pero.toast(Pero.t('toast.providerUnbound'));
        } catch (error) {
          Pero.toast(error.message || Pero.t('toast.error'));
        }
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
      if (preview) preview.textContent = preview.textContent.trim() || 'P';
      if (input) {
        input.value = '';
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }
      Pero.toast(Pero.t('toast.defaultAvatar'));
    });

    Pero.$('[data-avatar-upload]')?.addEventListener('click', () => Pero.toast(Pero.t('toast.uploadStub')));
  }

  api.init = function init() {
    initSocialActions();
    initAvatar();
  };
})();
