(function () {
  const Pero = window.Pero;
  const api = window.PeroAccountSessions = {};

  api.init = function initBulkTables() {
    ['authz', 'sessions'].forEach((scope) => {
      const selectAll = Pero.$(`[data-select-all="${scope}"]`);
      const countEl = Pero.$(`[data-selected-count="${scope}"]`);
      const action = Pero.$(`[data-bulk-action="${scope}"]`);
      const checkboxes = () => Pero.$$(`[data-row-checkbox="${scope}"]`).filter((box) => !box.disabled);

      const update = () => {
        const items = checkboxes();
        const selected = items.filter((box) => box.checked).length;
        if (countEl) countEl.textContent = String(selected);
        if (action) action.disabled = selected === 0;
        if (selectAll) selectAll.checked = items.length > 0 && selected === items.length;
      };

      selectAll?.addEventListener('change', () => {
        checkboxes().forEach((box) => { box.checked = selectAll.checked; });
        update();
      });

      checkboxes().forEach((box) => box.addEventListener('change', update));
      action?.addEventListener('click', async () => {
        const checked = checkboxes().filter((box) => box.checked);
        try {
          for (const box of checked) {
            const formData = new FormData();
            formData.append(action.dataset.postField, box.value);
            await window.PeroForms.postForm(action.dataset.postAction, formData);
            box.closest('tr')?.remove();
          }
          Pero.toast(scope === 'sessions' ? Pero.t('toast.sessionsTerminated') : Pero.t('toast.authorizationsRevoked'));
        } catch (error) {
          Pero.toast(error.message || Pero.t('toast.error'));
        } finally {
          update();
        }
      });

      update();
    });
  };
})();
