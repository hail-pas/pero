(function () {
  var api = window.PeroDialog = {};

  api.open = function open(name) {
    api.close();
    var overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    overlay.setAttribute('data-dialog-overlay', '');
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) api.close();
    });

    var panel = document.querySelector('[data-dialog="' + name + '"]');
    if (!panel) return;
    panel.classList.add('is-active');
    overlay.appendChild(panel);

    document.body.appendChild(overlay);
    document.body.style.overflow = 'hidden';

    var input = panel.querySelector('input');
    if (input) input.focus();
  };

  api.close = function close() {
    var overlay = document.querySelector('[data-dialog-overlay]');
    if (overlay) {
      var panel = overlay.querySelector('[data-dialog].is-active');
      if (panel) {
        panel.classList.remove('is-active');
        document.body.appendChild(panel);
      }
      overlay.remove();
      document.body.style.overflow = '';
    }
  };

  api.init = function init() {
    document.querySelectorAll('[data-dialog-open]').forEach(function (button) {
      button.addEventListener('click', function () {
        api.open(button.dataset.dialogOpen);
      });
    });
    document.querySelectorAll('[data-dialog-close]').forEach(function (button) {
      button.addEventListener('click', function () {
        api.close();
      });
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') api.close();
    });
  };

  document.addEventListener('DOMContentLoaded', function () {
    api.init();
  });
})();
