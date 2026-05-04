(function () {
  window.PeroCsrf = {
    init() {
      document.querySelectorAll('form input[name="csrf_token"]').forEach((input) => {
        input.closest('form')?.setAttribute('data-has-csrf', 'true');
      });
    },
  };
})();
