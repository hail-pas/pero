(function () {
  window.PeroCsrf = {
    readToken() {
      var match = document.cookie.match(/(?:^|;\s*)pero_csrf=([^;]*)/);
      return match ? decodeURIComponent(match[1]) : '';
    },

    init() {
      var token = this.readToken();
      if (!token) return;
      document.querySelectorAll('form[data-csrf]').forEach(function (form) {
        if (!form.querySelector('input[name="csrf_token"]')) {
          var input = document.createElement('input');
          input.type = 'hidden';
          input.name = 'csrf_token';
          input.value = token;
          form.appendChild(input);
        }
      });
    },
  };
})();
