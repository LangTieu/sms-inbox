(function () {
  "use strict";

  var PAGE_SIZE = 50;
  var SEARCH_DELAY = 300;

  var $ = function (id) {
    return document.getElementById(id);
  };

  var el = {
    loginView: $("login-view"),
    loginForm: $("login-form"),
    loginEmail: $("login-email"),
    loginPassword: $("login-password"),
    loginSubmit: $("login-submit"),
    modeToggle: $("mode-toggle"),
    loginError: $("login-error"),
    inboxView: $("inbox-view"),
    inboxError: $("inbox-error"),
    search: $("search"),
    count: $("count"),
    refresh: $("refresh"),
    logout: $("logout"),
    layout: $("layout"),
    list: $("list"),
    listStatus: $("list-status"),
    loadMore: $("load-more"),
    back: $("back"),
    detail: $("detail"),
    detailEmpty: $("detail-empty"),
    dFrom: $("d-from"),
    dTo: $("d-to"),
    dTime: $("d-time"),
    dBody: $("d-body"),
  };

  var state = {
    mode: "login",
    messages: [],
    nextBefore: null,
    query: "",
    selectedId: null,
    total: null,
    listToken: 0,
    detailToken: 0,
    loading: false,
  };

  var searchTimer = null;

  function UnauthorizedError() {
    this.name = "UnauthorizedError";
    this.message = "Unauthorized";
  }

  function api(path, options) {
    options = options || {};
    var init = {
      method: options.method || "GET",
      credentials: "same-origin",
      headers: {},
    };
    if (options.json !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.json);
    }
    return fetch(path, init).then(function (res) {
      return res
        .json()
        .catch(function () {
          return null;
        })
        .then(function (data) {
          if (res.status === 401 && !options.allow401) {
            showLogin();
            throw new UnauthorizedError();
          }
          if (!res.ok) {
            var err = new Error((data && data.error) || "Request failed (" + res.status + ").");
            err.status = res.status;
            throw err;
          }
          return data;
        });
    });
  }

  function showError(node, message) {
    if (message) {
      node.textContent = message;
      node.hidden = false;
    } else {
      node.textContent = "";
      node.hidden = true;
    }
  }

  function errorText(err) {
    if (err && err.name === "TypeError") return "Network error. Please check your connection and try again.";
    return (err && err.message) || "Something went wrong.";
  }

  /* Views */

  function showLogin() {
    clearTimeout(searchTimer);
    state.listToken++;
    state.detailToken++;
    state.messages = [];
    state.nextBefore = null;
    state.selectedId = null;
    state.query = "";
    el.search.value = "";
    el.list.textContent = "";
    el.inboxView.hidden = true;
    el.loginView.hidden = false;
    el.loginPassword.value = "";
    el.loginSubmit.disabled = false;
    state.mode = "login";
    el.loginSubmit.textContent = "Sign in";
    el.modeToggle.textContent = "No account yet? Create the first account";
    showError(el.inboxError, "");
  }

  function showInbox() {
    el.loginView.hidden = true;
    el.inboxView.hidden = false;
    showError(el.loginError, "");
    clearDetail();
    loadList(true);
  }

  /* Formatting */

  function pad(n) {
    return n < 10 ? "0" + n : String(n);
  }

  function formatTime(iso) {
    if (!iso) return "";
    var s = String(iso);
    if (!/(Z|[+-]\d{2}:?\d{2})$/i.test(s)) {
      s = s.replace(" ", "T") + "Z";
    }
    var d = new Date(s);
    if (isNaN(d.getTime())) return String(iso);
    return (
      pad(d.getDate()) + "/" + pad(d.getMonth() + 1) + "/" + d.getFullYear() + " " + pad(d.getHours()) + ":" + pad(d.getMinutes())
    );
  }

  function firstLine(body) {
    var lines = String(body || "").split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].trim()) return lines[i].trim();
    }
    return "";
  }

  /* List */

  function renderCount() {
    if (state.query) {
      var n = state.messages.length;
      el.count.textContent = n + (state.nextBefore ? "+" : "") + (n === 1 ? " result" : " results");
    } else if (state.total !== null) {
      el.count.textContent = state.total + (state.total === 1 ? " message" : " messages");
    } else {
      el.count.textContent = "";
    }
  }

  function buildItem(msg) {
    var li = document.createElement("li");
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "item";
    btn.dataset.id = msg.id;
    if (String(msg.id) === String(state.selectedId)) btn.setAttribute("aria-current", "true");

    var row = document.createElement("div");
    row.className = "item-row";
    var from = document.createElement("span");
    from.className = "item-from";
    from.textContent = msg.from_number || "Unknown";
    var time = document.createElement("span");
    time.className = "item-time";
    time.textContent = formatTime(msg.received_at);
    row.appendChild(from);
    row.appendChild(time);

    var preview = document.createElement("div");
    preview.className = "item-preview";
    preview.textContent = firstLine(msg.body);

    btn.appendChild(row);
    btn.appendChild(preview);
    li.appendChild(btn);
    return li;
  }

  function appendItems(messages) {
    var frag = document.createDocumentFragment();
    messages.forEach(function (m) {
      frag.appendChild(buildItem(m));
    });
    el.list.appendChild(frag);
  }

  function updateListFooter() {
    el.loadMore.hidden = !state.nextBefore;
    el.loadMore.disabled = state.loading;
    if (state.loading && state.messages.length === 0) {
      el.listStatus.textContent = "Loading...";
    } else if (!state.loading && state.messages.length === 0) {
      el.listStatus.textContent = state.query ? "No messages match your search." : "No messages yet.";
    } else {
      el.listStatus.textContent = "";
    }
  }

  function loadList(reset) {
    if (reset) {
      state.listToken++;
      state.messages = [];
      state.nextBefore = null;
      el.list.textContent = "";
    } else if (!state.nextBefore) {
      return Promise.resolve();
    }

    var token = state.listToken;
    var before = state.nextBefore;
    state.loading = true;
    showError(el.inboxError, "");
    updateListFooter();

    var params = new URLSearchParams();
    params.set("limit", String(PAGE_SIZE));
    if (!reset && before) params.set("before", before);
    if (state.query) params.set("q", state.query);

    var listPromise = api("/api/messages?" + params.toString())
      .then(function (data) {
        if (token !== state.listToken) return;
        var batch = (data && data.messages) || [];
        state.messages = state.messages.concat(batch);
        state.nextBefore = (data && data.next_before) || null;
        appendItems(batch);
      })
      .catch(function (err) {
        if (err instanceof UnauthorizedError || token !== state.listToken) return;
        showError(el.inboxError, errorText(err));
      })
      .then(function () {
        if (token !== state.listToken) return;
        state.loading = false;
        updateListFooter();
        renderCount();
      });

    var statsPromise = reset
      ? api("/api/stats")
          .then(function (s) {
            if (token !== state.listToken) return;
            state.total = s && typeof s.total === "number" ? s.total : null;
            renderCount();
          })
          .catch(function () {
            /* count is non-essential */
          })
      : Promise.resolve();

    return Promise.all([listPromise, statsPromise]);
  }

  /* Detail */

  function clearDetail() {
    state.selectedId = null;
    el.detail.hidden = true;
    el.detailEmpty.hidden = false;
    el.layout.classList.remove("show-detail");
    markSelected();
  }

  function markSelected() {
    var items = el.list.querySelectorAll(".item");
    for (var i = 0; i < items.length; i++) {
      if (state.selectedId !== null && items[i].dataset.id === String(state.selectedId)) {
        items[i].setAttribute("aria-current", "true");
      } else {
        items[i].removeAttribute("aria-current");
      }
    }
  }

  function renderDetail(msg) {
    el.dFrom.textContent = msg.from_number || "";
    el.dTo.textContent = msg.to_number || "";
    el.dTime.textContent = formatTime(msg.received_at);
    el.dBody.textContent = msg.body || "";
    el.detailEmpty.hidden = true;
    el.detail.hidden = false;
  }

  function selectMessage(id) {
    state.selectedId = id;
    markSelected();
    el.layout.classList.add("show-detail");
    showError(el.inboxError, "");

    var cached = null;
    for (var i = 0; i < state.messages.length; i++) {
      if (String(state.messages[i].id) === String(id)) {
        cached = state.messages[i];
        break;
      }
    }
    if (cached) renderDetail(cached);

    var token = ++state.detailToken;
    api("/api/messages/" + encodeURIComponent(id))
      .then(function (msg) {
        if (token !== state.detailToken || !msg) return;
        renderDetail(msg);
      })
      .catch(function (err) {
        if (err instanceof UnauthorizedError || token !== state.detailToken) return;
        showError(el.inboxError, errorText(err));
      });
  }

  /* Events */

  function doLogin(email, password) {
    return api("/api/auth/login", { method: "POST", json: { email: email, password: password }, allow401: true });
  }

  el.modeToggle.addEventListener("click", function () {
    state.mode = state.mode === "register" ? "login" : "register";
    var registering = state.mode === "register";
    el.loginSubmit.textContent = registering ? "Create account" : "Sign in";
    el.modeToggle.textContent = registering ? "Already have an account? Sign in" : "No account yet? Create the first account";
    showError(el.loginError, "");
  });

  el.loginForm.addEventListener("submit", function (e) {
    e.preventDefault();
    var email = el.loginEmail.value.trim();
    var password = el.loginPassword.value;
    showError(el.loginError, "");
    el.loginSubmit.disabled = true;

    var action;
    if (state.mode === "register") {
      action = api("/api/auth/register", { method: "POST", json: { email: email, password: password }, allow401: true })
        .catch(function (err) {
          if (err && err.status === 403) throw new Error("Registration is closed - an account already exists.");
          if (err && err.status === 400) throw new Error("Password must be at least 10 characters.");
          throw err;
        })
        .then(function () {
          return doLogin(email, password);
        });
    } else {
      action = doLogin(email, password);
    }
    action
      .then(function () {
        showInbox();
      })
      .catch(function (err) {
        showError(el.loginError, errorText(err));
        el.loginSubmit.disabled = false;
      });
  });

  el.list.addEventListener("click", function (e) {
    var btn = e.target.closest(".item");
    if (btn) selectMessage(btn.dataset.id);
  });

  el.loadMore.addEventListener("click", function () {
    loadList(false);
  });

  el.refresh.addEventListener("click", function () {
    loadList(true);
  });

  el.back.addEventListener("click", function () {
    el.layout.classList.remove("show-detail");
  });

  el.logout.addEventListener("click", function () {
    api("/api/auth/logout", { method: "POST", allow401: true })
      .catch(function () {
        /* leave the screen regardless */
      })
      .then(showLogin);
  });

  el.search.addEventListener("input", function () {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(function () {
      var q = el.search.value.trim();
      if (q === state.query) return;
      state.query = q;
      loadList(true);
    }, SEARCH_DELAY);
  });

  /* Boot */

  api("/api/auth/me", { allow401: true })
    .then(function () {
      showInbox();
    })
    .catch(function (err) {
      showLogin();
      if (!(err && err.status === 401)) showError(el.loginError, errorText(err));
    });
})();
