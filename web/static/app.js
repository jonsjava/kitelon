(function () {
  const KEY = "kitelon_api_key";
  let authPrompt = null;

  function storedKey() {
    return sessionStorage.getItem(KEY);
  }

  function promptForKey() {
    if (!authPrompt) {
      authPrompt = Promise.resolve(
        prompt("Kitelon API key required by server:") || ""
      ).then((k) => {
        sessionStorage.setItem(KEY, k);
        authPrompt = null;
        return k;
      });
    }
    return authPrompt;
  }

  async function api(path, options) {
    async function doFetch() {
      const headers = Object.assign(
        { "Content-Type": "application/json" },
        (options && options.headers) || {}
      );
      const key = storedKey();
      if (key) headers["X-API-Key"] = key;
      return fetch(path, Object.assign({}, options, { headers }));
    }

    let res = await doFetch();
    if (res.status === 401) {
      const key = await promptForKey();
      if (key) {
        const headers = Object.assign(
          { "Content-Type": "application/json" },
          (options && options.headers) || {}
        );
        headers["X-API-Key"] = key;
        res = await fetch(path, Object.assign({}, options, { headers }));
      }
    }
    if (!res.ok) {
      const text = await res.text();
      throw new Error(res.status + " " + text);
    }
    return res.json();
  }

  async function download(path, filename) {
    async function doFetch() {
      const headers = {};
      const key = storedKey();
      if (key) headers["X-API-Key"] = key;
      return fetch(path, { headers });
    }

    let res = await doFetch();
    if (res.status === 401) {
      const key = await promptForKey();
      if (key) {
        const headers = { "X-API-Key": key };
        res = await fetch(path, { headers });
      }
    }
    if (!res.ok) {
      const text = await res.text();
      throw new Error(res.status + " " + text);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function fillRow(tr, values) {
    values.forEach((v) => tr.appendChild(el("td", null, v == null ? "" : String(v))));
    return tr;
  }

  function stat(label, value) {
    const s = el("span", "stat", label + ": " + value);
    return s;
  }

  const WORKSPACE_ALIAS_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;
  const WORKSPACE_INVALID_CHARS = /[^a-zA-Z0-9._-]/g;

  function sanitizeWorkspaceAlias(raw) {
    let value = String(raw || "").replace(WORKSPACE_INVALID_CHARS, "");
    value = value.replace(/^[^a-zA-Z0-9]+/, "");
    if (value.length > 64) value = value.slice(0, 64);
    return value;
  }

  function validateWorkspaceAlias(raw) {
    const value = sanitizeWorkspaceAlias(raw);
    if (!value) {
      return "Workspace alias required: start with a letter or digit; use only letters, digits, . _ -";
    }
    if (!WORKSPACE_ALIAS_PATTERN.test(value)) {
      return "Invalid workspace alias.";
    }
    return null;
  }

  function bindWorkspaceInput(input) {
    if (!input || input.dataset.workspaceBound === "1") return;
    input.dataset.workspaceBound = "1";
    input.setAttribute("maxlength", "64");
    input.setAttribute("autocomplete", "off");
    input.setAttribute("spellcheck", "false");
    input.setAttribute("pattern", "[A-Za-z0-9][A-Za-z0-9._-]{0,63}");

    const sync = () => {
      const cleaned = sanitizeWorkspaceAlias(input.value);
      if (input.value !== cleaned) input.value = cleaned;
    };

    input.addEventListener("input", sync);
    input.addEventListener("paste", (ev) => {
      ev.preventDefault();
      const paste = (ev.clipboardData || window.clipboardData).getData("text");
      const start = input.selectionStart || 0;
      const end = input.selectionEnd || 0;
      const merged = input.value.slice(0, start) + paste + input.value.slice(end);
      input.value = sanitizeWorkspaceAlias(merged);
    });
  }

  function bindWorkspaceInputs(root) {
    (root || document).querySelectorAll("[data-workspace-input]").forEach(bindWorkspaceInput);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => bindWorkspaceInputs());
  } else {
    bindWorkspaceInputs();
  }

  async function upload(path, file, query) {
    let url = path;
    if (query) {
      const qs = typeof query === "string" ? query : new URLSearchParams(query).toString();
      if (qs) url += "?" + qs;
    }
    async function doFetch() {
      const headers = {};
      const key = storedKey();
      if (key) headers["X-API-Key"] = key;
      const body = new FormData();
      body.append("file", file);
      return fetch(url, { method: "POST", headers, body });
    }

    let res = await doFetch();
    if (res.status === 401) {
      const key = await promptForKey();
      if (key) {
        const headers = { "X-API-Key": key };
        const body = new FormData();
        body.append("file", file);
        res = await fetch(url, { method: "POST", headers, body });
      }
    }
    if (!res.ok) {
      const text = await res.text();
      throw new Error(res.status + " " + text);
    }
    return res.json();
  }

  function scanOptionsFromForm(form) {
    const options = {};
    form.querySelectorAll("[data-scan-option]").forEach((el) => {
      const id = el.getAttribute("data-scan-option");
      if (el.type === "checkbox") {
        if (el.checked) options[id] = true;
      } else if (el.value !== "") {
        options[id] = el.type === "number" ? Number(el.value) : el.value;
      }
    });
    return Object.keys(options).length ? options : undefined;
  }

  function renderScanOptions(container, optionsSpec, idPrefix) {
    container.innerHTML = "";
    const grid = document.createElement("div");
    grid.className = "option-grid";
    optionsSpec.forEach((opt) => {
      const label = document.createElement("label");
      label.className = "option-item";
      let input;
      if (opt.type === "bool") {
        input = document.createElement("input");
        input.type = "checkbox";
        input.dataset.scanOption = opt.id;
      } else if (opt.type === "number") {
        input = document.createElement("input");
        input.type = "number";
        input.min = "1";
        input.max = "65535";
        input.placeholder = opt.label;
        input.dataset.scanOption = opt.id;
      }
      if (input) {
        input.id = idPrefix + "-" + opt.id;
        label.appendChild(input);
        const text = document.createElement("span");
        text.textContent = opt.label;
        label.appendChild(text);
        grid.appendChild(label);
      }
    });
    container.appendChild(grid);
  }

  function fillModeSelect(select, modes) {
    select.innerHTML = "";
    modes.forEach((m) => {
      const opt = document.createElement("option");
      opt.value = m.id;
      opt.textContent = m.label + ": " + m.description;
      select.appendChild(opt);
    });
  }

  function reportPdfUrl(alias, hosts, force) {
    let url = "/api/v1/workspaces/" + encodeURIComponent(alias) + "/report.pdf";
    const params = [];
    if (force) params.push("force=true");
    if (hosts && hosts.length) {
      hosts.forEach((h) => params.push("hosts=" + encodeURIComponent(h)));
    }
    if (params.length) url += "?" + params.join("&");
    return url;
  }

  function sslReportPdfUrl(alias, hostname, port, force) {
    let url =
      "/api/v1/workspaces/" + encodeURIComponent(alias) +
      "/hosts/" + encodeURIComponent(hostname) +
      "/ssl-report.pdf?port=" + encodeURIComponent(port || 443);
    if (force) url += "&force=true";
    return url;
  }

  function artifactUrl(alias, relPath) {
    const encoded = String(relPath).split("/").map(encodeURIComponent).join("/");
    return "/api/v1/workspaces/" + encodeURIComponent(alias) + "/artifacts/" + encoded;
  }

  function formatBytes(n) {
    if (n == null || n === 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    let i = 0;
    let v = Number(n);
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i += 1;
    }
    return (i ? v.toFixed(1) : v) + " " + units[i];
  }

  window.KitelonUI = {
    api,
    download,
    upload,
    el,
    fillRow,
    stat,
    scanOptionsFromForm,
    renderScanOptions,
    fillModeSelect,
    reportPdfUrl,
    sslReportPdfUrl,
    artifactUrl,
    formatBytes,
    apiKeyStorage: KEY,
    sanitizeWorkspaceAlias,
    validateWorkspaceAlias,
    bindWorkspaceInput,
    bindWorkspaceInputs,
  };
})();
