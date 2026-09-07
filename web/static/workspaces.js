(function () {
  const { el, api, validateWorkspaceAlias, sanitizeWorkspaceAlias, upload, renderNav } = KitelonUI;
  const { mountSeverityDonut, severityCountsFromStats, SEVERITY_COLORS } = KitelonCharts;

  function formatImportedAt(value) {
    if (!value) return "Not imported";
    try {
      return new Date(value).toLocaleString();
    } catch (_e) {
      return String(value);
    }
  }

  function buildDonutWrap(stats) {
    const wrap = el("div", "donut-wrap");
    const canvas = document.createElement("canvas");
    canvas.setAttribute("aria-hidden", "true");
    const center = el("div", "donut-center");
    const score = el("span", "donut-score risk-none", "0");
    const label = el("span", "donut-label", "Risk");
    center.appendChild(score);
    center.appendChild(label);
    wrap.appendChild(canvas);
    wrap.appendChild(center);

    const legend = el("div", "donut-legend");
    severityCountsFromStats(stats).forEach((row) => {
      const item = el("span", "legend-item");
      const swatch = el("span", "legend-swatch");
      swatch.style.background = row.color;
      item.appendChild(swatch);
      item.appendChild(document.createTextNode(row.level + " " + row.count));
      legend.appendChild(item);
    });
    wrap.appendChild(legend);
    return wrap;
  }

  function updateLegend(legendEl, stats) {
    if (!legendEl) return;
    legendEl.innerHTML = "";
    severityCountsFromStats(stats).forEach((row) => {
      const item = el("span", "legend-item");
      const swatch = el("span", "legend-swatch");
      swatch.style.background = SEVERITY_COLORS[row.level];
      item.appendChild(swatch);
      item.appendChild(document.createTextNode(row.level + " " + row.count));
      legendEl.appendChild(item);
    });
  }

  function buildWorkspaceCard(ws, reload) {
    const card = el("article", "card workspace-card");
    card.dataset.workspaceAlias = ws.alias;

    const head = el("div", "card-head");
    const link = document.createElement("a");
    link.className = "card-title-link";
    link.href = "/workspace.html?alias=" + encodeURIComponent(ws.alias);
    link.appendChild(el("h2", null, ws.alias));
    head.appendChild(link);
    head.appendChild(el("p", "meta card-sub", ws.loot_path || ""));
    card.appendChild(head);

    const stats = ws.stats || {};
    const donutWrap = buildDonutWrap(stats);
    card.appendChild(donutWrap);
    mountSeverityDonut(donutWrap, stats);

    const metaRow = el("div", "card-meta-row");
    metaRow.appendChild(el("span", "meta-pill", (stats.hosts_total || 0) + " hosts"));
    metaRow.appendChild(el("span", "meta-pill", (stats.vulnerabilities_total || 0) + " findings"));
    metaRow.appendChild(el("span", "meta-pill meta-pill-muted", formatImportedAt(ws.last_imported_at)));
    card.appendChild(metaRow);

    const actions = el("div", "card-actions");
    if (!ws.last_imported_at) {
      const imp = document.createElement("button");
      imp.type = "button";
      imp.className = "secondary btn-sm";
      imp.textContent = "Import loot";
      imp.addEventListener("click", async (ev) => {
        ev.preventDefault();
        imp.disabled = true;
        try {
          await api("/api/v1/workspaces/" + encodeURIComponent(ws.alias) + "/import", {
            method: "POST",
            body: "{}",
          });
          imp.textContent = "Import queued";
        } catch (_e) {
          imp.textContent = "Import failed";
          imp.disabled = false;
        }
      });
      actions.appendChild(imp);
    }

    const ren = document.createElement("button");
    ren.type = "button";
    ren.className = "secondary btn-sm";
    ren.textContent = "Rename";
    ren.addEventListener("click", async () => {
      const newAlias = prompt("New workspace alias:", ws.alias);
      if (!newAlias || newAlias === ws.alias) return;
      try {
        await api("/api/v1/workspaces/" + encodeURIComponent(ws.alias), {
          method: "PATCH",
          body: JSON.stringify({ alias: newAlias }),
        });
        reload();
      } catch (e) {
        document.getElementById("error").textContent = e.message;
      }
    });
    actions.appendChild(ren);

    const del = document.createElement("button");
    del.type = "button";
    del.className = "secondary btn-sm";
    del.textContent = "Delete";
    del.addEventListener("click", async () => {
      if (!confirm("Delete workspace " + ws.alias + " and all loot?")) return;
      del.disabled = true;
      try {
        await api("/api/v1/workspaces/" + encodeURIComponent(ws.alias) + "?delete_loot=true", {
          method: "DELETE",
        });
        reload();
      } catch (e) {
        document.getElementById("error").textContent = e.message;
        del.disabled = false;
      }
    });
    actions.appendChild(del);
    card.appendChild(actions);
    return card;
  }

  function patchWorkspaceCard(card, ws) {
    const stats = ws.stats || {};
    const donutWrap = card.querySelector(".donut-wrap");
    if (donutWrap) {
      mountSeverityDonut(donutWrap, stats);
      updateLegend(donutWrap.querySelector(".donut-legend"), stats);
    }

    const metaRow = card.querySelector(".card-meta-row");
    if (metaRow) {
      const pills = metaRow.querySelectorAll(".meta-pill");
      if (pills[0]) pills[0].textContent = (stats.hosts_total || 0) + " hosts";
      if (pills[1]) pills[1].textContent = (stats.vulnerabilities_total || 0) + " findings";
      if (pills[2]) pills[2].textContent = formatImportedAt(ws.last_imported_at);
    }
  }

  function renderSummaryStrip(workspaces, status) {
    const strip = document.getElementById("summary-strip");
    if (!strip) return;
    strip.innerHTML = "";
    let hosts = 0;
    let findings = 0;
    workspaces.forEach((ws) => {
      const s = ws.stats || {};
      hosts += Number(s.hosts_total || 0);
      findings += Number(s.vulnerabilities_total || 0);
    });
    const items = [
      { label: "Workspaces", value: workspaces.length },
      { label: "Hosts", value: hosts },
      { label: "Findings", value: findings },
      { label: "Scan active", value: status && status.scan_running ? "Yes" : "No",
        highlight: !!(status && status.scan_running) },
    ];
    items.forEach((item) => {
      const box = el("div", "summary-item" + (item.highlight ? " summary-active" : ""));
      box.appendChild(el("span", "summary-value", String(item.value)));
      box.appendChild(el("span", "summary-label", item.label));
      strip.appendChild(box);
    });
  }

  function syncWorkspaceGrid(grid, workspaces, reload) {
    const existing = new Map();
    grid.querySelectorAll(".workspace-card[data-workspace-alias]").forEach((card) => {
      existing.set(card.dataset.workspaceAlias, card);
    });
    const nextAliases = workspaces.map((ws) => ws.alias);

    if (!workspaces.length) {
      grid.innerHTML = "";
      grid.appendChild(el("p", "empty", "No workspaces yet. Create one above or run a scan with -w alias."));
      return;
    }

    const emptyMsg = grid.querySelector(".empty");
    if (emptyMsg) emptyMsg.remove();

    nextAliases.forEach((alias, index) => {
      const ws = workspaces[index];
      let card = existing.get(alias);
      if (card) {
        patchWorkspaceCard(card, ws);
        const ref = grid.children[index];
        if (ref !== card) grid.insertBefore(card, ref || null);
      } else {
        card = buildWorkspaceCard(ws, reload);
        grid.insertBefore(card, grid.children[index] || null);
      }
    });

    existing.forEach((card, alias) => {
      if (!nextAliases.includes(alias)) card.remove();
    });
  }

  async function loadWorkspaces(options) {
    const grid = document.getElementById("grid");
    const err = document.getElementById("error");
    const incremental = !!(options && options.incremental);
    err.textContent = "";
    try {
      const [workspaces, st] = await Promise.all([
        api("/api/v1/workspaces"),
        api("/api/v1/status"),
      ]);
      renderSummaryStrip(workspaces, st);
      if (incremental) {
        syncWorkspaceGrid(grid, workspaces, () => loadWorkspaces({ incremental: true }));
      } else {
        grid.innerHTML = "";
        if (!workspaces.length) {
          grid.appendChild(el("p", "empty", "No workspaces yet. Create one above or run a scan with -w alias."));
          return;
        }
        workspaces.forEach((ws) => {
          grid.appendChild(buildWorkspaceCard(ws, () => loadWorkspaces()));
        });
      }
    } catch (e) {
      err.textContent = e.message;
    }
  }

  function bindWorkspacePage() {
    renderNav("workspaces", "Kitelon");

    const panelToggle = document.getElementById("panel-toggle");
    const panel = document.getElementById("workspace-panel");
    if (panelToggle && panel) {
      panelToggle.addEventListener("click", () => {
        panel.classList.toggle("panel-collapsed");
        panelToggle.setAttribute(
          "aria-expanded",
          panel.classList.contains("panel-collapsed") ? "false" : "true"
        );
      });
    }

    document.getElementById("create-workspace").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const err = document.getElementById("error");
      err.textContent = "";
      const fd = new FormData(ev.target);
      const alias = sanitizeWorkspaceAlias(fd.get("alias"));
      const aliasErr = validateWorkspaceAlias(alias);
      if (aliasErr) {
        err.textContent = aliasErr;
        return;
      }
      try {
        const ws = await api("/api/v1/workspaces", {
          method: "POST",
          body: JSON.stringify({ alias }),
        });
        ev.target.reset();
        location.href = "/workspace.html?alias=" + encodeURIComponent(ws.alias);
      } catch (e) {
        err.textContent = e.message;
      }
    });

    document.getElementById("import-zip-btn").addEventListener("click", async () => {
      const input = document.getElementById("import-zip-file");
      const msg = document.getElementById("import-zip-msg");
      const btn = document.getElementById("import-zip-btn");
      if (!input.files || !input.files[0]) {
        msg.textContent = "Choose a ZIP file first.";
        return;
      }
      const query = {};
      const alias = sanitizeWorkspaceAlias(document.getElementById("import-zip-alias").value);
      if (alias) query.alias = alias;
      if (document.getElementById("import-zip-replace").checked) query.replace = "true";
      btn.disabled = true;
      msg.textContent = "Importing…";
      try {
        const result = await upload("/api/v1/workspaces/import-zip", input.files[0], query);
        msg.textContent =
          "Imported " + result.alias + " (" + result.hosts + " hosts, " +
          result.vulnerabilities + " findings).";
        input.value = "";
        location.href = "/workspace.html?alias=" + encodeURIComponent(result.alias);
      } catch (e) {
        msg.textContent = e.message;
        btn.disabled = false;
      }
    });

    loadWorkspaces();
    setInterval(() => loadWorkspaces({ incremental: true }), 30000);
  }

  window.KitelonWorkspaces = { bindWorkspacePage, loadWorkspaces };
})();
