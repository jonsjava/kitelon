(function () {
  function jobErrorText(j) {
    if (j.error_message) return j.error_message;
    if (j.status === "failed" && j.exit_code != null) return "exit code " + j.exit_code;
    return "";
  }

  function statusPill(status) {
    const span = document.createElement("span");
    span.className = "status-pill status-pill-" + status;
    span.textContent = status;
    return span;
  }

  function setStatusCell(td, status) {
    let pill = td.querySelector(".status-pill");
    if (!pill || pill.textContent !== status) {
      td.textContent = "";
      td.className = "job-status";
      pill = statusPill(status);
      td.appendChild(pill);
    }
  }

  function setTextCell(td, text, className) {
    const value = text != null ? String(text) : "";
    if (td.textContent !== value) td.textContent = value;
    if (className != null) td.className = className;
  }

  function buildActionButtons(j, api, onError, reload) {
    const actTd = document.createElement("td");
    actTd.className = "job-actions";

    if (j.status === "pending") {
      const edit = document.createElement("button");
      edit.type = "button";
      edit.className = "secondary btn-sm";
      edit.textContent = "Edit";
      edit.addEventListener("click", async () => {
        const p = prompt("Priority (lower runs sooner):", String(j.priority != null ? j.priority : 100));
        if (p == null) return;
        const t = prompt("Target:", j.target || "");
        if (t == null) return;
        try {
          await api("/api/v1/jobs/" + j.id, {
            method: "PATCH",
            body: JSON.stringify({ priority: parseInt(p, 10), target: t }),
          });
          reload();
        } catch (e) {
          onError(e.message);
        }
      });
      actTd.appendChild(edit);
    }

    if (j.status === "failed" || j.status === "completed" || j.status === "cancelled") {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "secondary btn-sm";
      btn.textContent = "Re-queue";
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        try {
          await api("/api/v1/jobs/" + j.id + "/retry", { method: "POST", body: "{}" });
          reload();
        } catch (e) {
          onError(e.message);
          btn.disabled = false;
        }
      });
      actTd.appendChild(btn);
    }

    const del = document.createElement("button");
    del.type = "button";
    del.className = "secondary btn-sm";
    del.textContent = j.status === "running" ? "Cancel" : "Delete";
    del.addEventListener("click", async () => {
      const msg = j.status === "running"
        ? "Cancel running job #" + j.id + "?"
        : "Delete job #" + j.id + "?";
      if (!confirm(msg)) return;
      del.disabled = true;
      try {
        const q = j.status === "running" ? "?kill=true" : "";
        await api("/api/v1/jobs/" + j.id + q, { method: "DELETE" });
        reload();
      } catch (e) {
        onError(e.message);
        del.disabled = false;
      }
    });
    actTd.appendChild(del);
    return actTd;
  }

  function buildJobRow(j, api, onError, reload) {
    const tr = document.createElement("tr");
    tr.dataset.jobId = String(j.id);
    tr.dataset.jobStatus = j.status;
    tr.className = j.status === "failed" ? "job-failed" : (j.status === "running" ? "job-running" : "");

    const cells = [
      { text: j.id },
      { status: j.status },
      { text: j.job_type },
      { text: j.workspace_alias || "" },
      { text: j.target || "" },
      { text: j.mode || "" },
      { text: j.priority != null ? j.priority : "" },
    ];

    cells.forEach((cell, index) => {
      const td = document.createElement("td");
      if (cell.status) {
        setStatusCell(td, cell.status);
      } else {
        setTextCell(td, cell.text);
      }
      tr.appendChild(td);
    });

    const errTd = document.createElement("td");
    errTd.className = "job-error";
    const errText = jobErrorText(j);
    errTd.textContent = errText;
    if (errText) errTd.title = errText;
    tr.appendChild(errTd);

    tr.appendChild(buildActionButtons(j, api, onError, reload));
    return tr;
  }

  function patchJobRow(tr, j, api, onError, reload) {
    const prevStatus = tr.dataset.jobStatus;
    tr.dataset.jobStatus = j.status;
    tr.className = j.status === "failed" ? "job-failed" : (j.status === "running" ? "job-running" : "");

    setTextCell(tr.cells[0], j.id);
    setStatusCell(tr.cells[1], j.status);
    setTextCell(tr.cells[2], j.job_type);
    setTextCell(tr.cells[3], j.workspace_alias || "");
    setTextCell(tr.cells[4], j.target || "");
    setTextCell(tr.cells[5], j.mode || "");
    setTextCell(tr.cells[6], j.priority != null ? j.priority : "");

    const errText = jobErrorText(j);
    const errTd = tr.cells[7];
    if (errTd.textContent !== errText) errTd.textContent = errText;
    errTd.title = errText || "";

    if (prevStatus !== j.status) {
      const newActions = buildActionButtons(j, api, onError, reload);
      tr.replaceChild(newActions, tr.cells[8]);
    }
  }

  function syncJobsTable(tbody, jobs, api, onError, reload) {
    const existing = new Map();
    tbody.querySelectorAll("tr[data-job-id]").forEach((tr) => {
      existing.set(tr.dataset.jobId, tr);
    });

    const nextIds = jobs.map((j) => String(j.id));
    nextIds.forEach((id, index) => {
      const job = jobs[index];
      let tr = existing.get(id);
      if (tr) {
        patchJobRow(tr, job, api, onError, reload);
        const ref = tbody.children[index];
        if (ref !== tr) tbody.insertBefore(tr, ref || null);
      } else {
        tr = buildJobRow(job, api, onError, reload);
        tbody.insertBefore(tr, tbody.children[index] || null);
      }
    });

    existing.forEach((tr, id) => {
      if (!nextIds.includes(id)) tr.remove();
    });
  }

  window.KitelonJobs = {
    syncJobsTable,
    buildJobRow,
    patchJobRow,
  };
})();
