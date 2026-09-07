(function () {
  const SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"];

  const SEVERITY_COLORS = {
    critical: "#dc3545",
    high: "#fd7e14",
    medium: "#ffc107",
    low: "#17a2b8",
    info: "#6c757d",
  };

  const EMPTY_RING = "#2a3140";

  function severityCountsFromStats(stats) {
    const s = stats || {};
    return SEVERITY_LEVELS.map((level) => ({
      level,
      count: Number(s["vuln_" + level + "_total"] || 0),
      color: SEVERITY_COLORS[level],
    }));
  }

  function formatRiskScore(value) {
    const n = Number(value || 0);
    if (n >= 80) return { text: String(n), className: "risk-high" };
    if (n >= 40) return { text: String(n), className: "risk-medium" };
    if (n > 0) return { text: String(n), className: "risk-low" };
    return { text: "0", className: "risk-none" };
  }

  function donutDataset(counts) {
    const filtered = counts.filter((row) => row.count > 0);
    if (!filtered.length) {
      return {
        labels: ["empty"],
        data: [1],
        backgroundColor: [EMPTY_RING],
        borderWidth: 0,
        empty: true,
      };
    }
    return {
      labels: filtered.map((row) => row.level),
      data: filtered.map((row) => row.count),
      backgroundColor: filtered.map((row) => row.color),
      borderWidth: 0,
      empty: false,
    };
  }

  function createSeverityDonut(canvas, stats) {
    if (!window.Chart) {
      throw new Error("Chart.js is required for severity donuts");
    }
    const counts = severityCountsFromStats(stats);
    const dataset = donutDataset(counts);
    const chart = new Chart(canvas.getContext("2d"), {
      type: "doughnut",
      data: {
        labels: dataset.labels,
        datasets: [{
          data: dataset.data,
          backgroundColor: dataset.backgroundColor,
          borderWidth: dataset.borderWidth,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        cutout: "72%",
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label(ctx) {
                const label = ctx.label || "";
                const value = ctx.parsed || 0;
                return label + ": " + value;
              },
            },
          },
        },
        animation: { duration: 350 },
      },
    });
    chart._kitelonEmpty = dataset.empty;
    return chart;
  }

  function updateSeverityDonut(chart, stats) {
    if (!chart) return;
    const counts = severityCountsFromStats(stats);
    const dataset = donutDataset(counts);
    chart.data.labels = dataset.labels;
    chart.data.datasets[0].data = dataset.data;
    chart.data.datasets[0].backgroundColor = dataset.backgroundColor;
    chart._kitelonEmpty = dataset.empty;
    chart.update("none");
  }

  function updateDonutCenter(centerEl, stats) {
    if (!centerEl) return;
    const risk = formatRiskScore((stats || {}).workspace_risk_score);
    const scoreEl = centerEl.querySelector(".donut-score");
    const labelEl = centerEl.querySelector(".donut-label");
    if (scoreEl) {
      scoreEl.textContent = risk.text;
      scoreEl.className = "donut-score " + risk.className;
    }
    if (labelEl) {
      const total = Number((stats || {}).vulnerabilities_total || 0);
      labelEl.textContent = total ? "Risk" : "No findings";
    }
  }

  function mountSeverityDonut(wrapEl, stats) {
    const canvas = wrapEl.querySelector("canvas");
    const center = wrapEl.querySelector(".donut-center");
    let chart = wrapEl._kitelonChart;
    if (!chart) {
      chart = createSeverityDonut(canvas, stats);
      wrapEl._kitelonChart = chart;
    } else {
      updateSeverityDonut(chart, stats);
    }
    updateDonutCenter(center, stats);
    wrapEl.classList.toggle("donut-empty", !!chart._kitelonEmpty);
  }

  window.KitelonCharts = {
    SEVERITY_LEVELS,
    SEVERITY_COLORS,
    severityCountsFromStats,
    formatRiskScore,
    createSeverityDonut,
    updateSeverityDonut,
    updateDonutCenter,
    mountSeverityDonut,
  };
})();
