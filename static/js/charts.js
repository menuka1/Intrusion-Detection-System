/* Chart.js wrappers: charts are created once and updated in place on refresh. */
const Charts = (() => {
  const C = { normal: '#16A34A', malicious: '#DC2626', warn: '#F59E0B', blue: '#2563EB', navy: '#1E293B', grey: '#94a3b8', teal: '#0891B2', violet: '#7C3AED' };
  const LEVEL = { Critical: '#DC2626', High: '#F59E0B', Medium: '#3B82F6', Low: '#94a3b8' };
  const STATUS = { Open: '#DC2626', Acknowledged: '#F59E0B', Resolved: '#16A34A' };
  const SERIES = ['#2563EB', '#0891B2', '#7C3AED', '#F59E0B', '#16A34A', '#DB2777'];
  const registry = {};

  const available = () => typeof Chart !== 'undefined';

  function setEmpty(id, empty, msg) {
    const canvas = document.getElementById(id); if (!canvas) return;
    const box = canvas.parentElement;
    let ov = box.querySelector('.chart-empty');
    if (empty) {
      if (!ov) { ov = document.createElement('div'); ov.className = 'chart-empty'; box.appendChild(ov); }
      ov.textContent = msg || 'No data yet.';
    } else if (ov) ov.remove();
  }

  function render(id, config, empty, emptyMsg) {
    if (!available()) { setEmpty(id, true, 'Chart library could not be loaded (internet access to cdn.jsdelivr.net is required).'); return; }
    const canvas = document.getElementById(id); if (!canvas) return;
    setEmpty(id, empty, emptyMsg);
    const existing = registry[id];
    if (existing) {
      existing.data = config.data; existing.options = config.options; existing.update('none');
    } else {
      registry[id] = new Chart(canvas, config);
    }
  }

  const base = { responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, usePointStyle: true } } } };

  function doughnut(id, labels, data, colors, emptyMsg) {
    const total = data.reduce((a, b) => a + b, 0);
    render(id, { type: 'doughnut', data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0 }] }, options: { ...base, cutout: '62%' } }, total === 0, emptyMsg);
  }

  function bar(id, labels, series, { stacked = false, pct = false, emptyMsg, horizontal = false } = {}) {
    const empty = !series.some((s) => s.data.some((v) => v > 0));
    render(id, {
      type: 'bar',
      data: { labels, datasets: series.map((s, i) => ({ label: s.name, data: s.data, backgroundColor: s.color || SERIES[i % SERIES.length], borderRadius: 4 })) },
      options: { ...base, indexAxis: horizontal ? 'y' : 'x', scales: { x: { stacked, grid: { display: false } }, y: { stacked, beginAtZero: true, max: pct ? 1 : undefined, ticks: { precision: pct ? 2 : 0 } } } },
    }, empty, emptyMsg);
  }

  function line(id, labels, series, emptyMsg) {
    const empty = !series.some((s) => s.data.some((v) => v > 0));
    render(id, {
      type: 'line',
      data: { labels, datasets: series.map((s, i) => ({ label: s.name, data: s.data, borderColor: s.color || SERIES[i], backgroundColor: (s.color || SERIES[i]) + '22', fill: true, tension: .3, pointRadius: 2, borderWidth: 2 })) },
      options: { ...base, scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 8 } }, y: { beginAtZero: true, ticks: { precision: 0 } } } },
    }, empty, emptyMsg);
  }

  function destroyAll() { Object.values(registry).forEach((c) => c.destroy()); for (const k in registry) delete registry[k]; }
  return { C, LEVEL, STATUS, SERIES, doughnut, bar, line, render, destroyAll };
})();
