(() => {
  const { api, esc, $, $$, toast } = App;
  const TYPES = [['traffic', 'Network Traffic'], ['intrusion', 'Intrusion Detection'], ['threat_summary', 'Threat Summary'], ['ml_performance', 'ML Performance'], ['dataset_analysis', 'Dataset Analysis'], ['alert_history', 'Historical Alerts']];
  let type = 'traffic', chartSeq = 0;
  const TONE = { ok: 'ok', danger: 'danger', warn: 'warn' };

  const qs = () => {
    const p = new URLSearchParams(new FormData($('#rFilters')));
    [...p.keys()].forEach((k) => { if (!p.get(k)) p.delete(k); }); p.set('type', type); return p;
  };

  function syncFilters() {
    $$('#rFilters [data-for]').forEach((el) => { el.hidden = !el.dataset.for.split(',').includes(type); });
    $$('#rTabs .tab').forEach((t) => t.classList.toggle('active', t.dataset.type === type));
  }

  function render(r) {
    chartSeq++;
    const filters = Object.entries(r.filters).map(([k, v]) => `${esc(k)}: <strong>${esc(v)}</strong>`).join(' · ') || 'no filters (all data)';
    const out = $('#rOut');
    out.innerHTML = `<div class="card-head"><div><h2 style="font-size:20px">${esc(r.title)}</h2><span class="sub">Generated ${esc(r.generated_at)} · ${filters}</span></div></div>
      <div class="report-kpis">${r.kpis.map((k) => `<div class="card stat ${TONE[k.tone] || ''}"><span class="label">${esc(k.label)}</span><span class="value" style="font-size:22px">${esc(k.value)}</span></div>`).join('')}</div>
      <div class="grid cols-2">${r.charts.map((c, i) => `<div class="report-section"><h3>${esc(c.title)}</h3><div class="chart-box"><canvas id="rc${i}"></canvas></div></div>`).join('')}</div>
      ${r.tables.map((t) => `<div class="report-section"><h3>${esc(t.title)}</h3><div class="table-wrap"><table><thead><tr>${t.columns.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead>
        <tbody>${t.rows.length ? t.rows.map((row) => `<tr>${row.map((c) => `<td>${esc(c)}</td>`).join('')}</tr>`).join('') : `<tr><td colspan="${t.columns.length}" class="empty-inline">No data for the selected filters.</td></tr>`}</tbody></table></div></div>`).join('')}`;
    Charts.destroyAll();
    r.charts.forEach((c, i) => {
      const colors = c.type === 'doughnut' ? c.labels.map((l) => Charts.LEVEL[l] || Charts.STATUS[l] || Charts.SERIES[c.labels.indexOf(l) % 6]) : null;
      if (c.type === 'doughnut') Charts.doughnut('rc' + i, c.labels, c.series[0].data, colors, 'No data.');
      else if (c.type === 'line') Charts.line('rc' + i, c.labels, c.series.map((s) => ({ ...s, color: s.name === 'Normal' ? Charts.C.normal : Charts.C.malicious })), 'No data.');
      else Charts.bar('rc' + i, c.labels, c.series.map((s) => ({ ...s, color: s.name === 'Normal' ? Charts.C.normal : (s.name === 'Malicious' ? Charts.C.malicious : undefined) })), { emptyMsg: 'No data.', pct: c.title.includes('metrics') });
    });
  }

  async function generate() {
    try { $('#rOut').innerHTML = '<div class="empty-inline">Generating…</div>'; render(await api('/api/reports/summary?' + qs())); }
    catch (e) { $('#rOut').innerHTML = `<div class="alert-box alert-danger">${esc(e.message)}</div>`; }
  }

  document.addEventListener('DOMContentLoaded', async () => {
    $('#rTabs').innerHTML = TYPES.map(([k, l]) => `<button type="button" class="tab" data-type="${k}">${l}</button>`).join('');
    $$('#rTabs .tab').forEach((t) => t.addEventListener('click', () => { type = t.dataset.type; syncFilters(); generate(); }));
    try { const ds = await api('/api/datasets'); $('#rDataset').innerHTML = '<option value="">All</option>' + ds.map((d) => `<option value="${d.dataset_id}">${esc(d.dataset_name)}</option>`).join(''); } catch (e) { /* optional */ }
    $('#rFilters').addEventListener('submit', (e) => { e.preventDefault(); generate(); });
    $('#rCsv').addEventListener('click', () => { location.href = '/api/reports/export?' + qs(); });
    $('#rPrint').addEventListener('click', () => window.print());
    syncFilters(); generate();
  });
})();
