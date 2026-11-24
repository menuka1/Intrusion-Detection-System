(() => {
  const { api, esc, $, $$, fmtInt, fmtPct, fmtTime, badge, toast } = App;
  const state = { page: 1, per_page: 25, sort: 'log_id', order: 'desc' };
  let replayTimer = null;

  const params = () => {
    const p = new URLSearchParams(new FormData($('#filters')));
    [...p.keys()].forEach((k) => { if (!p.get(k)) p.delete(k); });
    Object.entries(state).forEach(([k, v]) => p.set(k, v));
    return p;
  };

  async function load() {
    try {
      const d = await api('/api/traffic?' + params());
      const body = $('#trafficBody');
      if (!d.items.length) body.innerHTML = '<tr><td colspan="9" class="empty-inline">No traffic records match. Start a replay or adjust the filters.</td></tr>';
      else body.innerHTML = d.items.map((r) => {
        const mal = r.prediction_result === 'Malicious';
        return `<tr class="clickable ${mal ? 'row-malicious' : ''}" data-id="${r.log_id}"><td>${r.log_id}</td><td>${fmtTime(r.timestamp)}</td><td class="mono">${esc(r.source_ip)}</td><td class="mono">${esc(r.destination_ip)}</td>
          <td>${esc(r.protocol)}</td><td class="num">${fmtInt(r.packet_size)}</td><td>${badge(r.prediction_result, mal ? 'malicious' : 'normal')}</td>
          <td class="num">${fmtPct(r.confidence_score, 1)}</td><td>${r.alert_id ? badge(r.threat_level) + ' #' + r.alert_id : '–'}</td></tr>`;
      }).join('');
      $$('#trafficBody tr.clickable').forEach((tr) => tr.addEventListener('click', () => detail(tr.dataset.id)));
      App.pager($('#pager'), d, (p) => { state.page = p; load(); });
    } catch (e) { toast(e.message, 'error'); }
  }

  async function detail(id) {
    try {
      const r = await api('/api/traffic/' + id);
      const raw = r.raw_data || {}; const feats = raw.features || {}; const meta = raw.meta || {};
      const rows = Object.entries(feats).map(([k, v]) => `<tr><td>${esc(k)}</td><td class="mono">${esc(v)}</td></tr>`).join('');
      const m = App.modal(`Traffic record #${r.log_id}`, `
        <dl class="kv">
          <dt>Timestamp</dt><dd>${fmtTime(r.timestamp)}</dd>
          <dt>Source → Destination</dt><dd class="mono">${esc(r.source_ip)} → ${esc(r.destination_ip)} ${meta.simulated_endpoints ? '<span class="badge warn">simulated addresses</span>' : ''}</dd>
          <dt>Protocol / size</dt><dd>${esc(r.protocol)} · ${fmtInt(r.packet_size)} bytes</dd>
          <dt>Origin</dt><dd>${esc(r.source)} ${r.source === 'replay' ? '(simulated replay of dataset rows)' : '(API request)'}</dd>
          <dt>Model</dt><dd>${esc(r.model_name)} ${esc(r.model_version)}</dd>
          <dt>Prediction</dt><dd>${badge(r.prediction_result, r.prediction_result === 'Malicious' ? 'malicious' : 'normal')}</dd>
          <dt>Confidence</dt><dd>${fmtPct(r.confidence_score, 2)} <span class="sub">(P(malicious) = ${fmtPct(r.malicious_probability, 2)})</span></dd>
          ${meta.ground_truth ? `<dt>Dataset label</dt><dd>${esc(meta.ground_truth)} <span class="sub">(kept for evaluation only; not a model input)</span></dd>` : ''}
          <dt>Alert</dt><dd>${r.alert_id ? `<a href="/alerts?open=${r.alert_id}">#${r.alert_id}</a> ${badge(r.threat_level)} ${badge(r.alert_status)}<br>${esc(r.alert_message)}` : 'No alert'}</dd>
        </dl>
        <h3 style="margin:16px 0 8px">Feature record</h3>
        <div class="table-wrap col-list"><table><tbody>${rows}</tbody></table></div>`);
    } catch (e) { toast(e.message, 'error'); }
  }

  // ---------------------------------------------------------------- replay
  function renderReplay(s) {
    const labels = { idle: 'Idle', loading: 'Loading dataset…', running: 'Running (simulated)', stopped: 'Stopped', completed: 'Completed', error: 'Error' };
    $('#replayState').innerHTML = `${s.running ? '<span class="live-dot"></span>' : ''}${esc(labels[s.state] || s.state)}${s.dataset_name ? ' · ' + esc(s.dataset_name) : ''}`;
    $('#rpBar').style.width = (s.total ? Math.min(100, (s.processed / s.total) * 100) : 0) + '%';
    $('#rpStart').disabled = s.running; $('#rpStop').disabled = !s.running;
    $('#rpStats').innerHTML = `<div><strong>${fmtInt(s.processed)}</strong>processed</div><div><strong>${fmtInt(s.normal)}</strong>normal</div>
      <div><strong>${fmtInt(s.malicious)}</strong>malicious</div><div><strong>${fmtInt(s.alerts)}</strong>alerts raised</div>
      <div><strong>${s.ground_truth_accuracy === null ? '–' : fmtPct(s.ground_truth_accuracy)}</strong>agreement with dataset labels</div>
      ${s.error ? `<div style="color:var(--danger)"><strong>Error</strong>${esc(s.error)}</div>` : ''}`;
    $('#liveHint').innerHTML = s.running ? '<span class="live-dot"></span>refreshing automatically' : '';
    return s;
  }

  async function pollReplay() {
    try {
      const s = renderReplay(await api('/api/traffic/replay/status'));
      if (s.running && state.page === 1) load();
    } catch (e) { /* transient */ }
  }

  async function init() {
    try {
      const [ds, protos, st] = await Promise.all([api('/api/datasets'), api('/api/traffic/protocols'), api('/api/settings')]);
      $('#rpDataset').innerHTML = ds.length ? ds.map((d) => `<option value="${d.dataset_id}">${esc(d.dataset_name)} (${fmtInt(d.row_count)} rows)</option>`).join('') : '<option value="">No datasets uploaded</option>';
      const def = st.settings.default_dataset_id; if (def) $('#rpDataset').value = def;
      $('#rpSpeed').value = st.settings.replay_speed;
      $('#fProtocol').innerHTML = '<option value="">All</option>' + protos.map((p) => `<option>${esc(p)}</option>`).join('');
    } catch (e) { toast(e.message, 'error'); }
    if (!App.isAdmin()) $$('[data-admin]').forEach((b) => { b.disabled = true; b.title = 'Administrator only'; });

    $('#rpStart').addEventListener('click', async () => {
      try {
        const body = { dataset_id: Number($('#rpDataset').value), speed: Number($('#rpSpeed').value), max_records: $('#rpMax').value ? Number($('#rpMax').value) : null };
        renderReplay(await api('/api/traffic/replay/start', { method: 'POST', body }));
        toast('Replay started (simulation).', 'success');
      } catch (e) { toast(e.message, 'error'); }
    });
    $('#rpStop').addEventListener('click', async () => {
      try { renderReplay(await api('/api/traffic/replay/stop', { method: 'POST', body: {} })); load(); toast('Replay stopped.'); } catch (e) { toast(e.message, 'error'); }
    });
    $('#filters').addEventListener('input', App.debounce(() => { state.page = 1; load(); }));
    $('#filters').addEventListener('reset', () => setTimeout(() => { state.page = 1; load(); }));
    $$('th.sortable').forEach((th) => th.addEventListener('click', () => {
      state.order = state.sort === th.dataset.sort && state.order === 'desc' ? 'asc' : 'desc'; state.sort = th.dataset.sort; load();
    }));
    await load(); await pollReplay();
    replayTimer = setInterval(() => { if (!document.hidden) pollReplay(); }, 2000);
  }
  document.addEventListener('DOMContentLoaded', init);
})();
