/* Dashboard: all values come from the backend and refresh without reloading the page. */
(() => {
  const { api, esc, $, fmtInt, fmtPct, fmtClock, fmtTime, badge, algoName } = App;
  const C = Charts.C;
  let timer = null;

  function renderStats(s) {
    $('#stTotal').textContent = fmtInt(s.total);
    $('#stNormal').textContent = fmtInt(s.normal);
    $('#stMal').textContent = fmtInt(s.malicious);
    $('#stAlerts').textContent = fmtInt(s.active_alerts);
    $('#stNormalPct').textContent = s.total ? `${((s.normal / s.total) * 100).toFixed(1)}% of traffic` : 'no traffic analysed yet';
    $('#stMalPct').textContent = s.total ? `${((s.malicious / s.total) * 100).toFixed(1)}% of traffic` : ' ';
    const m = s.selected_model;
    $('#stAcc').textContent = m ? fmtPct(m.accuracy) : '–';
    $('#stAccHint').textContent = m ? `${algoName(m.algorithm)} v${m.version} (test set)` : 'no active model';
    $('#noModelNotice').hidden = !!m;
    renderSystem(s.system);
    Charts.doughnut('chSplit', ['Normal', 'Malicious'], [s.normal, s.malicious], [C.normal, C.malicious], 'No traffic analysed yet.');
  }

  function statusRow(label, cls, text) {
    return `<li><span>${esc(label)}</span><span class="pill ${cls}"><i class="dot"></i>${esc(text)}</span></li>`;
  }

  function renderSystem(sys) {
    const m = sys.ml_engine, sel = sys.selected_model;
    $('#sysStatus').innerHTML = [
      statusRow('Database', sys.database.ok ? 'ok' : 'bad', `${sys.database.label} (${sys.database.backend})`),
      statusRow('ML engine', m.state === 'ready' ? 'ok' : (m.state === 'error' ? 'bad' : 'warn'), m.label),
      statusRow('Selected model', sel ? 'ok' : 'warn', sel ? `${algoName(sel.algorithm)} v${sel.version}` : 'None selected'),
      statusRow('Dataset processing', sys.dataset_processing.preprocessing || sys.dataset_processing.training_jobs_active ? 'warn' : 'ok',
        `${sys.dataset_processing.label} · ${sys.dataset_processing.training_jobs_active} training job(s)`),
      statusRow('Traffic replay', sys.replay.running ? 'warn' : '', sys.replay.running ? `Running (simulated) · ${fmtInt(sys.replay.processed)} records` : `Not running (${sys.replay.state})`),
      statusRow('Application health', sys.health === 'healthy' ? 'ok' : 'bad', sys.health),
    ].join('');
  }

  function renderTraffic(rows) {
    const body = $('#trafficBody');
    if (!rows.length) { body.innerHTML = '<tr><td colspan="8" class="empty-inline">No traffic has been analysed yet. Start a dataset replay on the Traffic Monitoring page.</td></tr>'; return; }
    body.innerHTML = rows.map((r) => {
      const mal = r.prediction_result === 'Malicious';
      return `<tr class="${mal ? 'row-malicious' : ''}"><td>${fmtClock(r.timestamp)}</td><td class="mono">${esc(r.source_ip)}</td><td class="mono">${esc(r.destination_ip)}</td>
        <td>${esc(r.protocol)}</td><td class="num">${fmtInt(r.packet_size)}</td><td>${badge(r.prediction_result, mal ? 'malicious' : 'normal')}</td>
        <td class="num">${fmtPct(r.confidence_score, 1)}</td><td>${mal ? badge('Threat Detected', 'danger') : badge('Normal', 'ok')}</td></tr>`;
    }).join('');
  }

  function renderSummary(t) {
    renderTraffic(t.recent);
    const fmtT = (iso) => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    Charts.line('chTimeline', t.timeline.map((b) => fmtT(b.t)), [
      { name: 'Normal', data: t.timeline.map((b) => b.normal), color: C.normal },
      { name: 'Malicious', data: t.timeline.map((b) => b.malicious), color: C.malicious }], 'No traffic in the last 30 minutes.');
    Charts.bar('chProto', t.protocols.map((p) => p.protocol), [
      { name: 'Normal', data: t.protocols.map((p) => p.total - p.malicious), color: C.normal },
      { name: 'Malicious', data: t.protocols.map((p) => p.malicious), color: C.malicious }], { stacked: true, emptyMsg: 'No protocol data yet.' });
  }

  function renderAlerts(a) {
    const levels = ['Critical', 'High', 'Medium', 'Low'].filter((l) => a.by_level[l]);
    Charts.doughnut('chLevel', levels, levels.map((l) => a.by_level[l]), levels.map((l) => Charts.LEVEL[l]), 'No alerts raised yet.');
    const st = ['Open', 'Acknowledged', 'Resolved'].filter((s) => a.by_status[s]);
    Charts.doughnut('chAlertStatus', st, st.map((s) => a.by_status[s]), st.map((s) => Charts.STATUS[s]), 'No alerts raised yet.');
    const ul = $('#recentAlerts');
    if (!a.recent.length) { ul.innerHTML = '<li class="empty-inline" style="border:0">No intrusion alerts. Alerts appear when the active model flags malicious traffic.</li>'; return; }
    ul.innerHTML = a.recent.map((x) => `<li class="${esc(x.threat_level)}"><div><strong>#${x.alert_id}</strong> ${badge(x.threat_level)} ${badge(x.status)}
      <span class="mono">${esc(x.source_ip)} → ${esc(x.destination_ip)}</span> [${esc(x.protocol)}]</div>
      <div class="meta"><span>${esc(x.model_name)} · confidence ${fmtPct(x.confidence_score, 1)}</span><span>${fmtTime(x.created_at)}</span></div></li>`).join('');
  }

  function renderModels(models) {
    Charts.bar('chModels', models.map((m) => `${m.display_name} v${m.version}`), [
      { name: 'Accuracy', data: models.map((m) => m.accuracy), color: C.blue },
      { name: 'Precision', data: models.map((m) => m.precision_score), color: C.teal },
      { name: 'Recall', data: models.map((m) => m.recall_score), color: C.violet },
      { name: 'F1', data: models.map((m) => m.f1_score), color: C.warn }], { pct: true, emptyMsg: 'No trained models yet.' });
  }

  async function refresh() {
    try {
      const [s, t, a] = await Promise.all([api('/api/dashboard/statistics'), api('/api/dashboard/traffic-summary'), api('/api/dashboard/alert-summary')]);
      renderStats(s); renderSummary(t); renderAlerts(a);
    } catch (e) { App.toast(e.message, 'error'); }
  }

  async function loadModels() {
    try { renderModels(await api('/api/models/metrics')); } catch (e) { /* shown elsewhere */ }
  }

  async function init() {
    await refresh(); loadModels();
    let secs = 5;
    try { const st = await api('/api/settings'); secs = Math.max(2, Number(st.settings.dashboard_refresh_seconds) || 5); } catch (e) { /* default */ }
    timer = setInterval(() => { if (!document.hidden) refresh(); }, secs * 1000);
    setInterval(() => { if (!document.hidden) loadModels(); }, 30000);
  }
  document.addEventListener('DOMContentLoaded', init);
})();
