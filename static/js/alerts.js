(() => {
  const { api, esc, $, $$, fmtInt, fmtPct, fmtTime, badge, toast } = App;
  const state = { page: 1, per_page: 20 };

  const query = () => {
    const p = new URLSearchParams(new FormData($('#aFilters')));
    [...p.keys()].forEach((k) => { if (!p.get(k)) p.delete(k); });
    p.set('page', state.page); p.set('per_page', state.per_page); return p;
  };

  async function load() {
    try {
      const d = await api('/api/alerts?' + query());
      const s = d.summary.by_status;
      $('#aOpen').textContent = fmtInt(s.Open || 0); $('#aAck').textContent = fmtInt(s.Acknowledged || 0); $('#aRes').textContent = fmtInt(s.Resolved || 0);
      $('#aTot').textContent = fmtInt((s.Open || 0) + (s.Acknowledged || 0) + (s.Resolved || 0));
      $('#aBody').innerHTML = d.items.length ? d.items.map((a) => `<tr class="clickable" data-id="${a.alert_id}"><td>#${a.alert_id}</td><td>${fmtTime(a.created_at)}</td><td class="mono">${esc(a.source_ip)}</td>
        <td class="mono">${esc(a.destination_ip)}</td><td>${esc(a.protocol)}</td><td>${esc(a.model_name)}</td><td class="num">${fmtPct(a.confidence_score, 1)}</td>
        <td>${badge(a.threat_level)}</td><td>${badge(a.status)}</td>
        <td style="white-space:nowrap">${a.status === 'Open' ? `<button class="btn btn-sm" data-ack="${a.alert_id}">Acknowledge</button> ` : ''}${a.status !== 'Resolved' ? `<button class="btn btn-sm btn-ok" data-res="${a.alert_id}">Resolve</button>` : ''}</td></tr>`).join('')
        : '<tr><td colspan="10" class="empty-inline">No alerts match. Alerts are created only when the active model flags malicious traffic.</td></tr>';
      $$('#aBody tr.clickable').forEach((tr) => tr.addEventListener('click', (e) => { if (!e.target.closest('button')) detail(tr.dataset.id); }));
      $$('[data-ack]').forEach((b) => b.addEventListener('click', () => setStatus(b.dataset.ack, 'Acknowledged')));
      $$('[data-res]').forEach((b) => b.addEventListener('click', () => setStatus(b.dataset.res, 'Resolved')));
      App.pager($('#aPager'), d, (p) => { state.page = p; load(); });
    } catch (e) { toast(e.message, 'error'); }
  }

  async function setStatus(id, status, refreshModal) {
    try { await api(`/api/alerts/${id}/status`, { method: 'PATCH', body: { status } }); toast(`Alert #${id} ${status.toLowerCase()}.`, 'success'); load(); if (refreshModal) { refreshModal.close(); detail(id); } }
    catch (e) { toast(e.message, 'error'); }
  }

  async function detail(id) {
    try {
      const d = await api('/api/alerts/' + id); const a = d.alert, l = d.log || {};
      const feats = ((l.raw_data || {}).features) || {};
      const rows = Object.entries(feats).map(([k, v]) => `<tr><td>${esc(k)}</td><td class="mono">${esc(v)}</td></tr>`).join('');
      const m = App.modal(`Alert #${a.alert_id}`, `
        <p>${esc(l.alert_message || '')}</p>
        <dl class="kv"><dt>Detected</dt><dd>${fmtTime(a.created_at)}</dd><dt>Threat level</dt><dd>${badge(a.threat_level)} <span class="sub">rule-based, independent of confidence</span></dd>
          <dt>Status</dt><dd>${badge(a.status)}</dd><dt>Source → Destination</dt><dd class="mono">${esc(a.source_ip)} → ${esc(a.destination_ip)} [${esc(a.protocol)}]</dd>
          <dt>Packet size</dt><dd>${fmtInt(a.packet_size)} bytes</dd><dt>Model prediction</dt><dd>${esc(a.model_name)} ${esc(a.model_version)}: ${esc(a.prediction_result)} · confidence ${fmtPct(a.confidence_score, 2)} (P(malicious) ${fmtPct(l.malicious_probability, 2)})</dd>
          <dt>Network log</dt><dd>#${a.log_id} (${esc(l.source)})</dd></dl>
        <div style="margin:14px 0;display:flex;gap:8px">${a.status === 'Open' ? '<button class="btn" id="mAck">Acknowledge</button>' : ''}${a.status !== 'Resolved' ? '<button class="btn btn-ok" id="mRes">Resolve</button>' : ''}${a.status !== 'Open' ? '<button class="btn" id="mOpen">Re-open</button>' : ''}</div>
        <h3 style="margin:10px 0 8px">Other records from this source</h3>
        <div class="table-wrap"><table><thead><tr><th>Time</th><th>Destination</th><th>Prediction</th><th>Confidence</th></tr></thead><tbody>${d.related.length ? d.related.map((r) => `<tr><td>${fmtTime(r.timestamp)}</td><td class="mono">${esc(r.destination_ip)}</td><td>${badge(r.prediction_result, r.prediction_result === 'Malicious' ? 'malicious' : 'normal')}</td><td>${fmtPct(r.confidence_score, 1)}</td></tr>`).join('') : '<tr><td colspan="4" class="empty-inline">None.</td></tr>'}</tbody></table></div>
        <h3 style="margin:14px 0 8px">Feature record analysed</h3><div class="table-wrap col-list"><table><tbody>${rows}</tbody></table></div>`);
      $('#mAck', m.el)?.addEventListener('click', () => setStatus(id, 'Acknowledged', m));
      $('#mRes', m.el)?.addEventListener('click', () => setStatus(id, 'Resolved', m));
      $('#mOpen', m.el)?.addEventListener('click', () => setStatus(id, 'Open', m));
    } catch (e) { toast(e.message, 'error'); }
  }

  document.addEventListener('DOMContentLoaded', () => {
    $('#aFilters').addEventListener('input', App.debounce(() => { state.page = 1; load(); }));
    $('#aFilters').addEventListener('reset', () => setTimeout(() => { state.page = 1; load(); }));
    load(); setInterval(() => { if (!document.hidden && !document.querySelector('.modal')) load(); }, 6000);
    const open = new URLSearchParams(location.search).get('open'); if (open) detail(open);
  });
})();
