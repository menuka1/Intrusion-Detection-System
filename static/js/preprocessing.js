(() => {
  const sel = document.getElementById('ppDataset'); if (!sel) return;
  const { api, esc, $, $$, fmtInt, badge, toast } = App;
  let current = null, poll = null;

  async function loadDataset(id) {
    clearTimeout(poll);
    try {
      const d = await api('/api/datasets/' + id);
      current = d; const meta = d.metadata || {};
      $('#ppInfo').innerHTML = `${fmtInt(d.row_count)} rows · ${d.column_count} columns · type ${esc(d.dataset_type)} · status ${badge(d.processing_status)}`;
      const cols = meta.columns || [];
      $('#ppLabel').innerHTML = cols.map((c) => `<option ${c.name === d.label_column ? 'selected' : ''}>${esc(c.name)}</option>`).join('');
      const excludeDefault = new Set((d.preprocess_config?.exclude_columns) || []);
      const known = { 'nsl-kdd': ['difficulty'], 'unsw-nb15': ['id', 'attack_cat'] }[d.dataset_type] || [];
      $('#ppCols').innerHTML = cols.map((c) => {
        const locked = known.includes(c.name);
        return `<tr><td><input type="checkbox" data-col="${esc(c.name)}" ${(c.name === d.label_column || locked || excludeDefault.has(c.name)) ? '' : 'checked'} ${locked ? 'disabled' : ''}></td>
          <td>${esc(c.name)} ${locked ? '<span class="badge info" title="Identifier / leaks the label: always excluded">auto-excluded</span>' : ''}</td><td>${esc(c.kind)}</td><td class="num">${fmtInt(c.missing)}</td><td class="num">${fmtInt(c.unique)}</td></tr>`;
      }).join('');
      const miss = meta.missing || { total: 0, columns_affected: 0 };
      $('#ppQuality').innerHTML = `<div class="note">Missing values: <strong>${fmtInt(miss.total)}</strong> (${miss.columns_affected || 0} columns) · Duplicate rows: <strong>${fmtInt(meta.duplicate_rows)}</strong></div>`;
      const cfg = d.preprocess_config;
      if (cfg) { const f = $('#ppForm'); ['scaling', 'feature_selection', 'k_features', 'test_size', 'val_size', 'seed'].forEach((k) => { if (cfg[k] !== null && cfg[k] !== undefined) f[k].value = cfg[k]; }); f.drop_duplicates.checked = cfg.drop_duplicates; }
      renderStatus(d);
    } catch (e) { toast(e.message, 'error'); }
  }

  function renderStatus(d) {
    $('#ppStatus').innerHTML = badge(d.processing_status);
    const err = d.processing_status === 'Failed' && d.error_message ? `<div class="alert-box alert-danger">${esc(d.error_message)}</div>` : '';
    if (d.processing_status === 'Preprocessing') {
      $('#ppSummary').innerHTML = '<div class="empty-inline">Preprocessing is running in the background…</div>';
      poll = setTimeout(() => loadDataset(d.dataset_id), 1500);
    } else $('#ppSummary').innerHTML = err + renderPrepSummary(d.preprocess_summary);
    $('#ppRun').disabled = !App.isAdmin() || d.processing_status === 'Preprocessing';
  }

  async function init() {
    try {
      const list = await api('/api/datasets');
      sel.innerHTML = list.length ? list.map((d) => `<option value="${d.dataset_id}">${esc(d.dataset_name)}</option>`).join('') : '<option value="">No datasets: upload one first</option>';
      $('#ppTest').innerHTML = '<option value="">None - stratified split</option>' + list.map((d) => `<option value="${d.dataset_id}">${esc(d.dataset_name)}</option>`).join('');
      const want = new URLSearchParams(location.search).get('dataset');
      if (want && list.some((d) => String(d.dataset_id) === want)) sel.value = want;
      if (list.length) loadDataset(sel.value);
    } catch (e) { toast(e.message, 'error'); }
    sel.addEventListener('change', () => loadDataset(sel.value));
    if (!App.isAdmin()) $$('[data-admin]').forEach((b) => { b.disabled = true; b.title = 'Administrator only'; });
    $('#ppForm').addEventListener('submit', async (e) => {
      e.preventDefault(); if (!current) return;
      const f = e.target;
      const body = {
        label_column: $('#ppLabel').value, exclude_columns: $$('#ppCols input[type=checkbox]').filter((c) => !c.checked && !c.disabled).map((c) => c.dataset.col),
        scaling: f.scaling.value, feature_selection: f.feature_selection.value, k_features: f.k_features.value ? Number(f.k_features.value) : null,
        drop_duplicates: f.drop_duplicates.checked, test_size: Number(f.test_size.value), val_size: Number(f.val_size.value), seed: Number(f.seed.value),
        test_dataset_id: $('#ppTest').value ? Number($('#ppTest').value) : null };
      try { await api(`/api/datasets/${current.dataset_id}/preprocess`, { method: 'POST', body }); toast('Preprocessing started.'); loadDataset(current.dataset_id); }
      catch (err) { toast(err.message, 'error'); }
    });
  }
  document.addEventListener('DOMContentLoaded', init);
})();
