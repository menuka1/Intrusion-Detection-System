/* Dataset list, upload, details page. Also exposes renderPrepSummary() for the preprocessing page. */
function renderPrepSummary(s) {
  const { esc, fmtInt } = App;
  if (!s) return '<div class="empty-inline">This dataset has not been preprocessed yet.</div>';
  const sp = (x) => `<td class="num">${fmtInt(x.total)}</td><td class="num">${fmtInt(x.normal)}</td><td class="num">${fmtInt(x.malicious)}</td>`;
  const rank = (s.feature_ranking || []).slice(0, 12).map((r) => `<tr><td>${esc(r.feature)}</td><td class="num">${r.score.toFixed(2)}</td></tr>`).join('');
  return `
    <div class="grid cols-2">
      <div><h3 style="margin-bottom:8px">Before → after</h3>
        <div class="table-wrap"><table><thead><tr><th>Measure</th><th class="num">Before</th><th class="num">After</th></tr></thead><tbody>
          <tr><td>Rows</td><td class="num">${fmtInt(s.before.rows)}</td><td class="num">${fmtInt(s.after.rows)}</td></tr>
          <tr><td>Columns</td><td class="num">${fmtInt(s.before.columns)}</td><td class="num">${fmtInt(s.after.feature_columns)} features</td></tr>
          <tr><td>Missing values</td><td class="num">${fmtInt(s.before.missing_values)}</td><td class="num">imputed (train median / mode)</td></tr>
          <tr><td>Duplicate rows</td><td class="num">${fmtInt(s.before.duplicate_rows)}</td><td class="num">${fmtInt(s.cleaning.duplicates_removed)} removed</td></tr>
          <tr><td>Missing labels removed</td><td class="num">–</td><td class="num">${fmtInt(s.cleaning.missing_label_removed)}</td></tr>
          <tr><td>Numeric / categorical</td><td class="num">–</td><td class="num">${s.after.numeric_columns} / ${s.after.categorical_columns}</td></tr>
          <tr><td>Encoded features</td><td class="num">–</td><td class="num">${fmtInt(s.after.encoded_features)}</td></tr>
          <tr><td>Selected features</td><td class="num">–</td><td class="num">${fmtInt(s.after.selected_features)} (${esc(s.feature_selection)}${s.k_features ? ', k=' + s.k_features : ''})</td></tr>
        </tbody></table></div>
        <p class="sub" style="margin-top:8px">Scaling: <strong>${esc(s.scaling)}</strong> · label: <code>${esc(s.label_column)}</code> · seed ${s.seed}<br>
        Excluded columns: ${(s.excluded_columns || []).map((c) => `<code>${esc(c)}</code>`).join(' ') || 'none'}${s.constant_columns_removed?.length ? '<br>Constant (removed): ' + s.constant_columns_removed.map((c) => `<code>${esc(c)}</code>`).join(' ') : ''}</p>
      </div>
      <div><h3 style="margin-bottom:8px">Split (${esc(s.split_mode)})</h3>
        <div class="table-wrap"><table><thead><tr><th>Split</th><th class="num">Records</th><th class="num">Normal</th><th class="num">Malicious</th></tr></thead><tbody>
          <tr><td>Training</td>${sp(s.splits.train)}</tr><tr><td>Validation</td>${sp(s.splits.validation)}</tr><tr><td>Test (held out)</td>${sp(s.splits.test)}</tr>
        </tbody></table></div>
        <p class="sub" style="margin-top:8px">${esc(s.fit_on)}</p>
        ${rank ? `<h3 style="margin:14px 0 8px">Top feature scores</h3><div class="table-wrap"><table><tbody>${rank}</tbody></table></div>` : ''}
      </div>
    </div>`;
}

(() => {
  const { api, esc, $, $$, fmtInt, fmtBytes, fmtTime, badge, toast } = App;

  // ------------------------------------------------------------ list page
  async function loadList() {
    const body = $('#dsBody'); if (!body) return;
    try {
      const rows = await api('/api/datasets');
      $('#dsCount').textContent = `${rows.length} dataset(s)`;
      if (!rows.length) { body.innerHTML = '<tr><td colspan="9" class="empty-inline">No datasets yet. Upload an NSL-KDD or UNSW-NB15 file above.</td></tr>'; return; }
      body.innerHTML = rows.map((d) => `<tr><td><a href="/datasets/${d.dataset_id}"><strong>${esc(d.dataset_name)}</strong></a><br><span class="sub">${esc(d.original_filename)}</span></td>
        <td>${esc(({ 'nsl-kdd': 'NSL-KDD', 'unsw-nb15': 'UNSW-NB15', custom: 'Custom' })[d.dataset_type] || d.dataset_type)}</td><td class="num">${fmtBytes(d.file_size)}</td>
        <td class="num">${fmtInt(d.row_count)}</td><td class="num">${fmtInt(d.column_count)}</td><td>${d.label_column ? `<code>${esc(d.label_column)}</code>` : '<span class="badge warn">not set</span>'}</td>
        <td>${badge(d.processing_status)}${d.error_message ? `<br><span class="sub" style="color:var(--danger)">${esc(d.error_message)}</span>` : ''}</td><td>${fmtTime(d.created_at)}</td>
        <td style="white-space:nowrap"><a class="btn btn-sm" href="/datasets/${d.dataset_id}">Details</a> <a class="btn btn-sm" href="/preprocessing?dataset=${d.dataset_id}">Preprocess</a>
        ${App.isAdmin() ? `<button class="btn btn-sm btn-danger" data-del="${d.dataset_id}" data-name="${esc(d.dataset_name)}" title="Delete">Delete</button>` : ''}</td></tr>`).join('');
      $$('[data-del]').forEach((b) => b.addEventListener('click', async () => {
        if (!App.confirmBox(`Permanently delete dataset "${b.dataset.name}" and its files? This cannot be undone.`)) return;
        try { await api('/api/datasets/' + b.dataset.del, { method: 'DELETE' }); toast('Dataset deleted.', 'success'); loadList(); } catch (e) { toast(e.message, 'error'); }
      }));
      if (rows.some((d) => d.processing_status === 'Preprocessing')) setTimeout(loadList, 2000);
    } catch (e) { toast(e.message, 'error'); }
  }

  function initList() {
    const form = $('#uploadForm'); if (!form) return;
    if (!App.isAdmin()) $$('[data-admin]').forEach((b) => { b.disabled = true; b.title = 'Administrator only'; });
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = $('#uploadBtn'); btn.disabled = true; btn.textContent = 'Uploading & validating…';
      try {
        const d = await api('/api/datasets/upload', { method: 'POST', form: new FormData(form) });
        toast(`Dataset "${d.dataset_name}" validated: ${fmtInt(d.row_count)} rows.`, 'success'); form.reset(); loadList();
      } catch (err) { toast(err.message, 'error'); }
      btn.disabled = !App.isAdmin(); btn.textContent = 'Upload & validate';
    });
    $$('[data-sample]').forEach((b) => b.addEventListener('click', async () => {
      try { await api('/api/datasets/load-sample', { method: 'POST', body: { type: b.dataset.sample } }); toast('Synthetic sample registered.', 'success'); loadList(); }
      catch (err) { toast(err.message, 'error'); }
    }));
    loadList();
  }

  // ------------------------------------------------------------ details page
  async function initDetail() {
    const root = $('#datasetDetail'); if (!root) return;
    try {
      const d = await api(`/api/datasets/${root.dataset.id}?preview=20`);
      const meta = d.metadata || {};
      $('#dName').textContent = d.dataset_name; $('#dStatus').innerHTML = badge(d.processing_status);
      $('#dMeta').innerHTML = [['Original file', d.original_filename], ['Type', d.dataset_type], ['File size', fmtBytes(d.file_size)], ['Uploaded', fmtTime(d.created_at)],
        ['Records', fmtInt(d.row_count)], ['Columns', fmtInt(d.column_count)], ['Label column', d.label_column || 'not set']].map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('');
      const cc = meta.class_counts;
      if (cc) Charts.doughnut('chClass', ['Normal', 'Malicious'], [cc.normal, cc.malicious], [Charts.C.normal, Charts.C.malicious], 'No label counts.');
      else Charts.doughnut('chClass', [], [], [], 'No label column set: choose one on the Preprocessing page.');
      const miss = meta.missing || { total: 0, by_column: {} };
      $('#dQuality').innerHTML = `<dt>Normal records</dt><dd>${cc ? fmtInt(cc.normal) : '–'}</dd><dt>Malicious records</dt><dd>${cc ? fmtInt(cc.malicious) : '–'}</dd>
        <dt>Unlabelled rows</dt><dd>${cc ? fmtInt(cc.missing_label) : '–'}</dd><dt>Missing values</dt><dd>${fmtInt(miss.total)} in ${miss.columns_affected || 0} column(s)</dd>
        <dt>Duplicate rows</dt><dd>${fmtInt(meta.duplicate_rows)}</dd><dt>Numeric columns</dt><dd>${(meta.numeric_columns || []).length}</dd><dt>Categorical columns</dt><dd>${(meta.categorical_columns || []).length}</dd>`;
      $('#dWarnings').innerHTML = (meta.warnings || []).map((w) => `<div class="note warn" style="margin-top:10px">${esc(w)}</div>`).join('');
      $('#dFeatCount').textContent = `${(meta.columns || []).length} columns`;
      $('#dCols').innerHTML = (meta.columns || []).map((c) => `<tr><td>${esc(c.name)} ${c.is_label ? '<span class="badge info">label</span>' : ''}</td><td>${esc(c.kind)}</td><td>${esc(c.dtype)}</td><td class="num">${fmtInt(c.missing)}</td><td class="num">${fmtInt(c.unique)}</td></tr>`).join('');
      $('#dPrep').innerHTML = (d.processing_status === 'Failed' && d.error_message ? `<div class="alert-box alert-danger">${esc(d.error_message)}</div>` : '') + renderPrepSummary(d.preprocess_summary);
      const pv = d.preview || [];
      if (pv.length) { const cols = Object.keys(pv[0]); $('#dPreview').innerHTML = `<thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${pv.map((r) => `<tr>${cols.map((c) => `<td>${esc(r[c])}</td>`).join('')}</tr>`).join('')}</tbody>`; }
      else $('#dPreview').innerHTML = `<tbody><tr><td class="empty-inline">${esc(d.preview_error || 'No preview available.')}</td></tr></tbody>`;
    } catch (e) { const el = $('#detailError'); el.textContent = e.message; el.hidden = false; }
  }

  document.addEventListener('DOMContentLoaded', () => { initList(); initDetail(); });
})();
