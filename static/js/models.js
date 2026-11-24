/* Model training page and model comparison page. */
(() => {
  const { api, esc, $, $$, fmtInt, fmtPct, fmtNum, fmtTime, badge, algoName, toast } = App;
  const C = Charts.C;

  // =============================================================== training page
  const FIELDS = {
    decision_tree: [
      ['criterion', 'Criterion', 'select', ['gini', 'entropy', 'log_loss'], 'gini'], ['max_depth', 'Max depth', 'number', null, '', 'blank = unlimited'],
      ['min_samples_split', 'Min samples split', 'number', null, 2], ['min_samples_leaf', 'Min samples leaf', 'number', null, 1],
      ['class_weight', 'Class weight', 'select', ['', 'balanced'], '']],
    random_forest: [
      ['n_estimators', 'Number of trees', 'number', null, 100], ['max_depth', 'Max depth', 'number', null, '', 'blank = unlimited'],
      ['min_samples_leaf', 'Min samples leaf', 'number', null, 1], ['max_features', 'Max features', 'select', ['sqrt', 'log2'], 'sqrt'],
      ['class_weight', 'Class weight', 'select', ['', 'balanced', 'balanced_subsample'], '']],
    ann: [
      ['hidden_layers', 'Hidden layers (neurons)', 'text', null, '64,32', 'comma separated'], ['activation', 'Activation', 'select', ['relu', 'tanh', 'elu'], 'relu'],
      ['dropout', 'Dropout', 'number', null, 0.2], ['learning_rate', 'Learning rate', 'number', null, 0.001], ['epochs', 'Max epochs', 'number', null, 30],
      ['batch_size', 'Batch size', 'number', null, 256], ['patience', 'Early-stopping patience', 'number', null, 5]],
  };
  let catalog = [], datasets = [], jobTimer = null;

  function renderFields(algo) {
    $('#paramFields').innerHTML = FIELDS[algo].map(([name, label, type, opts, def, hint]) =>
      `<label class="field"><span>${label}</span>${type === 'select'
        ? `<select data-param="${name}">${opts.map((o) => `<option value="${o}" ${o === def ? 'selected' : ''}>${o || 'none'}</option>`).join('')}</select>`
        : `<input data-param="${name}" type="${type}" step="any" value="${def}">`}${hint ? `<small>${hint}</small>` : ''}</label>`).join('');
  }

  function collectParams() {
    const p = {};
    $$('[data-param]').forEach((el) => { const v = el.value.trim(); if (v !== '') p[el.dataset.param] = el.tagName === 'SELECT' || el.type === 'text' ? v : Number(v); });
    return p;
  }

  function renderCards() {
    $('#algoCards').innerHTML = catalog.map((a) => {
      const m = a.latest_model, j = a.latest_job;
      const running = j && ['Pending', 'Running'].includes(j.job_status);
      const status = running ? j.job_status : (m ? 'Completed' : (j && j.job_status === 'Failed' ? 'Failed' : 'Not trained'));
      return `<div class="card model-card"><h3>${esc(a.display_name)} ${badge(status, status === 'Not trained' ? 'Pending' : status)}</h3><p>${esc(a.description)}</p>
        <dl class="kv" style="grid-template-columns:120px 1fr">
          <dt>Version</dt><dd>${m ? 'v' + m.version + (m.is_active ? ' · <span class="badge active">active</span>' : '') : '–'}</dd>
          <dt>Last trained</dt><dd>${m ? fmtTime(m.created_at) : '–'}</dd><dt>Dataset</dt><dd>${esc(m ? m.dataset_name : (j ? j.dataset_name : '–')) || '–'}</dd>
          <dt>Test F1</dt><dd>${m ? fmtPct(m.f1_score) : '–'}</dd></dl>
        <div class="progress ${status === 'Completed' ? 'ok' : status === 'Failed' ? 'bad' : ''}"><i style="width:${running ? j.progress : (m ? 100 : 0)}%"></i></div>
        <span class="sub">${running ? esc(j.progress_message) : (j && j.job_status === 'Failed' ? esc(j.error_message) : (m ? 'Training complete' : 'No model trained yet'))}</span>
        <button class="btn btn-primary" data-pick="${a.algorithm}" data-admin>Train ${esc(a.display_name)}</button></div>`;
    }).join('');
    $$('[data-pick]').forEach((b) => b.addEventListener('click', () => { $('#trAlgo').value = b.dataset.pick; renderFields(b.dataset.pick); $('#trainForm').scrollIntoView({ behavior: 'smooth' }); }));
    if (!App.isAdmin()) $$('[data-admin]').forEach((b) => { b.disabled = true; b.title = 'Administrator only'; });
  }

  async function loadJobs() {
    try {
      const [jobs, cat] = await Promise.all([api('/api/models/jobs'), api('/api/models/algorithms')]);
      catalog = cat; renderCards();
      $('#jobsBody').innerHTML = jobs.length ? jobs.map((j) => `<tr><td>#${j.job_id}</td><td>${esc(algoName(j.algorithm))}</td><td>${esc(j.dataset_name || '–')}</td><td>${badge(j.job_status)}</td>
        <td><div class="progress ${j.job_status === 'Completed' ? 'ok' : j.job_status === 'Failed' ? 'bad' : ''}"><i style="width:${j.progress}%"></i></div><span class="sub">${esc(j.progress_message || '')}</span></td>
        <td>${fmtTime(j.started_at)}</td><td>${fmtTime(j.completed_at)}</td>
        <td>${j.job_status === 'Failed' ? `<span style="color:var(--danger)">${esc(j.error_message)}</span>` : (j.model_id ? `<a href="/comparison">model #${j.model_id}</a>` : '–')}</td></tr>`).join('')
        : '<tr><td colspan="8" class="empty-inline">No training jobs yet.</td></tr>';
      const active = jobs.some((j) => ['Pending', 'Running'].includes(j.job_status));
      $('#jobsHint').innerHTML = active ? '<span class="live-dot"></span>updating…' : '';
      clearTimeout(jobTimer); jobTimer = setTimeout(loadJobs, active ? 1500 : 6000);
    } catch (e) { toast(e.message, 'error'); }
  }

  async function initTraining() {
    if (!$('#trainForm')) return;
    datasets = await api('/api/datasets');
    $('#trDataset').innerHTML = datasets.length ? datasets.map((d) => `<option value="${d.dataset_id}">${esc(d.dataset_name)} · ${d.processing_status}</option>`).join('') : '<option value="">Upload a dataset first</option>';
    $('#trAlgo').innerHTML = Object.keys(FIELDS).map((a) => `<option value="${a}">${esc(algoName(a))}</option>`).join('');
    renderFields('decision_tree');
    $('#trAlgo').addEventListener('change', (e) => renderFields(e.target.value));
    const hint = () => { const d = datasets.find((x) => String(x.dataset_id) === $('#trDataset').value); $('#dsHint').innerHTML = d ? (d.label_column ? `Label column: <code>${esc(d.label_column)}</code> · ${fmtInt(d.row_count)} rows` : '<span style="color:var(--danger)">This dataset has no label column. Set one on the Preprocessing page.</span>') : ''; };
    $('#trDataset').addEventListener('change', hint); hint();
    $('#trainForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        const job = await api('/api/models/train', { method: 'POST', body: { dataset_id: Number($('#trDataset').value), algorithm: $('#trAlgo').value, params: collectParams() } });
        toast(`Training job #${job.job_id} queued.`, 'success'); loadJobs();
      } catch (err) { toast(err.message, 'error'); }
    });
    loadJobs();
  }

  // =============================================================== comparison page
  const METRICS = [['accuracy', 'Accuracy', 'accuracy', true], ['precision', 'Precision (malicious)', 'precision_score', true], ['recall', 'Recall (malicious)', 'recall_score', true],
    ['f1_score', 'F1-Score (malicious)', 'f1_score', true], ['fpr', 'False Positive Rate', 'fpr', false], ['fnr', 'False Negative Rate', 'fnr', false]];

  function cmHtml(cm) {
    const [[tn, fp], [fn, tp]] = cm;
    return `<div class="cm"><span></span><span class="h">Pred. Normal</span><span class="h">Pred. Malicious</span>
      <span class="h">Actual Normal</span><span class="c good">${fmtInt(tn)}<br><small>TN</small></span><span class="c bad">${fmtInt(fp)}<br><small>FP</small></span>
      <span class="h">Actual Malicious</span><span class="c bad">${fmtInt(fn)}<br><small>FN</small></span><span class="c good">${fmtInt(tp)}<br><small>TP</small></span></div>`;
  }

  async function loadComparison() {
    const ds = $('#cmpDataset').value, metric = $('#cmpMetric').value;
    try {
      const d = await api(`/api/models/comparison?metric=${metric}${ds ? '&dataset_id=' + ds : ''}`);
      if (!$('#cmpDataset').options.length) {
        $('#cmpDataset').innerHTML = d.datasets.map((x) => `<option value="${x.dataset_id}">${esc(x.dataset_name)}</option>`).join('') || '<option value="">No trained models</option>';
        if (d.dataset_id) $('#cmpDataset').value = d.dataset_id;
      }
      $('#cmpNote').textContent = d.note;
      $('#cmpDatasetInfo').innerHTML = d.dataset ? `Dataset: <strong>${esc(d.dataset.dataset_name)}</strong> (${esc(d.dataset.dataset_type)}, ${fmtInt(d.dataset.row_count)} rows, ${d.dataset.column_count} columns)` : '';
      const models = d.models;
      if (!models.length) {
        $('#cmpTable').innerHTML = '<div class="empty-inline">No trained models yet. Train Decision Tree, Random Forest and ANN models on the <a href="/training">Model Training</a> page.</div>';
        $('#cmpCm').innerHTML = ''; $('#cmpSelect').innerHTML = ''; $('#cmpVersions').innerHTML = '';
        Charts.bar('chCmp', [], [], { emptyMsg: 'No trained models.' }); Charts.bar('chErr', [], [], { emptyMsg: 'No trained models.' }); return;
      }
      const best = {}; METRICS.forEach(([k, , col, hi]) => { const vals = models.map((m) => m[col]); best[k] = hi ? Math.max(...vals) : Math.min(...vals); });
      $('#cmpTable').innerHTML = `<div class="table-wrap"><table><thead><tr><th>Metric</th>${models.map((m) => `<th>${esc(m.display_name)} <small>v${m.version}</small> ${m.is_active ? '<span class="badge active">active</span>' : ''}</th>`).join('')}</tr></thead><tbody>
        ${METRICS.map(([k, label, col]) => `<tr><td><strong>${label}</strong></td>${models.map((m) => `<td class="${m[col] === best[k] && models.length > 1 ? 'best' : ''}">${fmtPct(m[col], 2)}</td>`).join('')}</tr>`).join('')}
        <tr><td>ROC-AUC</td>${models.map((m) => `<td>${m.roc_auc === null ? '–' : fmtNum(m.roc_auc, 4)}</td>`).join('')}</tr>
        <tr><td>Macro F1 (both classes)</td>${models.map((m) => `<td>${m.macro ? fmtPct(m.macro.f1, 2) : '–'}</td>`).join('')}</tr>
        <tr><td>Training duration</td>${models.map((m) => `<td>${m.training_seconds.toFixed(2)} s</td>`).join('')}</tr>
        <tr><td>Prediction duration (test set)</td>${models.map((m) => `<td>${(m.prediction_seconds * 1000).toFixed(1)} ms <small>(${fmtInt(m.n_test)} records)</small></td>`).join('')}</tr>
        <tr><td>Trained</td>${models.map((m) => `<td>${fmtTime(m.created_at)}</td>`).join('')}</tr></tbody></table></div>
        <p class="sub" style="margin-top:8px">Highlighted cells = best value for each metric (${d.best_model_id ? esc(algoName((models.find((m) => m.model_id === d.best_model_id) || {}).algorithm)) : '–'} is best by the selected criterion).</p>`;
      Charts.bar('chCmp', models.map((m) => m.display_name), [
        { name: 'Accuracy', data: models.map((m) => m.accuracy), color: C.blue }, { name: 'Precision', data: models.map((m) => m.precision_score), color: C.teal },
        { name: 'Recall', data: models.map((m) => m.recall_score), color: C.violet }, { name: 'F1', data: models.map((m) => m.f1_score), color: C.warn }], { pct: true });
      Charts.bar('chErr', models.map((m) => m.display_name), [{ name: 'False positive rate', data: models.map((m) => m.fpr), color: C.warn }, { name: 'False negative rate', data: models.map((m) => m.fnr), color: C.malicious }], { pct: true });
      $('#cmpCm').innerHTML = models.map((m) => `<div><h3 style="margin-bottom:8px;font-size:14px">${esc(m.display_name)} v${m.version}</h3>${cmHtml(m.confusion_matrix)}</div>`).join('');
      $('#cmpSelect').innerHTML = `<div class="grid cols-3">${models.map((m) => `<div class="card model-card ${m.is_active ? 'selected' : ''}"><h3>${esc(m.display_name)} v${m.version} ${m.model_id === d.best_model_id ? '<span class="badge ok">best</span>' : ''}</h3>
        <span class="sub">F1 ${fmtPct(m.f1_score)} · FPR ${fmtPct(m.fpr)} · FNR ${fmtPct(m.fnr)}</span>
        ${m.is_active ? '<span class="badge active" style="align-self:flex-start">Active detection model</span>' : `<button class="btn btn-primary" data-act="${m.model_id}" data-admin>Activate for detection</button>`}</div>`).join('')}</div>`;
      $('#cmpVersions').innerHTML = d.versions.map((m) => `<tr><td>#${m.model_id}</td><td>${esc(m.display_name)}</td><td>v${m.version}</td><td class="num">${fmtPct(m.accuracy)}</td><td class="num">${fmtPct(m.f1_score)}</td><td>${fmtTime(m.created_at)}</td>
        <td>${m.is_active ? '<span class="badge active">active</span>' : ''}</td><td>${m.is_active ? '' : `<button class="btn btn-sm" data-act="${m.model_id}" data-admin>Activate</button>`}</td></tr>`).join('');
      $$('[data-act]').forEach((b) => b.addEventListener('click', async () => {
        try { await api(`/api/models/${b.dataset.act || b.dataset.act}/activate`, { method: 'POST', body: {} }); toast('Model activated for detection.', 'success'); loadComparison(); App.refreshStatusPills?.(); }
        catch (e) { toast(e.message, 'error'); }
      }));
      if (!App.isAdmin()) $$('[data-admin]').forEach((b) => { b.disabled = true; b.title = 'Administrator only'; });
    } catch (e) { toast(e.message, 'error'); }
  }

  function initComparison() {
    if (!$('#cmpTable')) return;
    $('#cmpDataset').addEventListener('change', loadComparison);
    $('#cmpMetric').addEventListener('change', loadComparison);
    loadComparison();
  }

  document.addEventListener('DOMContentLoaded', () => { initTraining(); initComparison(); });
})();
