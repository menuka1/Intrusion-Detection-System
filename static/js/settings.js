/* Settings page + profile page (change password). */
(() => {
  const { api, esc, $, $$, fmtTime, toast, algoName } = App;

  async function initSettings() {
    const form = $('#setForm'); if (!form) return;
    try {
      const [s, ds] = await Promise.all([api('/api/settings'), api('/api/datasets')]);
      $('#setDataset').innerHTML = '<option value="">None</option>' + ds.map((d) => `<option value="${d.dataset_id}">${esc(d.dataset_name)}</option>`).join('');
      Object.entries(s.settings).forEach(([k, v]) => { if (form[k]) form[k].value = v; });
      const m = s.active_model;
      $('#setModel').innerHTML = m ? `<strong>${esc(algoName(m.algorithm))} v${m.version}</strong> · trained on ${esc(m.dataset_name || 'deleted dataset')}` : '<span class="badge warn">No active model</span>';
      const sys = s.system, app = s.application;
      $('#setSys').innerHTML = [['Database', `${sys.database.label} (${sys.database.backend})`], ['ML engine', sys.ml_engine.label], ['Dataset processing', sys.dataset_processing.label],
        ['Traffic replay', sys.replay.running ? 'Running (simulated)' : 'Not running'], ['Health', sys.health], ['Environment', app.environment], ['Max upload', app.max_upload_mb + ' MB'],
        ['Allowed uploads', app.allowed_extensions.join(', ')], ['Session lifetime', app.session_hours + ' h']].map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('');
    } catch (e) { toast(e.message, 'error'); }
    if (!App.isAdmin()) { $$('input,select', form).forEach((i) => (i.disabled = true)); $$('[data-admin]').forEach((b) => (b.disabled = true)); }
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const body = {}; new FormData(form).forEach((v, k) => { body[k] = v; });
      try { await api('/api/settings', { method: 'PUT', body }); toast('Settings saved.', 'success'); } catch (err) { toast(err.message, 'error'); }
    });
  }

  function initProfile() {
    const form = $('#pwForm'); if (!form) return;
    $$('[data-time]').forEach((el) => { if (el.dataset.time) el.textContent = fmtTime(el.dataset.time); });
    form.addEventListener('submit', async (e) => {
      e.preventDefault(); const err = $('#pwErr'); err.hidden = true;
      if (form.new_password.value !== form.confirm.value) { err.textContent = 'The new passwords do not match.'; err.hidden = false; return; }
      try {
        await api('/api/auth/change-password', { method: 'POST', body: { current_password: form.current_password.value, new_password: form.new_password.value } });
        toast('Password updated.', 'success'); form.reset();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    });
  }
  document.addEventListener('DOMContentLoaded', () => { initSettings(); initProfile(); });
})();
