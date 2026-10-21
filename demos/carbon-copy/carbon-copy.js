'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const names = ['nonce-replaced', 'expiry-extended'];
  const stages = ['Signed', 'Copied', 'Mutated', 'Decided'];
  const preference = matchMedia('(prefers-reduced-motion: reduce)');
  const controls = [...document.querySelectorAll('button, input')];
  let report = null, index = 0, step = 0, timer = null, playing = false, visible = false;
  const ns = 'http://www.w3.org/2000/svg';

  function shape(tag, attributes) {
    const element = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
    return element;
  }
  function seal(target, nonce) {
    const svg = shape('svg', {viewBox: '0 0 240 240', 'data-nonce': nonce});
    svg.append(shape('circle', {cx: 120, cy: 120, r: 100, class: 'outer-ring'}),
      shape('circle', {cx: 120, cy: 120, r: 77, class: 'outer-ring'}),
      shape('circle', {cx: 120, cy: 120, r: 26, class: 'core'}));
    const bytes = nonce.match(/../g).map(value => parseInt(value, 16));
    bytes.forEach((value, position) => {
      const angle = position / bytes.length * Math.PI * 2 - Math.PI / 2;
      const radius = 48 + value / 255 * 40;
      const x = 120 + Math.cos(angle) * radius, y = 120 + Math.sin(angle) * radius;
      const outerX = 120 + Math.cos(angle) * 100, outerY = 120 + Math.sin(angle) * 100;
      svg.append(shape('path', {d: `M120 120L${x} ${y}L${outerX} ${outerY}`, class: 'filament'}),
        shape('circle', {cx: x, cy: y, r: 2 + (value % 7), class: 'cell'}));
    });
    target.replaceChildren(svg);
  }
  function stop(note) {
    playing = false; clearTimeout(timer); timer = null;
    document.body.dataset.playing = 'false';
    $('play').setAttribute('aria-pressed', 'false');
    $('play').textContent = step === 3 ? 'Replay trace' : 'Play trace';
    if (note) $('motion-note').textContent = note;
  }
  function schedule() {
    clearTimeout(timer);
    if (!playing || !visible || document.hidden || preference.matches) return stop();
    timer = setTimeout(() => {
      step = Math.min(3, step + 1); render();
      if (step === 3) stop('Playback complete. The final record remains visible.');
      else schedule();
    }, 1900);
  }
  function render() {
    const current = report.cases[index], changed = step >= 2;
    const caller = changed ? current.caller_after : current.signed_fields, signed = current.signed_fields;
    document.body.dataset.step = String(step); document.body.dataset.mutated = String(changed);
    document.querySelectorAll('[data-case]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.case === current.name)));
    document.querySelectorAll('[data-stage]').forEach(item => {
      const active = Number(item.dataset.stage) === step;
      item.classList.toggle('current', active);
      if (active) item.setAttribute('aria-current', 'step'); else item.removeAttribute('aria-current');
    });
    $('scrub').value = String(step); $('scrub').setAttribute('aria-valuetext', stages[step]);
    $('position').textContent = `0${step + 1} / 04`;
    $('step-label').textContent = `STEP 0${step + 1} / ${stages[step].toUpperCase()}`;
    $('caller-state').textContent = changed ? 'CHANGED' : 'ORIGINAL';
    $('snapshot-state').textContent = step > 0 ? 'PRIVATE COPY' : 'NOT COPIED';
    $('caller-nonce').textContent = caller.nonce; $('caller-expiry').textContent = String(caller.expires_at);
    $('caller-nonce').classList.toggle('changed', caller.nonce !== signed.nonce);
    $('caller-expiry').classList.toggle('changed', caller.expires_at !== signed.expires_at);
    $('snapshot-nonce').textContent = step > 0 ? signed.nonce : '—';
    $('snapshot-expiry').textContent = step > 0 ? String(signed.expires_at) : '—';
    $('caller').textContent = JSON.stringify(caller, null, 2);
    $('snapshot').textContent = step > 0 ? JSON.stringify(signed, null, 2) : 'Snapshot not taken yet.';
    seal($('caller-seal'), caller.nonce); seal($('snapshot-seal'), signed.nonce);
    $('result').textContent = step === 3 ? current.decision.reason.toUpperCase() : ['SIGNED VALUES', 'PRIVATE COPY CREATED', 'CALLER OBJECT CHANGED'][step];
    $('explanation').textContent = step === 3
      ? (current.name === 'nonce-replaced' ? 'The ledger consumed the signed nonce. The replacement stayed in caller memory.' : 'The signed expiry still controls the decision. The extended caller value cannot keep the grant alive.')
      : step === 2 ? (current.name === 'nonce-replaced' ? 'The clock callback replaced the original nonce. The two shapes now diverge; the checked copy keeps its initial nonce.' : 'The callback extended expires_at. The nonce shapes stay equal, but the expiry fields diverge.')
      : step === 1 ? 'The verifier owns a bounded private tree. Later signature, binding and ledger checks use this copy.'
      : 'The initial nonce and expiry are part of the signed grant. The caller still holds the original dictionary.';
    $('ledger').textContent = step === 3 ? (current.ledger_nonces.join(', ') || '∅ / no nonce consumed') : 'Not reached';
    $('clock-readout').textContent = step >= 2 ? `Callback now: ${current.callbacks[0].now}${step === 3 ? ` · ${current.callbacks.length} recorded call${current.callbacks.length === 1 ? '' : 's'}` : ''}` : 'Clock callback not reached';
    $('record').textContent = JSON.stringify({case: current, source_sha256: report.source_sha256, baseline: report.baseline}, null, 2);
    $('back').disabled = step === 0; $('step').disabled = step === 3; $('play').disabled = preference.matches;
    $('play').textContent = playing ? 'Pause trace' : step === 3 ? 'Replay trace' : 'Play trace';
  }
  function move(next) {
    stop(preference.matches ? 'Reduced motion: manual steps remain available.' : 'Paused on a recorded step.');
    step = Math.max(0, Math.min(3, next)); render();
  }
  document.querySelectorAll('[data-case]').forEach(button => button.addEventListener('click', () => {
    if (!report) return; index = report.cases.findIndex(item => item.name === button.dataset.case); move(0);
  }));
  $('step').addEventListener('click', () => move(step + 1));
  $('back').addEventListener('click', () => move(step - 1));
  $('scrub').addEventListener('input', event => move(Number(event.target.value)));
  $('play').addEventListener('click', () => {
    if (!report || preference.matches) return;
    if (playing) return stop('Paused. Manual controls keep the current recorded state.');
    if (step === 3) step = 0;
    playing = true; document.body.dataset.playing = 'true'; $('play').setAttribute('aria-pressed', 'true');
    $('motion-note').textContent = 'Playing four recorded states. No signing or tool execution occurs.';
    render(); schedule();
  });
  document.addEventListener('visibilitychange', () => { if (document.hidden) stop('Paused while this page is hidden.'); });
  window.addEventListener('pagehide', () => stop());
  preference.addEventListener('change', () => {
    stop(preference.matches ? 'Reduced motion: manual steps remain available.' : 'Motion preference changed. Playback stays paused.');
    if (report) render();
  });
  new IntersectionObserver(entries => {
    visible = entries.some(entry => entry.isIntersecting);
    if (!visible) stop('Paused while the experiment is offscreen.');
  }, {threshold: 0.01}).observe($('experiment'));
  function validRecord(data) {
    if (data?.schema_version !== 1 || data.passed !== true || !Array.isArray(data.cases) || data.cases.length !== 2) return false;
    if (new Set(data.cases.map(item => item?.name)).size !== 2) return false;
    return data.cases.every(item => names.includes(item?.name) && item.passed === true &&
      [item.signed_fields, item.caller_after].every(fields => /^[0-9a-f]{32}$/.test(fields?.nonce) && Number.isSafeInteger(fields?.expires_at)) &&
      Array.isArray(item.callbacks) && item.callbacks.length > 0 && Number.isSafeInteger(item.callbacks[0]?.now) &&
      Array.isArray(item.ledger_nonces) && item.ledger_nonces.every(value => /^[0-9a-f]{32}$/.test(value)) &&
      item.decision && typeof item.decision.allowed === 'boolean' && typeof item.decision.reason === 'string');
  }
  fetch('../../snapshot-report.json').then(response => {
    if (!response.ok) throw Error('Record unavailable'); return response.text();
  }).then(raw => {
    if (raw.length > 131072) throw Error('Record too large');
    const data = JSON.parse(raw); if (!validRecord(data)) throw Error('Invalid record'); report = data;
    controls.forEach(control => control.disabled = false);
    $('status').textContent = `2 LOCAL REGRESSIONS / ${data.recorded_at}`;
    if (preference.matches) $('motion-note').textContent = 'Reduced motion: manual steps remain available.';
    render();
  }).catch(() => {
    controls.forEach(control => control.disabled = true); stop();
    $('status').textContent = 'Record unavailable. Serve this repository over HTTP and verify snapshot-report.json.';
  });
})();
