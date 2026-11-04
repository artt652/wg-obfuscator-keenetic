'use strict';

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];

// DOM builder: never injects HTML, so values from configs and logs stay inert.
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) el.append(c.nodeType ? c : String(c));
  return el;
}

class AuthError extends Error {}

async function api(path, body) {
  const opt = { headers: { 'X-WGOP': '1' }, credentials: 'same-origin' };
  if (body !== undefined) {
    opt.method = 'POST';
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  if (r.status === 401 && path !== '/api/login') { showLogin(); throw new AuthError('auth'); }
  let data = {};
  try { data = await r.json(); } catch { /* empty */ }
  data.httpStatus = r.status;
  return data;
}

let toastTimer;
function toast(msg, bad) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast' + (bad ? ' bad' : '');
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, bad ? 6000 : 3000);
}

const fmt = {
  dur(s) {
    if (!s || s < 0) return '—';
    const d = Math.floor(s / 86400), hh = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    if (d) return `${d} д ${hh} ч`;
    if (hh) return `${hh} ч ${m} мин`;
    if (m) return `${m} мин`;
    return `${Math.floor(s)} с`;
  },
  bytes(n) {
    const u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(i && n < 10 ? 1 : 0)} ${u[i]}`;
  },
  ago(ts) {
    if (!ts) return 'не было';
    return fmt.dur(Date.now() / 1000 - ts) + ' назад';
  },
};

// ---------------------------------------------------------------- login

function showLogin() {
  stopPolling();
  $('#app').hidden = true;
  $('#login').hidden = false;
  $('#login-pw').value = '';
  setTimeout(() => $('#login-pw').focus(), 50);
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('button', e.target);
  btn.disabled = true;
  $('#login-err').textContent = '';
  try {
    const r = await api('/api/login', { password: $('#login-pw').value });
    if (r.ok) start();
    else $('#login-err').textContent = r.error || 'Ошибка входа';
  } catch (err) {
    $('#login-err').textContent = 'Нет связи с роутером';
  } finally {
    btn.disabled = false;
  }
});

$('#btn-logout').addEventListener('click', async () => {
  try { await api('/api/logout', {}); } catch { /* ignore */ }
  showLogin();
});

// ---------------------------------------------------------------- tabs

let activeTab = 'overview';
$$('.tabs button').forEach((b) => b.addEventListener('click', () => selectTab(b.dataset.tab)));

function selectTab(name) {
  activeTab = name;
  $$('.tabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === name)));
  $$('.tab').forEach((t) => { t.hidden = t.id !== 'tab-' + name; });
  if (name === 'overview') refreshStatus();
  if (name === 'log') refreshLog(true);
  if (name === 'settings' && !cfg.loaded) loadConfig();
  if (name === 'kmod') refreshKmod();
}

// ---------------------------------------------------------------- status

let lastStatus = null;

async function refreshStatus() {
  try {
    const s = await api('/api/status');
    if (!s.ok) return;
    lastStatus = s;
    renderStatus(s);
  } catch (e) {
    if (!(e instanceof AuthError)) setPill(null);
  }
}

function setPill(running) {
  const p = $('#state-pill');
  p.className = 'state' + (running == null ? '' : running ? ' on' : ' off');
  $('#state-text').textContent = running == null ? 'нет связи' : running ? 'работает' : 'остановлен';
  $('#btn-start').disabled = running === true;
  $('#btn-stop').disabled = running === false;
}

function renderStatus(s) {
  setPill(s.running);
  $('#ov-state').textContent = s.running ? 'Работает' : 'Остановлен';
  $('#ov-uptime').textContent = s.running && s.procs.length ? fmt.dur(Math.max(...s.procs.map((p) => p.uptimeSec))) : '—';
  $('#ov-version').textContent = s.version ? 'v' + s.version : '—';
  $('#ov-procs').textContent = s.procs.length ? s.procs.map((p) => p.pid).join(', ') : '—';
  $('#foot').textContent = `wg-obfuscator-panel ${s.panelVersion}`;

  const problems = [];
  if (s.configError) problems.push('Конфиг не прочитан: ' + s.configError);
  for (const e of s.configErrors || []) problems.push(e.msg);
  const banner = $('#banner');
  banner.hidden = !problems.length;
  banner.replaceChildren(...problems.map((p) => h('div', null, p)));

  const inst = $('#ov-instances');
  inst.replaceChildren(...(s.instances || []).map((i) => h('div', { class: 'card' },
    h('div', { class: 'card-head' }, h('span', { class: 'card-title' }, i.Name), h('span', { class: 'tag' }, i.Masking)),
    h('dl', { class: 'kv' },
      h('dt', null, 'Слушает'), h('dd', null, i.Listen),
      h('dt', null, 'Сервер'), h('dd', null, i.Target || '—')),
  )));
  if (!s.instances || !s.instances.length) inst.replaceChildren(h('p', { class: 'muted' }, 'Нет секций в конфиге — добавьте на вкладке «Настройки».'));

  renderWG(s.wireguard);
}

let wgOffOpen = false;

function renderWG(wg) {
  const hint = $('#wg-hint');
  const hints = [];
  if (wg.source !== 'rci' && !wg.toolsInstalled) hints.push('Для рукопожатий и трафика установите wireguard-tools: opkg install wireguard-tools.');
  if (!wg.ndmcAvailable) hints.push('ndmc не найден — смена MTU и переподключение недоступны.');
  hint.hidden = !hints.length;
  hint.textContent = hints.join(' ');

  const box = $('#ov-wg');
  if (!wg.interfaces.length) {
    box.replaceChildren(h('p', { class: 'muted' }, 'Туннели WireGuard не найдены.'));
    return;
  }
  // Keep MTU inputs that the user is editing.
  const focused = document.activeElement && document.activeElement.dataset.iface;
  if (focused) return;

  // Active tunnels (enabled, or pointing at the obfuscator) get full cards,
  // obfuscated ones first; disabled tunnels collapse into a compact list.
  const viaObf = (i) => i.peers.some((p) => p.viaObfuscator);
  const active = wg.interfaces.filter((i) => i.enabled || viaObf(i))
    .sort((a, b) => viaObf(b) - viaObf(a));
  const off = wg.interfaces.filter((i) => !(i.enabled || viaObf(i)));
  const list = active;
  const cards = list.map((i) => {
    const state = !i.enabled ? ['bad', 'выключен'] : i.connected ? ['ok', 'подключён'] : ['warn', 'нет связи'];
    const peers = i.peers.map((p) => {
      const age = p.handshakeAgo;
      const fresh = p.online || (age >= 0 && age < 180);
      const cls = fresh ? 'ok' : age >= 0 && age < 600 ? 'warn' : 'bad';
      return h('div', { class: 'peer' },
        h('div', { class: 'card-head' },
          p.description && h('span', { class: 'card-sub' }, p.description),
          h('span', { class: 'tag ' + cls }, fresh ? 'на связи' : age >= 0 ? 'нет свежего рукопожатия' : 'рукопожатия не было'),
          p.viaObfuscator && h('span', { class: 'tag accent' }, 'через обфускатор «' + p.viaObfuscator + '»'),
          !p.enabled && h('span', { class: 'tag' }, 'пир отключён')),
        h('dl', { class: 'kv' },
          h('dt', null, 'Endpoint'), h('dd', null, p.endpoint || (p.remotePort ? '—, порт ' + p.remotePort : '—')),
          p.via && [h('dt', null, 'Через'), h('dd', null, p.via)],
          h('dt', null, 'Рукопожатие'), h('dd', null, age >= 0 ? fmt.dur(age) + ' назад' : 'не было'),
          h('dt', null, 'Принято'), h('dd', null, fmt.bytes(p.rxBytes)),
          h('dt', null, 'Отправлено'), h('dd', null, fmt.bytes(p.txBytes)),
          p.keepalive && [h('dt', null, 'Keepalive'), h('dd', null, p.keepalive + ' с')]));
    });
    const ndm = i.id || '';
    const mtuId = 'mtu-' + (i.kernel || ndm);
    const title = i.description || ndm || i.kernel;
    const sub = [ndm, i.kernel].filter((x) => x && x !== title).join(' · ');
    return h('div', { class: 'card' },
      h('div', { class: 'card-head' },
        h('span', { class: 'card-title' }, title),
        sub && h('span', { class: 'card-sub mono' }, sub),
        h('span', { class: 'tag ' + state[0] }, state[1]),
        i.connected && i.uptimeSec > 0 && h('span', {
          class: 'tag',
          title: i.uptimeFrom === 'router' ? 'По данным KeeneticOS'
            : i.uptimeMin ? 'Туннель уже работал, когда панель запустилась' : 'По наблюдению панели',
        }, 'в сети ' + (i.uptimeMin ? '≥ ' : '') + fmt.dur(i.uptimeSec)),
        h('span', { class: 'tag' }, 'MTU ' + (i.mtu || '?'))),
      peers,
      ndm && wg.ndmcAvailable ? h('div', { class: 'wg-actions' },
        h('div', null, h('label', { for: mtuId }, 'MTU'),
          h('input', { id: mtuId, class: 'mtu', type: 'number', min: 1000, max: 1500, step: 10, value: i.mtu || 1380, 'data-iface': ndm })),
        h('button', { class: 'btn', onclick: () => applyMTU(ndm, $('#' + CSS.escape(mtuId)).value) }, 'Применить MTU'),
        h('button', { class: 'btn ghost', onclick: () => reconnect(ndm, title) }, 'Переподключить')) : null);
  });
  if (!active.length) cards.push(h('p', { class: 'muted' }, 'Все туннели выключены.'));
  if (off.length) {
    const det = h('details', { class: 'card off-list' },
      h('summary', null, `Выключенные туннели: ${off.length}`),
      h('ul', null, off.map((i) => h('li', null,
        h('span', { class: 'off-name' }, i.description || i.id || i.kernel),
        h('span', { class: 'card-sub mono' }, [i.id, i.kernel].filter(Boolean).join(' · ')),
        h('span', { class: 'card-sub' }, 'MTU ' + (i.mtu || '?'))))));
    det.open = wgOffOpen;
    det.addEventListener('toggle', () => { wgOffOpen = det.open; });
    cards.push(det);
  }
  box.replaceChildren(...cards);
}

async function applyMTU(iface, val) {
  const mtu = parseInt(val, 10);
  if (!(mtu >= 1000 && mtu <= 1500)) return toast('MTU: от 1000 до 1500', true);
  if (!confirm(`Установить MTU ${mtu} для ${iface} и сохранить конфигурацию роутера?`)) return;
  const r = await api('/api/mtu', { iface, mtu });
  toast(r.ok ? `MTU ${mtu} применён` : (r.error || 'Ошибка') + (r.output ? '\n' + r.output : ''), !r.ok);
  document.activeElement.blur();
  refreshStatus();
}

async function reconnect(iface, title) {
  if (!confirm(`Выключить и снова включить «${title || iface}»? Связь через туннель прервётся на несколько секунд.`)) return;
  toast('Переподключаю…');
  const r = await api('/api/reconnect', { iface });
  toast(r.ok ? `«${title || iface}» переподключён` : (r.error || 'Ошибка'), !r.ok);
  setTimeout(refreshStatus, 3000);
}

// ---------------------------------------------------------------- service

$$('[data-svc]').forEach((b) => b.addEventListener('click', async () => {
  const action = b.dataset.svc;
  if (action === 'stop' && !confirm('Остановить обфускатор? Туннель перестанет работать.')) return;
  const btns = $$('[data-svc]');
  btns.forEach((x) => { x.disabled = true; });
  const label = { start: 'Запускаю…', stop: 'Останавливаю…', restart: 'Перезапускаю…' }[action];
  $('#state-text').textContent = label;
  try {
    const r = await api('/api/service', { action });
    toast(r.ok ? { start: 'Запущен', stop: 'Остановлен', restart: 'Перезапущен' }[action]
      : (r.error || 'Ошибка') + ' — подробности на вкладке «Журнал»', !r.ok);
  } catch { /* handled */ }
  await refreshStatus();
  if (lastStatus) setPill(lastStatus.running);
}));

// ---------------------------------------------------------------- settings

const cfg = { loaded: false, instances: [], cur: 0, raw: '', mode: 'form', dirty: false, defaultLog: '/opt/var/log/wg-obfuscator.log', errors: [] };

async function loadConfig() {
  const r = await api('/api/config');
  if (!r.ok) return toast(r.error || 'Не удалось прочитать конфиг', true);
  cfg.loaded = true;
  cfg.defaultLog = r.defaultLog || cfg.defaultLog;
  cfg.instances = r.instances.length ? r.instances : [newInstance('main')];
  cfg.raw = r.raw || '';
  cfg.cur = Math.min(cfg.cur, cfg.instances.length - 1);
  cfg.dirty = false;
  cfg.errors = [];
  if (r.parseErrors && r.parseErrors.length) showMsg('В файле есть ошибки:\n' + r.parseErrors.map((e) => '• ' + e.msg).join('\n'), true);
  else hideMsg();
  $('#raw-text').value = cfg.raw;
  renderInstTabs();
  fillForm();
}

function newInstance(name) {
  return { name, sourceIf: '127.0.0.1', sourceLport: '', target: '', key: '', masking: 'STUN', verbose: 'ERROR',
    logFile: cfg.defaultLog, logTimestamps: '', maxClients: '', idleTimeout: '', inTimeout: '', maxDummy: '',
    fwmark: '', resolveInterval: '', allowClean: false, staticBindings: [], extra: [] };
}

function renderInstTabs() {
  const errNames = new Set(cfg.errors.map((e) => e.instance));
  const tabs = cfg.instances.map((inst, i) => h('button', {
    type: 'button', class: (i === cfg.cur ? 'on' : '') + (errNames.has(inst.name) ? ' has-err' : ''),
    onclick: () => { cfg.cur = i; renderInstTabs(); fillForm(); },
  }, inst.name || '(без имени)'));
  tabs.push(h('button', { type: 'button', title: 'Добавить секцию', onclick: addInstance }, '+ секция'));
  $('#inst-tabs').replaceChildren(...tabs);
  $('#btn-del-inst').hidden = cfg.instances.length < 2;
}

function addInstance() {
  let n = cfg.instances.length + 1, name;
  do { name = 'inst' + n++; } while (cfg.instances.some((i) => i.name === name));
  cfg.instances.push(newInstance(name));
  cfg.cur = cfg.instances.length - 1;
  cfg.dirty = true;
  renderInstTabs();
  fillForm();
}

$('#btn-del-inst').addEventListener('click', () => {
  const inst = cfg.instances[cfg.cur];
  if (cfg.instances.length < 2 || !confirm(`Удалить секцию «${inst.name}»? Изменение вступит в силу после сохранения.`)) return;
  cfg.instances.splice(cfg.cur, 1);
  cfg.cur = Math.max(0, cfg.cur - 1);
  cfg.dirty = true;
  renderInstTabs();
  fillForm();
});

function fillForm() {
  const inst = cfg.instances[cfg.cur];
  // No log file means no log at all: show it as "logging off".
  if (!inst.logFile) inst.verbose = 'NONE';
  for (const el of $$('[data-k]', $('#inst-form'))) {
    const k = el.dataset.k;
    if (el.type === 'checkbox') el.checked = !!inst[k];
    else if (k === 'staticBindings') el.value = (inst[k] || []).join('\n');
    else el.value = inst[k] ?? '';
  }
  markErrors();
}

$('#inst-form').addEventListener('input', (e) => {
  const el = e.target;
  if (!el.dataset.k) return;
  const inst = cfg.instances[cfg.cur];
  const k = el.dataset.k;
  if (el.type === 'checkbox') inst[k] = el.checked;
  else if (k === 'staticBindings') inst[k] = el.value.split('\n').map((s) => s.trim()).filter(Boolean);
  else inst[k] = el.value.trim();
  cfg.dirty = true;
  if (k === 'verbose') {
    if (inst.verbose === 'NONE') inst.logFile = '';
    else if (!inst.logFile) inst.logFile = cfg.defaultLog;
    $('#f-logFile').value = inst.logFile;
  }
  if (k === 'logFile') {
    if (!inst.logFile) inst.verbose = 'NONE';
    else if (inst.verbose === 'NONE') inst.verbose = 'ERROR';
    $('#f-verbose').value = inst.verbose;
  }
  if (k === 'name') renderInstTabs();
  const f = el.closest('.f');
  if (f && f.classList.contains('invalid')) { f.classList.remove('invalid'); f.querySelector('.fe')?.remove(); }
});
$('#inst-form').addEventListener('submit', (e) => e.preventDefault());

function markErrors() {
  $$('.f.invalid').forEach((f) => { f.classList.remove('invalid'); f.querySelector('.fe')?.remove(); });
  const inst = cfg.instances[cfg.cur];
  for (const e of cfg.errors) {
    if (e.instance !== inst.name) continue;
    const el = $('#f-' + e.field);
    const f = el && el.closest('.f');
    if (!f) continue;
    f.classList.add('invalid');
    f.append(h('div', { class: 'fe' }, e.msg));
    if (f.closest('details')) f.closest('details').open = true;
  }
}

$('#toggle-key').addEventListener('click', (e) => {
  const k = $('#f-key');
  k.type = k.type === 'password' ? 'text' : 'password';
  e.target.textContent = k.type === 'password' ? 'Показать' : 'Скрыть';
});

// mode switch
$('#mode-form').addEventListener('click', async () => {
  if (cfg.mode === 'form') return;
  const r = await api('/api/config/parse', { text: $('#raw-text').value });
  if (!r.ok) return toast(r.error || 'Не удалось разобрать текст', true);
  if (r.parseErrors && r.parseErrors.length) {
    showMsg('Исправьте текст перед переходом в форму:\n' + r.parseErrors.map((e) => '• ' + e.msg).join('\n'), true);
    return;
  }
  cfg.instances = r.instances.length ? r.instances : [newInstance('main')];
  cfg.cur = 0;
  setMode('form');
  renderInstTabs();
  fillForm();
});
$('#mode-raw').addEventListener('click', () => {
  if (cfg.mode === 'raw') return;
  if (cfg.dirty && !confirm('Несохранённые изменения формы не попадут в текстовый режим. Продолжить?')) return;
  $('#raw-text').value = cfg.raw;
  cfg.dirty = false;
  setMode('raw');
});
$('#raw-text').addEventListener('input', () => { cfg.dirty = true; });

function setMode(m) {
  cfg.mode = m;
  $('#mode-form').classList.toggle('on', m === 'form');
  $('#mode-raw').classList.toggle('on', m === 'raw');
  $('#form-mode').hidden = m !== 'form';
  $('#raw-mode').hidden = m !== 'raw';
  hideMsg();
}

function showMsg(text, bad, pre) {
  const m = $('#save-msg');
  m.className = 'msg ' + (bad ? 'bad' : 'ok');
  m.replaceChildren(text, pre ? h('pre', null, pre) : '');
  m.hidden = false;
}
function hideMsg() { $('#save-msg').hidden = true; }

async function save(restart) {
  const btns = [$('#btn-save'), $('#btn-save-restart')];
  btns.forEach((b) => { b.disabled = true; });
  showMsg(restart ? 'Сохраняю и перезапускаю…' : 'Сохраняю…', false);
  try {
    const r = cfg.mode === 'form'
      ? await api('/api/config', { instances: cfg.instances, restart })
      : await api('/api/config/raw', { text: $('#raw-text').value, restart });
    cfg.errors = r.fieldErrors || [];
    if (cfg.mode === 'form') { renderInstTabs(); markErrors(); }
    if (r.ok) {
      showMsg((restart ? 'Сохранено, обфускатор перезапущен.' : 'Сохранено. Изменения вступят в силу после перезапуска.') + (/endpoint|-> internal|asc/.test(r.tunnels || '') ? '\nТуннели обновлены по новым настройкам.' : ''), false, /endpoint|asc|ERROR|rejected/.test(r.tunnels || '') ? r.tunnels : '');
      cfg.loaded = false;
      const keepMode = cfg.mode, keepCur = cfg.cur;
      await loadConfig();
      cfg.cur = Math.min(keepCur, cfg.instances.length - 1);
      renderInstTabs(); fillForm();
      setMode(keepMode);
      showMsg((restart ? 'Сохранено, обфускатор перезапущен.' : 'Сохранено. Изменения вступят в силу после перезапуска.') + (/endpoint|-> internal|asc/.test(r.tunnels || '') ? '\nТуннели обновлены по новым настройкам.' : ''), false, /endpoint|asc|ERROR|rejected/.test(r.tunnels || '') ? r.tunnels : '');
    } else if (cfg.errors.length) {
      const list = cfg.errors.map((e) => `• ${e.instance ? '[' + e.instance + '] ' : ''}${e.msg}`).join('\n');
      showMsg((r.error || 'Ошибки в настройках') + ':\n' + list, true);
      const first = cfg.errors.find((e) => e.instance);
      if (cfg.mode === 'form' && first) {
        const idx = cfg.instances.findIndex((i) => i.name === first.instance);
        if (idx >= 0 && idx !== cfg.cur) { cfg.cur = idx; renderInstTabs(); fillForm(); }
      }
    } else {
      const tail = (r.log || []).join('\n');
      showMsg(r.error || 'Ошибка сохранения', true, [tail, r.output].filter(Boolean).join('\n\n'));
    }
  } catch (e) {
    if (!(e instanceof AuthError)) showMsg('Нет связи с роутером', true);
  } finally {
    btns.forEach((b) => { b.disabled = false; });
    refreshStatus();
  }
}
$('#btn-save').addEventListener('click', () => save(false));
$('#btn-save-restart').addEventListener('click', () => save(true));

// import
$('#btn-import').addEventListener('click', () => {
  $('#import-err').textContent = '';
  $('#import-text').value = '';
  $('#import-replace').checked = false;
  $('#dlg-import').showModal();
});
$('#import-do').addEventListener('click', async (e) => {
  e.preventDefault();
  const text = $('#import-text').value.trim();
  if (!text) { $('#import-err').textContent = 'Вставьте текст конфига'; return; }
  const r = await api('/api/config/parse', { text });
  if (!r.ok || !r.instances.length) {
    $('#import-err').textContent = (r.parseErrors || []).map((x) => x.msg).join('; ') || 'В тексте не найдено ни одной секции';
    return;
  }
  const prep = (src, base) => {
    const out = { ...(base || newInstance(src.name || 'main')) };
    for (const [k, v] of Object.entries(src)) {
      if (Array.isArray(v) ? v.length : (v !== '' && v !== false && v != null)) out[k] = v;
    }
    if (!src.sourceIf) out.sourceIf = (base && base.sourceIf) || '127.0.0.1';
    if (!src.logFile) out.logFile = base ? base.logFile : cfg.defaultLog;
    if (!src.verbose) out.verbose = base ? base.verbose : 'ERROR';
    if (base) out.name = base.name;
    return out;
  };
  if (cfg.mode === 'raw') setMode('form');
  if ($('#import-replace').checked || !cfg.loaded) {
    cfg.instances = r.instances.map((i) => prep(i));
    cfg.cur = 0;
  } else {
    cfg.instances[cfg.cur] = prep(r.instances[0], cfg.instances[cfg.cur]);
  }
  cfg.loaded = true;
  cfg.dirty = true;
  cfg.errors = [];
  $('#dlg-import').close();
  renderInstTabs();
  fillForm();
  showMsg('Параметры подставлены. Проверьте их и нажмите «Сохранить и перезапустить».', false);
});

// password
$('#pw-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const r = await api('/api/password', { old: $('#pw-old').value, new: $('#pw-new').value });
  $('#pw-msg').textContent = r.ok ? 'Пароль изменён, войдите заново' : (r.error || 'Ошибка');
  if (r.ok) setTimeout(showLogin, 1200);
});

// ---------------------------------------------------------------- log

async function refreshLog(scrollEnd) {
  const box = $('#log-box');
  const atEnd = scrollEnd || box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
  try {
    const r = await api('/api/log?lines=' + $('#log-lines').value);
    if (!r.ok) return;
    if (!r.enabled) {
      $('#log-path').textContent = 'Запись в файл не включена: укажите «Файл журнала» в настройках.';
      box.replaceChildren();
      return;
    }
    $('#log-path').textContent = r.path + (r.size != null ? ' · ' + fmt.bytes(r.size) : '');
    const frag = document.createDocumentFragment();
    for (const line of r.lines) {
      const m = line.match(/\]\[([EWIDT])\]/);
      frag.append(h('span', { class: m ? 'l-' + m[1] : '' }, line + '\n'));
    }
    if (!r.lines.length) frag.append(h('span', { class: 'l-D' }, 'Журнал пуст.\n'));
    box.replaceChildren(frag);
    if (atEnd) box.scrollTop = box.scrollHeight;
  } catch { /* ignore */ }
}
$('#log-lines').addEventListener('change', () => refreshLog(true));
$('#btn-log-clear').addEventListener('click', async () => {
  if (!confirm('Очистить файл журнала?')) return;
  const r = await api('/api/log/clear', {});
  toast(r.ok ? 'Журнал очищен' : (r.error || 'Ошибка'), !r.ok);
  refreshLog(true);
});

// ---------------------------------------------------------------- built-in obfuscator

let kmodLast = null;
let kmodBusy = false;

async function refreshKmod() {
  if (kmodBusy) return;
  try {
    const r = await api('/api/kmod');
    if (!r.ok) return;
    kmodLast = r.kmod;
    renderKmod(r.kmod);
  } catch { /* auth handled */ }
}

function renderKmod(k) {
  const mod = { patched: ['ok', 'с обфускатором'], stock: ['warn', 'стандартный'], none: ['bad', 'не загружен'] }[k.module] || ['', k.module];
  $('#km-module').replaceChildren(h('span', { class: 'tag ' + mod[0] }, mod[1]));
  const auto = { enabled: 'включён', disabled: 'выключен', none: 'не установлен' }[k.autostart] || '—';
  $('#km-auto').textContent = auto;
  $('#km-auto').title = k.disabledReason || '';
  $('#km-genl').textContent = k.genlId || '—';
  $('#km-kernel').textContent = k.autostart === 'none' ? '—' : k.kernelMatch ? 'совпадает' : 'другое';

  const warn = [];
  if (!k.installed) warn.push('Модуль не установлен: поставьте пакет wgobfs-kmod (github.com/artt652/keenetic-wgobfs).');
  else if (!k.fits) warn.push('В пакете wgobfs-kmod нет модуля для этой прошивки: стандартный модуль WireGuard отличается от известных сборок. Туннели в режиме «авто» работают через внешний обфускатор.');
  if (k.installed && k.fits && !k.kernelMatch && k.autostart !== 'none') warn.push('Ядро отличается от того, для которого включён автозапуск (обновление прошивки?). Подмена при загрузке пропускается; модуль может не подойти к новой прошивке.');
  if (k.autostart === 'disabled' && k.disabledReason) warn.push('Автозапуск выключен: ' + k.disabledReason);
  if (k.pending) warn.push('Идёт подмена модуля или она не завершилась.');
  if (k.error) warn.push(k.error);
  $('#km-banner').hidden = !warn.length;
  $('#km-banner').textContent = warn.join(' ');

  $('#km-swap').hidden = !(k.installed && k.fits && k.module !== 'patched');
  $('#km-auto-on').hidden = k.autostart !== 'disabled';
  $('#km-auto-off').hidden = k.autostart !== 'enabled';
  $('#km-log').textContent = k.lastLog.join('\n');
  $('#km-log-box').hidden = !k.lastLog.length;

  const box = $('#km-tunnels');
  // Do not rebuild the cards under a select the user is working with.
  if (box.contains(document.activeElement) && document.activeElement.tagName === 'SELECT') return;
  const list = k.tunnels.filter((t) => t.enabled || t.wgobfs || t.mode);
  const modeName = { auto: 'авто', internal: 'встроенный', external: 'внешний' };
  const cards = list.map((t) => {
    const title = t.description || t.id;
    const state = !t.enabled ? ['bad', 'выключен'] : t.online ? ['ok', 'на связи'] : t.connected ? ['warn', 'нет рукопожатия'] : ['warn', 'нет связи'];
    let mode;
    if (t.mode && t.effective === 'internal' && k.module !== 'patched') {
      mode = h('span', { class: 'tag warn', title: 'Режим «встроенный», но модуль с обфускатором не загружен — туннель не подключится' }, 'встроенный, но модуль стандартный');
    } else if (t.mode) {
      mode = h('span', { class: 'tag accent', title: 'Режим ' + modeName[t.mode] + ', секция «' + t.section + '»' },
        (t.effective === 'internal' ? 'встроенный обфускатор' : 'внешний обфускатор') + (t.mode === 'auto' ? ' (авто)' : ''));
    } else if (!t.wgobfs) mode = h('span', { class: 'tag' }, 'обычный WireGuard');
    else if (k.module !== 'patched') mode = h('span', { class: 'tag warn', title: 'I5 задан, но загружен стандартный модуль' }, 'I5 задан, модуль стандартный');
    else mode = h('span', { class: 'tag accent' }, `обфускатор: ${t.masking}, dummy ${t.maxDummy}` + (t.kernelMode === 'off' ? ' (в модуле выкл.)' : ''));

    let modeRow = null;
    if (k.modeTool && k.ndmcAvailable && k.sections.length) {
      const sel = kmodPick[t.id] || { mode: t.mode || '', section: t.section || t.suggested || k.sections[0].name };
      const mSel = h('select', { 'aria-label': 'Режим', onchange: (e) => { sel.mode = e.target.value; kmodPick[t.id] = sel; } },
        [['', 'не управлять'], ['auto', 'авто'], ['internal', 'встроенный'], ['external', 'внешний']]
          .map(([v, l]) => h('option', { value: v, selected: v === sel.mode }, l)));
      const sSel = h('select', { 'aria-label': 'Секция обфускатора', onchange: (e) => { sel.section = e.target.value; kmodPick[t.id] = sel; } },
        k.sections.map((s) => h('option', { value: s.name, selected: s.name === sel.section }, `${s.name} (:${s.port} → ${s.target})`)));
      modeRow = h('div', { class: 'wg-actions mode-row' },
        h('div', null, h('label', null, 'Режим'), mSel),
        h('div', { class: 'grow' }, h('label', null, 'Секция обфускатора'), sSel),
        h('button', { class: 'btn primary', onclick: () => setTunnelMode(t, sel) }, 'Применить'));
    }
    return h('div', { class: 'card' },
      h('div', { class: 'card-head' },
        h('span', { class: 'card-title' }, title),
        h('span', { class: 'card-sub mono' }, [t.id, t.kernel].filter((x) => x && x !== title).join(' · ')),
        h('span', { class: 'tag ' + state[0] }, state[1]), mode),
      h('dl', { class: 'kv' },
        h('dt', null, 'Endpoint'), h('dd', null, t.endpoint || '—'),
        h('dt', null, 'Рукопожатие'), h('dd', null, t.handshakeAgo >= 0 ? fmt.dur(t.handshakeAgo) + ' назад' : 'не было'),
        h('dt', null, 'Принято / отправлено'), h('dd', null, fmt.bytes(t.rxBytes) + ' / ' + fmt.bytes(t.txBytes))),
      modeRow,
      k.ndmcAvailable && !t.mode ? h('div', { class: 'wg-actions' },
        h('button', { class: 'btn', onclick: () => openKmodDialog(t) }, t.wgobfs ? 'Изменить вручную' : 'Включить вручную'),
        t.wgobfs && h('button', { class: 'btn ghost danger', onclick: () => disableKmod(t) }, 'Выключить')) : null);
  });
  if (!cards.length) cards.push(h('p', { class: 'muted' }, 'Включённых туннелей WireGuard нет.'));
  if (k.modeTool && !k.sections.length) cards.unshift(h('p', { class: 'muted small' }, 'Режимы «авто / встроенный / внешний» берут ключ и сервер из секции локального обфускатора — добавьте её на вкладке «Настройки».'));
  box.replaceChildren(...cards);
}

const kmodPick = {};

async function setTunnelMode(t, sel) {
  const title = t.description || t.id;
  const what = { '': 'перестать управлять режимом', auto: 'включить режим «авто»', internal: 'включить встроенный обфускатор', external: 'перейти на внешний обфускатор' }[sel.mode];
  const r = await kmodAction('/api/kmod/mode', { iface: t.id, mode: sel.mode || 'off', section: sel.section },
    `«${title}»: готово`, `«${title}»: ${what}? Связь через туннель может прерваться на несколько секунд.`);
  if (r) {
    delete kmodPick[t.id];
    if (!r.ok && r.output) $('#km-log').textContent = r.output;
  }
}

async function kmodAction(path, body, okMsg, confirmMsg) {
  if (confirmMsg && !confirm(confirmMsg)) return null;
  kmodBusy = true;
  toast('Выполняю…');
  try {
    const r = await api(path, body);
    toast(r.ok ? okMsg : (r.error || 'Ошибка'), !r.ok);
    return r;
  } finally {
    kmodBusy = false;
    setTimeout(refreshKmod, 1500);
  }
}

$('#km-swap').addEventListener('click', () => kmodAction('/api/kmod/swap', {}, 'Модуль загружен',
  'Заменить модуль WireGuard сейчас? Все туннели WireGuard прервутся на несколько секунд.'));
$('#km-auto-on').addEventListener('click', () => kmodAction('/api/kmod/autostart', { enable: true }, 'Автозапуск включён'));
$('#km-auto-off').addEventListener('click', () => kmodAction('/api/kmod/autostart', { enable: false }, 'Автозапуск выключен'));

async function disableKmod(t) {
  const ep = prompt(`Выключить встроенный обфускатор на «${t.description || t.id}»?\n\nЕсли туннель должен снова идти через локальный обфускатор, укажите его endpoint (например 127.0.0.1:13255). Пусто — endpoint не менять.`, '');
  if (ep === null) return;
  await kmodAction('/api/kmod/disable', { iface: t.id, endpoint: ep.trim() }, 'Обфускатор выключен');
}

let kmodTarget = null;
function openKmodDialog(t) {
  kmodTarget = t;
  $('#km-dlg-title').textContent = 'Встроенный обфускатор: ' + (t.description || t.id);
  $('#km-key').value = t.key || '';
  $('#km-key').type = 'password';
  $('#km-key-show').textContent = 'Показать';
  $('#km-masking').value = t.masking || 'STUN';
  $('#km-dummy').value = t.wgobfs ? t.maxDummy : 4;
  const ep = t.endpoint || '';
  $('#km-endpoint').value = /^127\.|^localhost/.test(ep) ? '' : (t.wgobfs ? ep : '');
  $('#km-dlg-err').textContent = '';
  $('#km-dlg-out').hidden = true;
  $('#dlg-kmod').showModal();
}

$('#km-key-show').addEventListener('click', () => {
  const k = $('#km-key');
  k.type = k.type === 'password' ? 'text' : 'password';
  $('#km-key-show').textContent = k.type === 'password' ? 'Показать' : 'Скрыть';
});

$('#km-from-obf').addEventListener('click', async () => {
  const r = await api('/api/config');
  const list = (r.ok && r.instances) || [];
  if (!list.length) return toast('В настройках обфускатора нет секций', true);
  // Prefer the section whose local port is this tunnel's current endpoint port.
  const port = kmodTarget && kmodTarget.endpoint ? kmodTarget.endpoint.split(':').pop() : '';
  const inst = list.find((i) => i.sourceLport === port) || list[0];
  $('#km-key').value = inst.key || '';
  const m = (inst.masking || '').toUpperCase();
  $('#km-masking').value = m === 'NONE' || m === 'AUTO' || !m ? 'NONE' : 'STUN';
  if (inst.maxDummy) $('#km-dummy').value = inst.maxDummy;
  $('#km-endpoint').value = inst.target || '';
  toast('Взято из секции «' + inst.name + '»');
});

$('#km-apply').addEventListener('click', async (e) => {
  e.preventDefault();
  const body = {
    iface: kmodTarget.id,
    key: $('#km-key').value,
    masking: $('#km-masking').value,
    maxDummy: parseInt($('#km-dummy').value, 10) || 0,
    endpoint: $('#km-endpoint').value.trim(),
  };
  const btn = $('#km-apply');
  btn.disabled = true;
  $('#km-dlg-err').textContent = '';
  kmodBusy = true;
  try {
    const r = await api('/api/kmod/enable', body);
    if (r.ok) {
      $('#dlg-kmod').close();
      toast('Обфускатор включён на «' + (kmodTarget.description || kmodTarget.id) + '»');
    } else {
      $('#km-dlg-err').textContent = r.error || 'Ошибка';
      if (r.output) { $('#km-dlg-out').textContent = r.output; $('#km-dlg-out').hidden = false; }
    }
  } finally {
    btn.disabled = false;
    kmodBusy = false;
    setTimeout(refreshKmod, 2000);
  }
});

$('#km-conv-do').addEventListener('click', async () => {
  $('#km-conv-msg').textContent = '';
  const r = await api('/api/kmod/convert', { text: $('#km-conv-in').value });
  if (!r.ok) { $('#km-conv-out').hidden = true; $('#km-conv-msg').textContent = r.error || 'Ошибка'; return; }
  const res = r.result;
  $('#km-conv-text').value = res.conf;
  $('#km-conv-out').hidden = false;
  if (res.name && res.name !== 'main') $('#km-conv-name').value = res.name.replace(/[^\w.-]+/g, '_') + '.conf';
  $('#km-conv-msg').textContent = `Сервер ${res.endpoint}, маскировка ${res.masking}, dummy ${res.maxDummy}` + ((res.notes || []).length ? ' · ' + res.notes.join(' · ') : '');
});

$('#km-conv-dl').addEventListener('click', () => {
  const blob = new Blob([$('#km-conv-text').value], { type: 'text/plain' });
  const a = h('a', { href: URL.createObjectURL(blob), download: $('#km-conv-name').value || 'wgobfs.conf' });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
});

$('#km-conv-copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('#km-conv-text').value); toast('Скопировано'); }
  catch { $('#km-conv-text').select(); document.execCommand('copy'); toast('Скопировано'); }
});

// ---------------------------------------------------------------- polling

let timer = null;
function stopPolling() { clearInterval(timer); timer = null; }
function startPolling() {
  stopPolling();
  let tick = 0;
  timer = setInterval(() => {
    if (document.hidden) return;
    tick++;
    if (activeTab === 'overview' && tick % 2 === 0) refreshStatus();
    if (activeTab === 'log' && $('#log-follow').checked) refreshLog(false);
    if (activeTab === 'settings' && tick % 5 === 0) refreshStatus();
    if (activeTab === 'kmod' && tick % 3 === 0 && !$('#dlg-kmod').open) refreshKmod();
  }, 3000);
}

window.addEventListener('beforeunload', (e) => {
  if (cfg.dirty) { e.preventDefault(); e.returnValue = ''; }
});

async function start() {
  $('#login').hidden = true;
  $('#app').hidden = false;
  await refreshStatus();
  selectTab(activeTab);
  startPolling();
}

(async () => {
  try {
    const s = await api('/api/status');
    if (s.ok) { lastStatus = s; start(); }
  } catch { /* showLogin already called on 401 */ }
})();
