const {appChannel: channel, appHostOrigin: origin} = document.documentElement.dataset;
const el = id => document.getElementById(id);
let sequence = 0;
let pending;
let page = 1;
let revision;
let recipient;
let mode;
let target;
let opener;
let busy = false;
// Each host context owns its requests, editor and encryption recipient.
let contextVersion = 0;

function request(op, body) {
  return new Promise((resolve, reject) => {
    const id = 'wallet-' + (++sequence);
    const timer = setTimeout(() => {
      pending = null;
      reject(new Error('The host did not reply. Refresh to check the wallet.'));
    }, 20000);
    pending = {id, resolve, reject, timer};
    parent.postMessage({type: 'app-request', channel, id, op, body}, origin);
  });
}

function setBusy(value) {
  busy = value;
  for (const button of document.querySelectorAll('button, input')) button.disabled = value;
  el('prev').disabled = value || page <= 1;
  el('next').disabled = value || page >= Number(el('pages').dataset.total);
  el('import').disabled = value || !globalThis.crypto?.subtle;
  if (!globalThis.crypto?.subtle) el('import').title = 'Use HTTPS or localhost to encrypt a key for import.';
}

function closeEditor() {
  el('secret').value = '';
  el('name').value = '';
  el('selected').textContent = '';
  target = null;
  el('feedback').textContent = '';
  el('editor').hidden = true;
  mode = null;
  if (opener?.isConnected) opener.focus();
}

function edit(action, source, item) {
  if (busy) return;
  opener = source;
  mode = action;
  target = item?.public_key;
  const title = {generate: 'Generate key', import: 'Import key', rename: 'Rename signer'}[mode];
  el('editor-title').textContent = title;
  el('save').textContent = mode === 'rename' ? 'Save name' : title;
  el('selected').hidden = !target;
  el('selected').textContent = target || '';
  el('name').value = item?.name || '';
  el('secret').value = '';
  el('import-fields').hidden = mode !== 'import';
  el('feedback').textContent = '';
  el('notice').textContent = '';
  el('editor').hidden = false;
  el(mode === 'import' ? 'secret' : 'name').focus();
}

function render(graph) {
  const items = graph?.items || [];
  const wallet = items.find(item => item.kind === 'wallet');
  if (!Number.isInteger(wallet?.count)) throw new Error(wallet?.summary || 'The host could not read the wallet.');
  page = wallet.page;
  revision = graph.revision;
  recipient = wallet.import_recipient;
  el('actions').hidden = !recipient;
  el('keys').replaceChildren();
  for (const item of items) {
    if (item.kind !== 'public-key' || !/^04[0-9a-f]{128}$/.test(item.public_key)) continue;
    const row = document.createElement('li');
    const head = document.createElement('div');
    head.className = 'row-head';
    const name = document.createElement('strong');
    name.textContent = item.name || 'Unnamed signer';
    name.dir = 'auto';
    head.append(name);
    if (recipient) {
      const rename = document.createElement('button');
      rename.type = 'button';
      rename.textContent = 'Rename';
      rename.onclick = () => edit('rename', rename, item);
      head.append(rename);
    }
    const key = document.createElement('code');
    key.textContent = item.public_key;
    row.append(head, key);
    el('keys').append(row);
  }
  el('count').textContent = String(wallet.count);
  el('status').textContent = wallet.count ? '' : 'No signers yet.';
  el('pages').hidden = wallet.pages <= 1;
  el('pages').dataset.total = wallet.pages;
  el('page').textContent = 'Page ' + page + ' of ' + wallet.pages;
}

function clearView() {
  el('keys').replaceChildren();
  el('actions').hidden = el('pages').hidden = true;
  el('count').textContent = '';
  revision = recipient = null;
}

async function load(focus) {
  const version = contextVersion;
  closeEditor();
  setBusy(true);
  try {
    const graph = await request('view', {focus, stage: 'unfold'});
    if (version === contextVersion) render(graph);
  } catch (error) {
    if (version !== contextVersion) return;
    clearView();
    el('status').textContent = error.message;
  } finally {
    if (version === contextVersion) setBusy(false);
  }
}

async function seal(value) {
  const secret = Uint8Array.from(value.match(/../g), pair => parseInt(pair, 16));
  try {
    const der = Uint8Array.from(atob(recipient), char => char.charCodeAt(0));
    const key = await crypto.subtle.importKey('spki', der, {name: 'RSA-OAEP', hash: 'SHA-256'}, false, ['encrypt']);
    const encrypted = await crypto.subtle.encrypt({name: 'RSA-OAEP'}, key, secret);
    return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
  } finally {
    secret.fill(0);
  }
}

async function save() {
  if (busy || !mode || !revision) return;
  const version = contextVersion;
  const action = mode;
  const params = {name: el('name').value.trim()};
  el('feedback').textContent = '';
  if (Array.from(params.name).length > 80) {
    el('feedback').textContent = 'Use a name of up to 80 characters.';
    return;
  }
  setBusy(true);
  try {
    if (action === 'import') {
      if (!/^[0-9a-fA-F]{64}$/.test(el('secret').value)) {
        el('feedback').textContent = 'Enter exactly 64 hexadecimal digits.';
        return;
      }
      const envelope = seal(el('secret').value);
      el('secret').value = '';
      try {
        params.envelope = await envelope;
      } catch {
        throw new Error('Could not encrypt this key. Open Hive over HTTPS or localhost and refresh.');
      }
    }
    if (version !== contextVersion) return;
    const result = await request('act', {action, items: target ? [target] : [], params, base_revision: revision});
    if (version !== contextVersion) return;
    if (result?.status !== 'done') {
      if (result?.status === 'stale') {
        el('notice').textContent = 'The wallet changed. Review the current list and try again.';
        await load('page-' + page);
        return;
      }
      throw new Error(result?.message || 'The host could not complete the action.');
    }
    const importNotice = {
      imported: 'Key imported.',
      present: 'This key is already in the wallet.',
      renamed: 'This key was already in the wallet. Its name was updated.',
    };
    el('notice').textContent = {
      generate: 'Key generated.',
      import: importNotice[result.detail.import_outcome] || 'Key imported.',
      rename: 'Signer name saved.',
    }[action];
    await load(result.detail.public_key);
  } catch (error) {
    if (version === contextVersion) el('feedback').textContent = error.message;
  } finally {
    if (version === contextVersion) setBusy(false);
  }
}

window.addEventListener('message', event => {
  const msg = event.data;
  if (!channel || event.source !== parent || event.origin !== origin || msg?.channel !== channel) return;
  if (msg.type === 'app-context') {
    contextVersion++;
    if (pending) {
      clearTimeout(pending.timer);
      pending.reject(new Error('The Hive context changed.'));
      pending = null;
    }
    clearView();
    el('notice').textContent = '';
    el('status').textContent = 'Loading wallet…';
    load('page-1');
    return;
  }
  if (msg.type !== 'app-reply' || !pending || msg.id !== pending.id) return;
  const call = pending;
  pending = null;
  clearTimeout(call.timer);
  if (msg.ok) call.resolve(msg.result);
  else call.reject(new Error('The host could not complete the request. Refresh to check the wallet.'));
});

el('refresh').onclick = () => { el('notice').textContent = ''; load('page-' + page); };
el('prev').onclick = () => load('page-' + (page - 1));
el('next').onclick = () => load('page-' + (page + 1));
for (const action of ['generate', 'import']) el(action).onclick = () => edit(action, el(action));
el('save').onclick = save;
el('cancel').onclick = closeEditor;
el('editor').onkeydown = event => {
  if (busy || event.isComposing || event.keyCode === 229) return;
  if (event.key === 'Escape') closeEditor();
  if (event.key === 'Enter' && event.target.matches('input')) save();
};

if (channel && origin) parent.postMessage({type: 'app-ready', channel}, origin);
else {
  el('refresh').disabled = true;
  el('status').textContent = 'Open Chain Wallet in OmegaHive to view signers.';
}
