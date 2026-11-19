const {appChannel: channel, appHostOrigin: origin} = document.documentElement.dataset;
const element = id => document.getElementById(id);
let page = 1;
let sequence = 0;
let pending;
let timer;

function showStatus(message) {
  element('status').textContent = message;
  element('keys').replaceChildren();
  element('pages').hidden = true;
}

function load(requested) {
  clearTimeout(timer);
  showStatus('Loading wallet…');
  if (!channel || !origin) {
    showStatus('Open Chain Wallet in OmegaHive to view public keys.');
    return;
  }
  pending = 'wallet-' + (++sequence);
  parent.postMessage({type: 'app-request', channel, id: pending, op: 'view',
    body: {focus: 'page-' + requested, stage: 'unfold'}}, origin);
  timer = setTimeout(() => {
    showStatus('Still waiting for the host. You can refresh to try again.');
  }, 16000);
}

window.addEventListener('message', event => {
  const msg = event.data;
  if (!channel || event.source !== parent || event.origin !== origin || msg?.channel !== channel) return;
  if (msg.type === 'app-context') { load(page); return; }
  if (msg.type !== 'app-reply' || !pending || msg.id !== pending) return;
  pending = null;
  clearTimeout(timer);
  const items = msg.result?.items ?? [];
  const wallet = items.find(item => item.kind === 'wallet');
  if (!msg.ok || !Number.isInteger(wallet?.count)) {
    showStatus('The host could not read the public key list.');
    return;
  }
  page = wallet.page;
  showStatus(wallet.count ? wallet.count + (wallet.count === 1 ? ' public key' : ' public keys') : 'No public keys yet.');
  for (const item of items) {
    if (item.kind !== 'public-key' || !/^04[0-9a-f]{128}$/.test(item.public_key)) continue;
    const row = document.createElement('li');
    const key = document.createElement('code');
    key.textContent = item.public_key;
    row.append(key);
    element('keys').append(row);
  }
  element('pages').hidden = wallet.pages === 1;
  element('page').textContent = 'Page ' + page + ' of ' + wallet.pages;
  element('prev').disabled = page === 1;
  element('next').disabled = page >= wallet.pages;
});

element('refresh').onclick = () => load(page);
element('prev').onclick = () => load(page - 1);
element('next').onclick = () => load(page + 1);
if (channel && origin) parent.postMessage({type: 'app-ready', channel}, origin);
else load(1);
