const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const localHost = location.hostname === 'localhost' || location.hostname === '127.0.0.1';

function isWrongLocalAppUrl() {
  const port = location.port || (location.protocol === 'https:' ? '443' : '80');
  return localHost && port !== '3000';
}

function formatRequestError(error, fallbackMessage) {
  if (error?.name === 'AbortError') return 'The request was cancelled.';
  if (error instanceof TypeError || error?.message === 'Failed to fetch') {
    return localHost
      ? 'The app server could not be reached. Run "start-xampp.bat" and open http://localhost:3000.'
      : 'The server could not be reached. Check that the app is running.';
  }
  return error?.message || fallbackMessage;
}

if (isWrongLocalAppUrl()) {
  location.replace(`${location.protocol}//${location.hostname}:3000/`);
}

const MAX_BYTES = 25 * 1024 * 1024;
const demoFiles = [
  { name: 'invoice_oct.pdf', size: 1468006, type: 'PDF', verdict: 'clean', time: '8 min ago' },
  { name: 'project-brief.docx', size: 862208, type: 'DOC', verdict: 'clean', time: 'Yesterday' },
  { name: 'holiday_photos.zip', size: 8598323, type: 'ZIP', verdict: 'warning', time: 'Oct 04, 2026' },
  { name: 'design-assets.fig', size: 4928307, type: 'FIG', verdict: 'clean', time: 'Oct 03, 2026' }
];

let selectedFile = null;
let currentUser = null;
let scannerConfigured = false;
let scannerProvider = null;
let scanTimer = null;
let scanProgressValue = 0;
let scanActive = false;
let abortController = null;
let tipIndex = 0;
let history = [...demoFiles];

async function readApiResponse(response) {
  const body = await response.text();
  try {
    return JSON.parse(body);
  } catch {
    if (localHost && location.port !== '3000') {
      throw new Error('This page was opened through XAMPP Apache. Run "start-xampp.bat" and use http://localhost:3000.');
    }
    throw new Error(`The app server returned an invalid response (HTTP ${response.status}). Run "start-xampp.bat" and open http://localhost:3000.`);
  }
}

const tips = [
  { title: 'A small habit<br /><em>goes a long way.</em>', text: 'Scan files you weren’t expecting before opening them, especially attachments from unknown senders.' },
  { title: 'Slow down<br /><em>on urgency.</em>', text: 'If a message pressures you to open a file immediately, verify the sender through a second channel first.' },
  { title: 'Keep your<br /><em>guardrails fresh.</em>', text: 'Use current software and operating system updates so known weaknesses are patched before they are used.' }
];

function formatBytes(bytes) {
  if (!bytes) return '0 KB';
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function updateCurrentDate() {
  const now = new Date();
  const dateLabel = $('#currentDate');
  dateLabel.dateTime = now.toISOString().slice(0, 10);
  dateLabel.textContent = new Intl.DateTimeFormat(undefined, {
    weekday: 'long',
    month: 'long',
    day: 'numeric',
    year: 'numeric'
  }).format(now);
}

function getType(name) { return (name.split('.').pop()?.toUpperCase() || 'FILE').slice(0, 4); }

function relativeTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const minutes = Math.max(0, Math.round((Date.now() - date.getTime()) / 60000));
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes} min ago`;
  if (minutes < 1440) return `${Math.round(minutes / 60)} hr ago`;
  return date.toLocaleDateString(undefined, { month: 'short', day: '2-digit', year: 'numeric' });
}

function showToast(message) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.classList.add('show');
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove('show'), 3200);
}

function setAuthDialogMode(mode) {
  const signingUp = mode === 'signup';
  $('#authMode').value = mode;
  $('#loginDialogTitle').textContent = signingUp ? 'Create your account' : 'Welcome back';
  $('#authSubmitButton').textContent = signingUp ? 'Create account' : 'Sign in';
  $('#authNameField').hidden = !signingUp;
  $('#authName').required = signingUp;
  $('#authName').autocomplete = signingUp ? 'name' : 'off';
  $('#authPassword').autocomplete = signingUp ? 'new-password' : 'current-password';
  $('#authModePrompt').textContent = signingUp ? 'Already have an account?' : 'New here?';
  $('#authModeToggle').textContent = signingUp ? 'Sign in' : 'Create an account';
  $('#loginDialogMessage').hidden = true;
  $('#loginDialogMessage').textContent = '';
}

function openAuthDialog(mode = 'login') {
  setAuthDialogMode(mode);
  if (!$('#loginDialog').open) $('#loginDialog').showModal();
  if (mode === 'signup') $('#authName').focus();
  else $('#authEmail').focus();
}

async function submitAuth(event) {
  event.preventDefault();
  const mode = $('#authMode').value;
  const submitButton = $('#authSubmitButton');
  submitButton.disabled = true;
  $('#loginDialogMessage').hidden = true;
  try {
    const response = await fetch(`/api/auth/${mode}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({
        name: $('#authName').value,
        email: $('#authEmail').value,
        password: $('#authPassword').value
      })
    });
    const payload = await readApiResponse(response);
    if (!response.ok) throw new Error(payload.error || 'Account request failed. Please try again.');
    setAuthState(payload.user, payload.scannerConfigured, payload.scannerProvider);
    $('#loginDialog').close();
    $('#authForm').reset();
    showToast(mode === 'signup' ? 'Account created. You are now signed in.' : 'You are signed in.');
  } catch (error) {
    $('#loginDialogMessage').textContent = formatRequestError(error, 'The account server could not be reached. Check that the server is running.');
    $('#loginDialogMessage').hidden = false;
  } finally {
    submitButton.disabled = false;
  }
}

async function signOut() {
  try {
    const response = await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
    const payload = await readApiResponse(response);
    if (!response.ok) throw new Error(payload.error || 'Could not sign out.');
    setAuthState(null, false);
    showToast('You are signed out.');
  } catch (error) {
    showToast(formatRequestError(error, 'The account server could not be reached.'));
  }
}

function updateScanButton() {
  const button = $('#scanButton');
  button.disabled = !selectedFile || !currentUser || !scannerConfigured || scanActive;
  if (scanActive) $('#scanButtonText').textContent = 'Scanning securely…';
  else if (!currentUser) $('#scanButtonText').textContent = 'Sign in to scan';
  else if (!scannerConfigured) $('#scanButtonText').textContent = 'Scanner unavailable';
  else if (!selectedFile) $('#scanButtonText').textContent = 'Choose a file';
  else $('#scanButtonText').textContent = currentUser ? 'Start real scan' : 'Sign in to scan';
  $('#scanButton').querySelector('.scan-button-icon').textContent = scanActive ? '⋯' : '⌁';
}

function setAuthState(user, scannerIsConfigured = false, provider = null) {
  currentUser = user;
  scannerConfigured = scannerIsConfigured;
  scannerProvider = scannerConfigured ? provider || 'VirusTotal' : null;
  const loggedIn = Boolean(user);
  $('#authRequired').hidden = loggedIn;
  $('#scanProviderNotice').hidden = !loggedIn || scannerConfigured;
  $('#loginButton').textContent = loggedIn ? 'Sign out' : 'Sign in';
  $('#accountButton').setAttribute('aria-label', loggedIn ? 'Sign out' : 'Sign in');
  $('#profileName').textContent = loggedIn ? user.name : 'Guest user';
  $('#profileDetail').textContent = loggedIn ? user.email : 'Sign in for saved history';
  $('#profileAvatar').textContent = loggedIn ? (user.name || 'U').split(' ').map((part) => part[0]).join('').slice(0, 2).toUpperCase() : '?';
  $('#connectionLabel').textContent = loggedIn ? 'Account ready' : 'Live scanner';
  $('#connectionDetail').textContent = loggedIn ? 'Account protected' : 'Sign in to scan';
  $('#engineStatus').textContent = loggedIn ? (scannerConfigured ? `${scannerProvider} ready` : 'Scanner unavailable') : 'Sign-in required';
  $('#environmentPill').innerHTML = `<span class="pulse-dot"></span> ${loggedIn ? 'Signed-in workspace' : 'Live environment'}`;
  if (loggedIn) {
    $('#alertsToggle').setAttribute('aria-pressed', String(user.alertsEnabled !== false));
    $('#alertsToggle').innerHTML = `<span class="toggle-dot"></span> Email alerts ${user.alertsEnabled !== false ? 'on' : 'off'}`;
    $('#demoDisclosure').querySelector('span:nth-child(2)').innerHTML = scannerConfigured
      ? `<strong>Your account is ready.</strong> Submitted files are scanned by ${scannerProvider} and saved in your private history.`
      : '<strong>You are signed in.</strong> Configure a VirusTotal API key or use Windows with Microsoft Defender enabled to scan files.';
    $('.summary-note').innerHTML = scannerConfigured
      ? `<span>i</span> Results are provided by ${scannerProvider}. No scanner can guarantee a file is safe.`
      : '<span>i</span> Configure VirusTotal or Microsoft Defender to enable real file scanning.';
  } else {
    $('#alertsToggle').setAttribute('aria-pressed', 'false');
    $('#alertsToggle').innerHTML = '<span class="toggle-dot"></span> Sign in to manage email alerts';
    $('#demoDisclosure').querySelector('span:nth-child(2)').innerHTML = '<strong>Real scanning is protected.</strong> Sign in to use the configured antivirus and keep scan history. Demo history is illustrative until you sign in.';
    $('.summary-note').innerHTML = '<span>i</span> Demo history is illustrative and not a security verdict.';
  }
  updateScanButton();
  if (loggedIn) loadHistory();
  else { history = [...demoFiles]; renderHistory(); updateSummary(); }
}

async function checkSession() {
  try {
    const response = await fetch('/api/me', { credentials: 'same-origin' });
    const payload = await readApiResponse(response);
    if (!response.ok) throw new Error(payload.error || 'Account service is not ready.');
    setAuthState(payload.user || null, payload.scannerConfigured, payload.scannerProvider);
  } catch (error) {
    if (error instanceof TypeError || error?.message === 'Failed to fetch') {
      setAuthState(null, false);
      return;
    }
    setAuthState(null, false);
  }
}

function validateAndSelect(file) {
  if (!file) return;
  if (file.size > MAX_BYTES) { showToast('That file is over the 25 MB upload limit.'); $('#dropzone').focus(); return; }
  selectedFile = file;
  $('#selectedFile').hidden = false;
  $('#selectedFileType').textContent = getType(file.name);
  $('#selectedFileName').textContent = file.name;
  $('#selectedFileMeta').textContent = `${formatBytes(file.size)} · ${currentUser ? 'ready for a real scan' : 'sign in to scan'}`;
  $('#resultBanner').hidden = true;
  $('#scanProgress').hidden = true;
  updateScanButton();
  showToast(`${file.name} is ready.`);
}

function resetSelection() {
  selectedFile = null;
  $('#fileInput').value = '';
  $('#selectedFile').hidden = true;
  $('#resultBanner').hidden = true;
  updateScanButton();
}

function resultCopy(verdict, provider) {
  if (verdict === 'warning') return { title: 'Suspicious signal found', text: `${provider} reported suspicious detections. Avoid opening the file until you’ve reviewed it.`, className: 'warning', symbol: '!' };
  if (verdict === 'threat') return { title: 'Threat detected', text: `${provider} detected a threat. Do not open the file; follow your antivirus recommendations.`, className: 'threat', symbol: '!' };
  if (verdict === 'cancelled') return { title: 'Scan cancelled', text: 'No result was generated. You can choose the file again whenever you’re ready.', className: 'cancelled', symbol: '—' };
  if (verdict === 'error') return { title: 'Scan could not be completed', text: 'The scanner did not return a verified result. The file was not marked clean.', className: 'threat', symbol: '!' };
  return { title: 'Scan complete — no detections', text: `${provider} reported no detections. This does not guarantee the file is safe.`, className: '', symbol: '✓' };
}

function setResult(verdict, provider = scannerProvider || 'The scanner') {
  const banner = $('#resultBanner');
  const copy = resultCopy(verdict, provider);
  banner.hidden = false;
  banner.className = `result-banner ${copy.className}`;
  $('#resultSymbol').textContent = copy.symbol;
  $('#resultTitle').textContent = copy.title;
  $('#resultText').textContent = copy.text;
  $('#scanProgress').hidden = true;
  $('#cancelButton').hidden = true;
}

function updateProgress(value) {
  scanProgressValue = value;
  $('#progressBar').style.width = `${value}%`;
  $('#progressPercent').textContent = `${value}%`;
  if (scannerProvider === 'Microsoft Defender') {
    $('#progressLabel').textContent = value < 90 ? 'Scanning with Microsoft Defender' : 'Saving the result';
    $('#progressDetail').textContent = value < 90 ? 'The file is being scanned locally on this computer…' : 'Saving the result to your private history…';
  } else {
    $('#progressLabel').textContent = value < 35 ? 'Uploading securely' : value < 82 ? 'VirusTotal is analyzing' : 'Finalizing result';
    $('#progressDetail').textContent = value < 35 ? 'The file is sent over an encrypted connection…' : value < 82 ? 'Waiting for provider engines to complete…' : 'Saving the result to your private history…';
  }
}

function addToHistory(scan) {
  history = [{ ...scan, time: 'Just now' }, ...history].slice(0, 50);
  renderHistory();
  updateSummary();
}

async function runRealScan() {
  if (!currentUser) return openAuthDialog('login');
  if (!scannerConfigured) {
    showToast('No real scanner is configured. Add a VirusTotal API key or enable Microsoft Defender on Windows.');
    return;
  }
  if (!selectedFile || scanActive) return;
  scanActive = true;
  abortController = new AbortController();
  $('#scanButton').disabled = true;
  $('#cancelButton').hidden = false;
  $('#resultBanner').hidden = true;
  $('#scanProgress').hidden = false;
  updateProgress(4);
  scanTimer = window.setInterval(() => updateProgress(Math.min(92, scanProgressValue + Math.floor(Math.random() * 7) + 2)), 500);
  const form = new FormData();
  form.append('file', selectedFile, selectedFile.name);
  try {
    const response = await fetch('/api/scans', { method: 'POST', body: form, credentials: 'same-origin', signal: abortController.signal });
    const payload = await readApiResponse(response);
    if (!response.ok) throw new Error(payload.error || 'The scan failed.');
    updateProgress(100);
    addToHistory(payload.scan);
    setResult(payload.scan.verdict, payload.scan.provider || scannerProvider);
    showToast(payload.scan.verdict === 'clean' ? 'Scan complete — no detections.' : 'Security alert: review the result.');
  } catch (error) {
    if (error.name === 'AbortError') setResult('cancelled');
    else { setResult('error'); showToast(formatRequestError(error, error.message || 'The scan could not be completed.')); }
  } finally {
    window.clearInterval(scanTimer);
    scanTimer = null;
    scanActive = false;
    abortController = null;
    $('#scanButton').disabled = false;
    updateScanButton();
  }
}

function cancelScan() {
  if (!scanActive) return;
  abortController?.abort();
  window.clearInterval(scanTimer);
  scanTimer = null;
  scanActive = false;
  $('#scanButton').disabled = false;
  setResult('cancelled');
  updateScanButton();
  showToast('Scan cancelled.');
}

function updateSummary() {
  const items = currentUser ? history : demoFiles;
  const counts = items.reduce((acc, item) => { const verdict = item.verdict || item.result || 'clean'; acc[verdict] = (acc[verdict] || 0) + 1; return acc; }, { clean: 0, warning: 0, threat: 0 });
  const total = currentUser ? items.length : 24;
  $('#totalScans').textContent = total;
  $('#totalScans').nextElementSibling.innerHTML = `${currentUser ? 'real scans' : 'demo checks'}<br />completed`;
  $('#filesScanned').innerHTML = `${total}<span> files</span>`;
  $('#cleanCount').textContent = currentUser ? counts.clean : 22;
  $('#warningCount').textContent = currentUser ? counts.warning : 2;
  $('#threatCount').textContent = currentUser ? counts.threat : 0;
  $('#cleanBar').style.width = `${total ? Math.min(100, ((currentUser ? counts.clean : 22) / total) * 100) : 0}%`;
  $('#warningBar').style.width = `${Math.min(100, (currentUser ? counts.warning : 2) * 18)}%`;
  $('#threatBar').style.width = `${Math.min(100, (currentUser ? counts.threat : 0) * 18)}%`;
  const latest = items[0];
  if (latest) { $('#lastScanName').textContent = latest.name; $('#lastScanTime').innerHTML = currentUser ? 'Now<span></span>' : '08<span>m</span>'; }
}

function renderHistory() {
  const target = $('#historyRows');
  if (!history.length) { target.innerHTML = '<div class="empty-history">No real scans yet. Choose a file above to create your first saved result.</div>'; return; }
  target.innerHTML = history.map((item, index) => {
    const verdict = item.verdict || item.result || 'clean';
    const badge = verdict === 'warning' ? 'warning' : verdict === 'threat' ? 'threat' : '';
    const label = verdict === 'warning' ? 'Suspicious' : verdict === 'threat' ? 'Threat detected' : verdict === 'error' ? 'Error' : 'Clean';
    const time = item.time || relativeTime(item.createdAt);
    return `<div class="history-row"><div class="history-file"><span class="file-type-badge">${item.type || getType(item.name)}</span><span>${item.name}</span></div><span class="history-time">${time}</span><span><span class="result-badge ${badge}">${label}</span></span><span class="history-size">${formatBytes(item.size)}</span><button class="row-more" type="button" data-scan-index="${index}" aria-label="Show details for ${item.name}">···</button></div>`;
  }).join('');
}

async function loadHistory() {
  try {
    const response = await fetch('/api/scans', { credentials: 'same-origin' });
    if (response.status === 401) return;
    const payload = await readApiResponse(response);
    if (response.ok) { history = (payload.scans || []).map((item) => ({ ...item, time: relativeTime(item.createdAt) })); renderHistory(); updateSummary(); }
  } catch (error) {
    showToast(formatRequestError(error, 'Saved history is temporarily unavailable.'));
  }
}

async function toggleAlerts() {
  if (!currentUser) { showToast('Sign in to manage email alert preferences.'); return; }
  const next = currentUser.alertsEnabled === false;
  try {
    const response = await fetch('/api/preferences', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ alertsEnabled: next }), credentials: 'same-origin' });
    if (!response.ok) throw new Error('Could not update email alerts.');
    currentUser.alertsEnabled = next;
    $('#alertsToggle').setAttribute('aria-pressed', String(next));
    $('#alertsToggle').innerHTML = `<span class="toggle-dot"></span> Email alerts ${next ? 'on' : 'off'}`;
    showToast(`Email alerts turned ${next ? 'on' : 'off'}.`);
  } catch (error) { showToast(formatRequestError(error, error.message || 'Could not update email alerts.')); }
}

function chooseFile() { $('#fileInput').click(); }

$('#dropzone').addEventListener('click', chooseFile);
$('#dropzone').addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); chooseFile(); } });
$('#fileInput').addEventListener('change', (event) => validateAndSelect(event.target.files[0]));
['dragenter', 'dragover'].forEach((name) => $('#dropzone').addEventListener(name, (event) => { event.preventDefault(); $('#dropzone').classList.add('dragover'); }));
['dragleave', 'drop'].forEach((name) => $('#dropzone').addEventListener(name, (event) => { event.preventDefault(); $('#dropzone').classList.remove('dragover'); }));
$('#dropzone').addEventListener('drop', (event) => validateAndSelect(event.dataTransfer.files[0]));
$('#removeFile').addEventListener('click', resetSelection);
$('#scanButton').addEventListener('click', runRealScan);
$('#cancelButton').addEventListener('click', cancelScan);
$('#resultClose').addEventListener('click', () => { $('#resultBanner').hidden = true; });
$('#refreshButton').addEventListener('click', async () => { await checkSession(); showToast('Status refreshed.'); });
$('#viewAllButton').addEventListener('click', () => {
  $('#history').scrollIntoView({ behavior: 'smooth', block: 'start' });
  showToast(currentUser ? 'Showing your latest 50 real scans.' : 'Showing recent demo activity. Sign in to view saved scans.');
});
$('#notificationButton').addEventListener('click', () => {
  $('#history').scrollIntoView({ behavior: 'smooth', block: 'start' });
  showToast('Your recent scan activity is shown below.');
});
$('#historyRows').addEventListener('click', (event) => {
  const button = event.target.closest('[data-scan-index]');
  if (!button) return;
  const item = history[Number(button.dataset.scanIndex)];
  if (!item) return;
  const verdict = item.verdict || item.result || 'clean';
  const label = verdict === 'warning' ? 'suspicious' : verdict === 'threat' ? 'threat detected' : verdict;
  showToast(`${item.name} — ${label}; ${item.time || relativeTime(item.createdAt)}; ${formatBytes(item.size)}.`);
});
$('#nextTip').addEventListener('click', () => { tipIndex = (tipIndex + 1) % tips.length; $('#guidanceTitle').innerHTML = tips[tipIndex].title; $('#guidanceText').textContent = tips[tipIndex].text; });
$('#alertsToggle').addEventListener('click', toggleAlerts);
$('#loginButton').addEventListener('click', () => currentUser ? signOut() : openAuthDialog('login'));
$('#loginButtonInline').addEventListener('click', () => openAuthDialog('login'));
$('#accountButton').addEventListener('click', () => currentUser ? signOut() : openAuthDialog('login'));
$('#authForm').addEventListener('submit', submitAuth);
$('#authModeToggle').addEventListener('click', () => setAuthDialogMode($('#authMode').value === 'login' ? 'signup' : 'login'));
$('#authDialogClose').addEventListener('click', () => $('#loginDialog').close());
$('.disclosure-close').addEventListener('click', (event) => event.currentTarget.parentElement.remove());
$$('[data-scroll-to]').forEach((button) => button.addEventListener('click', () => document.getElementById(button.dataset.scrollTo).scrollIntoView({ behavior: 'smooth', block: 'start' })));
$('.mobile-menu').addEventListener('click', () => {
  const sidebar = $('.sidebar');
  const isOpen = sidebar.classList.toggle('open');
  $('.mobile-menu').setAttribute('aria-expanded', String(isOpen));
});
function setActiveNavigation(activeItem) {
  $$('.nav-item').forEach((link) => {
    const active = link === activeItem;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
}
$$('.nav-item').forEach((item) => item.addEventListener('click', () => {
  $('.sidebar').classList.remove('open');
  $('.mobile-menu').setAttribute('aria-expanded', 'false');
  setActiveNavigation(item);
}));
window.addEventListener('hashchange', () => {
  const currentLink = $$('.nav-item').find((item) => item.hash === window.location.hash);
  if (currentLink) setActiveNavigation(currentLink);
});
const initialNavItem = $$('.nav-item').find((item) => item.hash === window.location.hash);
if (initialNavItem) setActiveNavigation(initialNavItem);

updateCurrentDate();
window.setInterval(updateCurrentDate, 60 * 1000);
renderHistory();
updateSummary();
checkSession();
