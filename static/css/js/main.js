const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const filePreview = document.getElementById('filePreview');
const fileName = document.getElementById('fileName');
const fileSize = document.getElementById('fileSize');
const removeFile = document.getElementById('removeFile');
const scanBtn = document.getElementById('scanBtn');
const scanText = document.querySelector('.scan-btn-text');
const scanLoader = document.querySelector('.scan-loader');
const resultsCard = document.getElementById('resultsCard');

let selectedFile = null;

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(2) + ' MB';
}

function setFile(file) {
  selectedFile = file;
  fileName.textContent = file.name;
  fileSize.textContent = formatBytes(file.size);
  filePreview.style.display = 'block';
  dropZone.style.display = 'none';
  scanBtn.disabled = false;
  scanText.textContent = 'SCAN FILE';
}

function clearFile() {
  selectedFile = null;
  filePreview.style.display = 'none';
  dropZone.style.display = 'block';
  scanBtn.disabled = true;
  scanText.textContent = 'SELECT A FILE TO SCAN';
  fileInput.value = '';
  resultsCard.style.display = 'none';
}

fileInput.addEventListener('change', e => { if (e.target.files[0]) setFile(e.target.files[0]); });
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault(); dropZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) setFile(file);
});
removeFile.addEventListener('click', clearFile);
document.getElementById('scanAgainBtn').addEventListener('click', clearFile);

scanBtn.addEventListener('click', async () => {
  if (!selectedFile) return;
  scanText.style.display = 'none';
  scanLoader.style.display = 'inline';
  scanBtn.disabled = true;
  resultsCard.style.display = 'none';

  const formData = new FormData();
  formData.append('file', selectedFile);

  try {
    const resp = await fetch('/scan', { method: 'POST', body: formData });
    const data = await resp.json();
    if (data.error) { alert('Error: ' + data.error); return; }
    renderResults(data);
  } catch (err) {
    alert('Connection error. Is Flask running? ' + err.message);
  } finally {
    scanText.style.display = 'inline';
    scanLoader.style.display = 'none';
    scanBtn.disabled = false;
  }
});

function renderResults(data) {
  const isMalicious = data.prediction === 'MALICIOUS';
  const banner = document.getElementById('verdictBanner');
  banner.className = 'verdict-banner ' + (isMalicious ? 'malicious' : 'benign');
  document.getElementById('verdictIcon').textContent = isMalicious ? '⚠️' : '✅';
  document.getElementById('verdictLabel').textContent = data.prediction;
  document.getElementById('verdictSub').textContent = isMalicious
    ? 'This file shows characteristics of ransomware or malicious software.'
    : 'This file appears safe based on static analysis.';
  document.getElementById('resultFilename').textContent = data.filename;

  const pct = data.confidence;
  document.getElementById('confPct').textContent = pct + '%';
  const ring = document.getElementById('ringFg');
  ring.style.strokeDashoffset = 213.6 - (pct / 100) * 213.6;
  ring.style.stroke = isMalicious ? 'var(--danger)' : 'var(--safe)';

  document.getElementById('riskValue').textContent = data.risk_score + ' / 100';
  document.getElementById('riskBar').style.width = data.risk_score + '%';

  const d = data.details;
  const tableData = [
    ['File Size', d.file_size], ['Extension', d.extension], ['Entropy', d.entropy],
    ['Strings', d.strings], ['URLs', d.urls], ['IPs', d.ips],
    ['MD5', d.md5.substring(0,16) + '...'], ['SHA256', d.sha256.substring(0,16) + '...'],
  ];
  document.getElementById('detailTable').innerHTML =
    tableData.map(([k,v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join('');

  document.getElementById('reasonList').innerHTML =
    data.reasons.map(r => `<li>${r}</li>`).join('');

  const tipsBox = document.getElementById('tipsBox');
  tipsBox.className = 'tips-box' + (isMalicious ? '' : ' safe-tips');
  tipsBox.querySelector('h3').textContent = isMalicious ? 'PREVENTION TIPS' : 'SECURITY TIPS';
  document.getElementById('tipsList').innerHTML =
    data.tips.map(t => `<li>${t}</li>`).join('');

  resultsCard.style.display = 'block';
  resultsCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
}