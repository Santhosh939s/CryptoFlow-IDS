// CryptoFlow-IDS Real-Time Cyber Dashboard Controller

let ws = null;
let entropyChart = null;
let protocolChart = null;
let soundEnabled = true;

// Web Audio API Synth for Cyber Alerts
const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
function playAlertSound() {
    if (!soundEnabled || !audioCtx) return;
    try {
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, audioCtx.currentTime); // A5
        osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.25);
        gain.gain.setValueAtTime(0.15, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.25);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.25);
    } catch (e) {
        // Ignore audio policy errors
    }
}

// Initialize Charts
function initCharts() {
    const entropyCtx = document.getElementById('entropyChart').getContext('2d');
    entropyChart = new Chart(entropyCtx, {
        type: 'line',
        data: {
            labels: Array(25).fill(''),
            datasets: [
                {
                    label: 'Payload Shannon Entropy',
                    data: Array(25).fill(0),
                    borderColor: '#00f2fe',
                    backgroundColor: 'rgba(0, 242, 254, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.35,
                    pointRadius: 2,
                    pointHoverRadius: 5
                },
                {
                    label: 'Alert Threshold (7.2)',
                    data: Array(25).fill(7.2),
                    borderColor: 'rgba(255, 42, 95, 0.7)',
                    borderDash: [5, 5],
                    borderWidth: 1.5,
                    fill: false,
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: {
                y: {
                    min: 0,
                    max: 8.0,
                    grid: { color: 'rgba(64, 93, 140, 0.15)' },
                    ticks: { color: '#8292ab', font: { family: 'JetBrains Mono', size: 10 } }
                },
                x: {
                    grid: { display: false },
                    ticks: { display: false }
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#f0f4fc', font: { family: 'Rajdhani', size: 12 } }
                }
            }
        }
    });

    const protocolCtx = document.getElementById('protocolChart').getContext('2d');
    protocolChart = new Chart(protocolCtx, {
        type: 'doughnut',
        data: {
            labels: ['TCP Exfil/Data', 'TLS Web', 'QUIC (UDP)'],
            datasets: [{
                data: [1, 1, 1],
                backgroundColor: [
                    '#4facfe',
                    '#00f090',
                    '#9b51e0'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#8292ab', font: { family: 'Rajdhani', size: 12 } }
                }
            },
            cutout: '70%'
        }
    });
}

// WebSocket Connection & Real-Time Handler
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        console.log('Telemetry WebSocket connected.');
        document.getElementById('connectionStatus').innerText = 'CONNECTED';
        document.getElementById('connectionStatus').style.color = '#00f090';
    };

    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        handleWsMessage(msg);
    };

    ws.onclose = () => {
        document.getElementById('connectionStatus').innerText = 'DISCONNECTED';
        document.getElementById('connectionStatus').style.color = '#ff2a5f';
        setTimeout(connectWebSocket, 2000);
    };
}

function handleWsMessage(msg) {
    if (msg.type === 'init') {
        updateStats(msg.data.engine.stats);
        renderThreats(msg.data.threats);
        renderBlockedIps(msg.data.blocked_ips);
        populateInterfaces(msg.data.interfaces, msg.data.engine.interface);
        updateEngineState(msg.data.engine.running);
    } else if (msg.type === 'tick') {
        updateStats(msg.data.stats);
        updateEngineState(msg.data.running);
    } else if (msg.type === 'flow') {
        addFlowRow(msg.data);
        pushEntropyData(msg.data.entropy);
    } else if (msg.type === 'threat_alert') {
        prependThreatCard(msg.data);
        playAlertSound();
        fetchBlockedIps(); // Refresh blocklist
    } else if (msg.type === 'engine_status') {
        updateEngineState(msg.data.status === 'running');
    } else if (msg.type === 'ip_unblocked') {
        fetchBlockedIps();
    } else if (msg.type === 'threat_intel_update') {
        updateThreatCardIntel(msg.data);
    }
}

// UI Updating Functions
function updateStats(stats) {
    if (!stats) return;
    document.getElementById('valPackets').innerText = stats.packets_inspected.toLocaleString();
    document.getElementById('valThreats').innerText = stats.threats_detected.toLocaleString();
    document.getElementById('valBlocked').innerText = stats.blocked_count.toLocaleString();
    document.getElementById('valPPS').innerText = `${stats.pps || 0} pps`;

    // Threat level badge
    const badge = document.getElementById('threatBadge');
    const badgeText = document.getElementById('threatText');
    if (stats.current_threat_level === 'CRITICAL') {
        badge.className = 'threat-level-badge critical';
        badgeText.innerText = 'CRITICAL ALERT';
    } else {
        badge.className = 'threat-level-badge';
        badgeText.innerText = 'NORMAL MONITOR';
    }

    // Update Protocol Chart
    if (protocolChart) {
        protocolChart.data.datasets[0].data = [
            stats.tcp_packets || 1,
            stats.tls_packets || 1,
            stats.quic_packets || 1
        ];
        protocolChart.update();
    }
}

// Throttled Chart & Telemetry Redraw Loop (60 FPS Performance)
const entropyBuffer = [];
let chartRenderScheduled = false;

function pushEntropyData(val) {
    entropyBuffer.push(val);
    if (!chartRenderScheduled) {
        chartRenderScheduled = true;
        requestAnimationFrame(flushChartUpdates);
    }
}

function flushChartUpdates() {
    if (entropyChart && entropyBuffer.length > 0) {
        const data = entropyChart.data.datasets[0].data;
        while (entropyBuffer.length > 0) {
            data.push(entropyBuffer.shift());
            if (data.length > 25) data.shift();
        }
        entropyChart.update('none'); // Update without animation lag
    }
    chartRenderScheduled = false;
}

function prependThreatCard(threat) {
    const list = document.getElementById('threatFeedList');
    const card = document.createElement('div');
    card.className = 'threat-card';
    if (threat.id) {
        card.id = 'threat-card-' + threat.id;
    }

    const protoPill = threat.is_quic 
        ? '<span class="pill pill-quic">QUIC (UDP)</span>' 
        : '<span class="pill pill-tcp">TCP</span>';

    const flag = threat.flag || '🧪';
    const country = threat.country || 'Local Lab / Simulation';
    const asn = threat.asn || 'AS-PRIVATE';
    const score = threat.threat_score || 85;
    const pcapBtn = threat.pcap_file 
        ? `<a href="/api/incidents/${threat.pcap_file}" download class="btn-pcap" title="Download Forensic PCAP for Wireshark">💾 PCAP</a>` 
        : '';

    card.innerHTML = `
        <div class="threat-card-header">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span class="threat-badge">🚨 THREAT DETECTED</span>
                <span class="score-badge">SEV: ${score}/100</span>
            </div>
            <div style="display: flex; align-items: center; gap: 8px;">
                ${pcapBtn}
                <span class="threat-time">${threat.datetime_str || 'Just now'}</span>
            </div>
        </div>
        <div class="threat-details">
            <div class="threat-field" style="grid-column: 1 / -1;">
                <span>Threat Origin & Intelligence</span>
                <span class="intel-badge">${flag} ${country} • <span style="font-family: var(--font-mono); color: var(--primary);">${asn}</span></span>
            </div>
            <div class="threat-field">
                <span>Source IP</span>
                <span>${threat.src_ip}</span>
            </div>
            <div class="threat-field">
                <span>Target Port</span>
                <span>${threat.dst_port}</span>
            </div>
            <div class="threat-field">
                <span>Protocol</span>
                <span>${protoPill}</span>
            </div>
            <div class="threat-field">
                <span>Shannon Entropy</span>
                <span style="color: #ff2a5f;">${threat.entropy} / 8.0</span>
            </div>
            <div class="threat-field">
                <span>Confidence</span>
                <span>${threat.confidence}%</span>
            </div>
            <div class="threat-field">
                <span>Mitigation</span>
                <span style="color: #00f090;">${threat.mitigated ? 'BLOCKED (WFP)' : 'FLAGGED'}</span>
            </div>
        </div>
    `;

    list.insertBefore(card, list.firstChild);
    while (list.children.length > 30) {
        list.removeChild(list.lastChild);
    }
}

function updateThreatCardIntel(data) {
    if (!data || !data.id) return;
    const card = document.getElementById('threat-card-' + data.id);
    if (!card) return;

    const intelBadge = card.querySelector('.intel-badge');
    if (intelBadge) {
        const flag = data.flag || '🌐';
        const country = data.country || 'External Host';
        const asn = data.asn || 'AS-REMOTE';
        intelBadge.innerHTML = `${flag} ${country} • <span style="font-family: var(--font-mono); color: var(--primary);">${asn}</span>`;
    }

    const scoreBadge = card.querySelector('.score-badge');
    if (scoreBadge && data.threat_score !== undefined) {
        scoreBadge.innerText = `SEV: ${data.threat_score}/100`;
    }
}

function renderThreats(threats) {
    const list = document.getElementById('threatFeedList');
    list.innerHTML = '';
    if (!threats || threats.length === 0) {
        list.innerHTML = '<div style="color: #4d5d75; text-align: center; padding: 20px;">No threats detected yet. System secure.</div>';
        return;
    }
    threats.forEach(t => prependThreatCard(t));
}

let flowRowCount = 0;
function addFlowRow(flow) {
    const tbody = document.getElementById('trafficTableBody');
    const tr = document.createElement('tr');

    const pillClass = flow.is_threat ? 'pill-threat' : (flow.protocol === 'QUIC' ? 'pill-quic' : 'pill-tcp');

    tr.innerHTML = `
        <td>${new Date().toLocaleTimeString()}</td>
        <td><span class="pill ${pillClass}">${flow.protocol}</span></td>
        <td>${flow.src_ip}</td>
        <td>${flow.dst_ip}:${flow.port}</td>
        <td>${flow.entropy}</td>
        <td>${flow.size} B</td>
        <td>${flow.is_threat ? '🚨 MALICIOUS' : 'SAFE'}</td>
    `;

    tbody.insertBefore(tr, tbody.firstChild);
    flowRowCount++;
    if (flowRowCount > 20) {
        tbody.removeChild(tbody.lastChild);
        flowRowCount--;
    }
}

// Blocklist Management
async function fetchBlockedIps() {
    try {
        const res = await fetch('/api/blocked-ips');
        const data = await res.json();
        renderBlockedIps(data);
    } catch (e) {
        console.error(e);
    }
}

function renderBlockedIps(ips) {
    const tbody = document.getElementById('blockedIpsBody');
    tbody.innerHTML = '';
    if (!ips || ips.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #4d5d75; padding: 20px;">No active firewall block rules.</td></tr>';
        return;
    }
    ips.forEach(item => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="color: #ff2a5f; font-weight: 600;">${item.ip}</td>
            <td>${item.datetime_str}</td>
            <td>${item.reason}</td>
            <td><span class="pill pill-threat">ACTIVE DROP</span></td>
            <td>
                <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="unblockIp('${item.ip}')">Unblock</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function unblockIp(ip) {
    try {
        await fetch(`/api/blocked-ips/${encodeURIComponent(ip)}`, { method: 'DELETE' });
        fetchBlockedIps();
    } catch (e) {
        alert('Failed to unblock: ' + e);
    }
}

// Engine Controls
function populateInterfaces(interfaces, selectedId) {
    const select = document.getElementById('ifaceSelect');
    select.innerHTML = '';
    interfaces.forEach(iface => {
        const opt = document.createElement('option');
        opt.value = iface.id;
        opt.innerText = iface.name;
        if (iface.id === selectedId) opt.selected = true;
        select.appendChild(opt);
    });
}

function updateEngineState(isRunning) {
    const btn = document.getElementById('btnToggleEngine');
    const badge = document.getElementById('engineBadge');
    if (isRunning) {
        btn.innerText = 'STOP ENGINE';
        btn.className = 'btn btn-danger';
        badge.innerText = 'ENGINE: RUNNING';
        badge.style.color = '#00f090';
    } else {
        btn.innerText = 'START ENGINE';
        btn.className = 'btn btn-primary';
        badge.innerText = 'ENGINE: STOPPED';
        badge.style.color = '#8292ab';
    }
}

async function toggleEngine() {
    const btn = document.getElementById('btnToggleEngine');
    const isRunning = btn.innerText.includes('STOP');
    const iface = document.getElementById('ifaceSelect').value;

    if (isRunning) {
        await fetch('/api/engine/stop', { method: 'POST' });
    } else {
        await fetch('/api/engine/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: iface })
        });
    }
}

// In-App Attack Simulator
async function runSim(mode) {
    const statusBox = document.getElementById('simStatus');
    statusBox.innerText = `[SIMULATOR] Launching simulated ${mode.toUpperCase()} attack chunks...`;

    try {
        const res = await fetch('/api/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode: mode, chunks: 5 })
        });
        const data = await res.json();
        statusBox.innerText = `[SIMULATOR] Exfiltration in progress (${mode}). Watch alerts!`;
        setTimeout(() => {
            statusBox.innerText = '[SIMULATOR] Ready. Select an attack scenario to test.';
        }, 5000);
    } catch (e) {
        statusBox.innerText = `[SIMULATOR ERROR] ${e}`;
    }
}

// Toggle Sound
function toggleSound() {
    soundEnabled = !soundEnabled;
    document.getElementById('btnSound').innerText = soundEnabled ? '🔊 Sound: ON' : '🔇 Sound: OFF';
}

// Phase 3: Scroll & Offline Forensic Studio Controllers
function scrollToStudio() {
    const el = document.getElementById('forensicStudioSection');
    if (el) el.scrollIntoView({ behavior: 'smooth' });
}

function initOfflineStudio() {
    const dropZone = document.getElementById('pcapDropZone');
    const fileInput = document.getElementById('pcapFileInput');
    if (!dropZone || !fileInput) return;

    ['dragenter', 'dragover'].forEach(name => {
        dropZone.addEventListener(name, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(name => {
        dropZone.addEventListener(name, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove('dragover');
        });
    });

    dropZone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            uploadAndAnalyzePcap(files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (fileInput.files.length > 0) {
            uploadAndAnalyzePcap(fileInput.files[0]);
        }
    });
}

async function uploadAndAnalyzePcap(file) {
    const loading = document.getElementById('pcapLoading');
    const results = document.getElementById('offlineResults');
    loading.style.display = 'block';
    results.style.display = 'none';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch('/api/pcap/analyze', {
            method: 'POST',
            body: formData
        });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Analysis failed');
        }
        const data = await res.json();
        renderOfflineResults(data);
    } catch (err) {
        alert('PCAP Analysis Error: ' + err.message);
    } finally {
        loading.style.display = 'none';
    }
}

function renderOfflineResults(data) {
    document.getElementById('resTotalPkts').innerText = data.total_packets.toLocaleString();
    document.getElementById('resPayloads').innerText = data.inspected_payloads.toLocaleString();
    document.getElementById('resThreats').innerText = data.threat_count.toLocaleString();
    document.getElementById('resSafe').innerText = data.safe_count.toLocaleString();
    document.getElementById('resAvgEntropy').innerText = `${data.avg_entropy} / 8.0`;
    document.getElementById('resQuic').innerText = data.quic_count.toLocaleString();

    const tbody = document.getElementById('offlineTableBody');
    tbody.innerHTML = '';
    if (!data.threats || data.threats.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--safe); padding: 20px;">🛡️ Clean capture. No malicious high-entropy exfiltrations detected.</td></tr>';
    } else {
        data.threats.forEach(t => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${t.packet_num}</td>
                <td><strong>${t.src_ip}</strong></td>
                <td>${t.dst_ip}:${t.dst_port}</td>
                <td><span class="pill ${t.protocol === 'QUIC' ? 'pill-quic' : 'pill-tcp'}">${t.protocol}</span></td>
                <td style="color: var(--danger); font-weight: 600;">${t.entropy}</td>
                <td>${t.confidence}%</td>
                <td><span class="pill pill-threat">EXFILTRATION</span></td>
            `;
            tbody.appendChild(tr);
        });
    }

    document.getElementById('offlineResults').style.display = 'flex';
    scrollToStudio();
}

function resetOfflineStudio() {
    document.getElementById('offlineResults').style.display = 'none';
    document.getElementById('offlineTableBody').innerHTML = '';
    const fileInput = document.getElementById('pcapFileInput');
    if (fileInput) fileInput.value = '';
}

// Page Load
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    connectWebSocket();
    initOfflineStudio();

    document.getElementById('btnToggleEngine').addEventListener('click', toggleEngine);
    document.getElementById('btnSound').addEventListener('click', toggleSound);
});
