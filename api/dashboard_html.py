HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Razorpay Aegis — Enterprise Fraud & Threat Defense</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
                        mono: ['JetBrains Mono', 'Menlo', 'Monaco', 'Courier New', 'monospace'],
                    },
                    colors: {
                        slate: {
                            850: '#131c2e',
                            900: '#0c1322',
                            950: '#070b14',
                        }
                    }
                }
            }
        }
    </script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        body { font-feature-settings: "cv02", "cv03", "cv04", "cv11"; }
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: #070b14; }
        ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #334155; }
    </style>
</head>
<body class="bg-slate-950 text-slate-200 min-h-screen flex flex-col selection:bg-blue-600 selection:text-white font-sans antialiased text-sm">

    <!-- Top Professional Enterprise Header -->
    <header class="border-b border-slate-800/80 bg-slate-900/90 backdrop-blur-md sticky top-0 z-50 px-6 py-3 flex items-center justify-between">
        <div class="flex items-center gap-3.5">
            <div class="h-8 w-8 rounded-md bg-blue-600 flex items-center justify-center text-white shadow-sm">
                <i class="fa-solid fa-shield-halved text-sm"></i>
            </div>
            <div>
                <div class="flex items-center gap-2.5">
                    <h1 class="font-semibold text-slate-100 tracking-tight text-base">Razorpay Aegis</h1>
                    <span class="text-[10px] font-mono font-medium uppercase tracking-wider bg-slate-800 text-slate-300 border border-slate-700/80 px-2 py-0.5 rounded">Autonomous L2 Risk Gateway</span>
                    <span class="text-[10px] font-mono font-medium uppercase tracking-wider bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded flex items-center gap-1">
                        <i class="fa-solid fa-shield-virus text-[9px]"></i> Threat Mesh Active
                    </span>
                </div>
            </div>
        </div>

        <div class="flex items-center gap-3">
            <div id="health-badge" class="flex items-center gap-2 bg-slate-800/80 border border-slate-700/80 text-slate-300 px-3 py-1 rounded text-xs font-mono">
                <span class="h-2 w-2 rounded-full bg-emerald-400"></span>
                <span>System Normal</span>
                <span class="text-slate-600">|</span>
                <span id="buffer-stat" class="text-slate-400">Buffer: 0 txns</span>
            </div>

            <div class="flex items-center gap-1.5 bg-slate-800/80 border border-slate-700/80 text-slate-300 px-3 py-1 rounded text-xs font-mono">
                <i class="fa-solid fa-microchip text-blue-400 text-xs"></i>
                <span id="llm-provider-label">Groq LPU (GPT-OSS 120B)</span>
            </div>

            <button onclick="fetchData()" class="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1 rounded text-xs font-medium transition flex items-center gap-1.5 border border-slate-700">
                <i class="fa-solid fa-arrows-rotate text-[11px]" id="refresh-icon"></i> Refresh
            </button>
        </div>
    </header>

    <!-- Main Workspace -->
    <main class="flex-1 p-6 max-w-[1700px] w-full mx-auto space-y-5">

        <!-- Metrics Grid -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3.5">
            <!-- Total Flagged Alerts -->
            <div class="bg-slate-900 border border-slate-800/80 rounded-lg p-4 flex flex-col justify-between">
                <div class="flex items-center justify-between text-slate-400 text-xs">
                    <span class="font-medium">Detected Threat Windows</span>
                    <i class="fa-solid fa-triangle-exclamation text-rose-400 text-xs"></i>
                </div>
                <div class="my-2 flex items-baseline gap-2">
                    <span id="metric-alerts-total" class="text-2xl font-bold text-slate-100 font-mono tracking-tight">0</span>
                    <span class="text-[11px] text-slate-400">flagged</span>
                </div>
                <div class="text-[11px] text-slate-400 flex items-center justify-between border-t border-slate-800 pt-2 font-mono">
                    <span>Precision: <strong id="metric-precision" class="text-emerald-400 font-medium">100.0%</strong></span>
                    <span>F1: <strong id="metric-f1" class="text-blue-400 font-medium">1.000</strong></span>
                </div>
            </div>

            <!-- Accuracy breakdown -->
            <div class="bg-slate-900 border border-slate-800/80 rounded-lg p-4 flex flex-col justify-between">
                <div class="flex items-center justify-between text-slate-400 text-xs">
                    <span class="font-medium">Detection Accuracy</span>
                    <i class="fa-solid fa-bullseye text-emerald-400 text-xs"></i>
                </div>
                <div class="my-2 flex items-baseline gap-4 font-mono">
                    <div>
                        <span class="text-xs text-slate-500">TP:</span>
                        <span id="metric-tp" class="text-xl font-semibold text-emerald-400">0</span>
                    </div>
                    <div>
                        <span class="text-xs text-slate-500">FP:</span>
                        <span id="metric-fp" class="text-xl font-semibold text-slate-400">0</span>
                    </div>
                </div>
                <div class="text-[11px] text-emerald-400/90 border-t border-slate-800 pt-2 flex items-center gap-1.5">
                    <i class="fa-solid fa-check text-[10px]"></i> Zero legitimate checkout friction
                </div>
            </div>

            <!-- Collective Immune Mesh Metrics -->
            <div class="bg-slate-900 border border-slate-800/80 rounded-lg p-4 flex flex-col justify-between">
                <div class="flex items-center justify-between text-slate-400 text-xs">
                    <span class="font-medium">Collective Threat Mesh</span>
                    <i class="fa-solid fa-network-wired text-cyan-400 text-xs"></i>
                </div>
                <div class="my-2 flex items-baseline gap-2">
                    <span id="mesh-active-vaccines" class="text-2xl font-bold text-cyan-400 font-mono tracking-tight">0</span>
                    <span class="text-[11px] text-slate-400">active vaccines</span>
                </div>
                <div class="text-[11px] text-slate-400 border-t border-slate-800 pt-2 flex items-center justify-between font-mono">
                    <span>Cuckoo Entries: <strong id="mesh-cuckoo-count" class="text-slate-300 font-medium">0</strong></span>
                    <span id="mesh-load-factor" class="text-cyan-400/90">Load: 0.0%</span>
                </div>
            </div>

            <!-- Review Cost Savings -->
            <div class="bg-slate-900 border border-slate-800/80 rounded-lg p-4 flex flex-col justify-between">
                <div class="flex items-center justify-between text-slate-400 text-xs">
                    <span class="font-medium">Estimated Review OpEx</span>
                    <i class="fa-solid fa-indian-rupee-sign text-amber-400 text-xs"></i>
                </div>
                <div class="my-2">
                    <span id="metric-fp-cost" class="text-2xl font-bold text-slate-100 font-mono tracking-tight">INR 0.00</span>
                </div>
                <div class="text-[11px] text-slate-400 border-t border-slate-800 pt-2">
                    <span>INR 200/FP saved vs legacy rules</span>
                </div>
            </div>

            <!-- Latency & Throughput -->
            <div class="bg-slate-900 border border-slate-800/80 rounded-lg p-4 flex flex-col justify-between">
                <div class="flex items-center justify-between text-slate-400 text-xs">
                    <span class="font-medium">Gateway Latency SLA</span>
                    <i class="fa-solid fa-bolt text-blue-400 text-xs"></i>
                </div>
                <div class="my-2 flex items-baseline gap-2">
                    <span class="text-2xl font-bold text-slate-100 font-mono tracking-tight">&lt; 0.8 ms</span>
                    <span class="text-[11px] text-emerald-400 font-mono">Fast-path &lt;0.1ms</span>
                </div>
                <div class="text-[11px] text-slate-400 border-t border-slate-800 pt-2 flex items-center justify-between">
                    <span>LLM Gating: <strong class="text-slate-300">Async Queue</strong></span>
                    <span class="text-emerald-400">Zero Lag</span>
                </div>
            </div>
        </div>

        <!-- Main Split View: Left = Threat Log & AI Reasoning, Right = Live Stream & Mesh Telemetry -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-5">

            <!-- Left: Incident Log & AI Reasoning Stream (2 Columns) -->
            <div class="lg:col-span-2 space-y-3">
                <div class="bg-slate-900 border border-slate-800/80 rounded-lg overflow-hidden flex flex-col">
                    <div class="px-4 py-3 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
                        <div class="flex items-center gap-2">
                            <span class="h-2 w-2 rounded-full bg-rose-500"></span>
                            <h2 class="font-semibold text-slate-100 text-xs uppercase tracking-wider">Attack Incident Stream & AI Reasoning</h2>
                        </div>
                        <span id="alerts-count-badge" class="text-[11px] font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">0 active attacks</span>
                    </div>

                    <!-- Alerts Feed List -->
                    <div id="alerts-container" class="p-4 space-y-3 max-h-[720px] overflow-y-auto">
                        <div id="no-alerts-placeholder" class="py-16 text-center text-slate-500 space-y-2">
                            <i class="fa-solid fa-shield-check text-3xl text-slate-600"></i>
                            <p class="text-xs font-medium text-slate-400">No active anomaly spikes detected</p>
                            <p class="text-[11px] text-slate-600 max-w-sm mx-auto">Transactions are streaming in real-time. Automated card-testing bursts or sequential BIN attacks will trigger instant AI analysis here.</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Right: Real-time Ingestion Stream & Threat Mesh Vaccines -->
            <div class="space-y-4">

                <!-- Threat Mesh Active Vaccines Widget -->
                <div class="bg-slate-900 border border-slate-800/80 rounded-lg overflow-hidden flex flex-col">
                    <div class="px-4 py-2.5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
                        <div class="flex items-center gap-2">
                            <i class="fa-solid fa-shield-virus text-cyan-400 text-xs"></i>
                            <h3 class="font-semibold text-slate-100 text-xs uppercase tracking-wider">Collective Immune Vaccines</h3>
                        </div>
                        <span id="mesh-badge" class="text-[10px] font-mono text-cyan-400 bg-cyan-950/40 border border-cyan-800/50 px-2 py-0.5 rounded">0 active</span>
                    </div>
                    <div id="vaccines-container" class="p-3 max-h-[220px] overflow-y-auto space-y-2 font-mono text-xs">
                        <div class="text-center py-5 text-slate-600 text-[11px]">No active threat vaccines broadcast yet.</div>
                    </div>
                </div>

                <!-- Ingestion Stream Ticker -->
                <div class="bg-slate-900 border border-slate-800/80 rounded-lg overflow-hidden flex flex-col">
                    <div class="px-4 py-2.5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
                        <div class="flex items-center gap-2">
                            <i class="fa-solid fa-list-check text-slate-400 text-xs"></i>
                            <h3 class="font-semibold text-slate-100 text-xs uppercase tracking-wider">Live Transaction Ingest</h3>
                        </div>
                        <span id="txns-count" class="text-[11px] font-mono text-slate-400">0 ingested</span>
                    </div>
                    <div id="transactions-container" class="p-3 max-h-[340px] overflow-y-auto space-y-1.5 font-mono text-xs">
                        <div class="text-center py-6 text-slate-600 text-[11px]">Waiting for transaction stream...</div>
                    </div>
                </div>

                <!-- Architecture Summary Info -->
                <div class="bg-slate-900 border border-slate-800/80 rounded-lg p-4 space-y-2.5 text-xs">
                    <div class="flex items-center gap-2 text-slate-200 font-semibold text-xs uppercase tracking-wider">
                        <i class="fa-solid fa-layer-group text-blue-400"></i>
                        <span>Defensive Architecture Flow</span>
                    </div>
                    <div class="space-y-2 text-slate-400 text-[11px] leading-relaxed">
                        <div class="bg-slate-950/60 border border-slate-800/80 p-2.5 rounded">
                            <div class="text-slate-200 font-medium flex items-center justify-between">
                                <span>0. Fast Path: Cuckoo Threat Mesh</span>
                                <span class="text-cyan-400 font-mono">&lt; 0.1ms</span>
                            </div>
                            <p class="text-slate-400 mt-0.5">Known multi-merchant bot fingerprints challenged with 3DS step-up instantly.</p>
                        </div>
                        <div class="bg-slate-950/60 border border-slate-800/80 p-2.5 rounded">
                            <div class="text-slate-200 font-medium flex items-center justify-between">
                                <span>1. Tier 1: Statistical Outlier Filter</span>
                                <span class="text-emerald-400 font-mono">&lt; 0.8ms</span>
                            </div>
                            <p class="text-slate-400 mt-0.5">Welford variance and Isolation Forest filter 99.8% of clean payments.</p>
                        </div>
                        <div class="bg-slate-950/60 border border-slate-800/80 p-2.5 rounded">
                            <div class="text-slate-200 font-medium flex items-center justify-between">
                                <span>2. Tier 2: LLM Reasoning Brain</span>
                                <span class="text-blue-400 font-mono">Async LPU</span>
                            </div>
                            <p class="text-slate-400 mt-0.5">Diagnoses root cause, explains pattern to analysts, submits ZK threat hash.</p>
                        </div>
                    </div>
                </div>

            </div>

        </div>

    </main>

    <!-- Professional Footer -->
    <footer class="border-t border-slate-800/80 bg-slate-900/60 px-6 py-2.5 text-[11px] text-slate-500 flex items-center justify-between font-mono">
        <div class="flex items-center gap-2">
            <span class="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
            <span>Razorpay Aegis Risk Engineering Engine · Production Prototype</span>
        </div>
        <div>
            <span>Poller Interval: 1.0s · Zero Checkout Blocking</span>
        </div>
    </footer>

    <!-- JavaScript Data Poller -->
    <script>
        async function fetchData() {
            try {
                const [healthRes, alertsRes, metricsRes, txnsRes, meshRes] = await Promise.all([
                    fetch('/health').then(r => r.json()).catch(() => null),
                    fetch('/alerts?limit=50').then(r => r.json()).catch(() => []),
                    fetch('/metrics').then(r => r.json()).catch(() => null),
                    fetch('/transactions?limit=30').then(r => r.json()).catch(() => []),
                    fetch('/threat-mesh/status').then(r => r.json()).catch(() => null),
                ]);

                // Update Health
                if (healthRes) {
                    document.getElementById('buffer-stat').innerText = `Buffer: ${healthRes.buffer_size || 0} txns`;
                }

                // Update Metrics
                if (metricsRes && !metricsRes.message) {
                    document.getElementById('metric-alerts-total').innerText = metricsRes.alerts_total || 0;
                    document.getElementById('metric-precision').innerText = `${((metricsRes.precision || 0) * 100).toFixed(1)}%`;
                    document.getElementById('metric-f1').innerText = (metricsRes.f1_partial || 0).toFixed(3);
                    document.getElementById('metric-tp').innerText = metricsRes.tp || 0;
                    document.getElementById('metric-fp').innerText = metricsRes.fp || 0;
                    document.getElementById('metric-fp-cost').innerText = `INR ${(metricsRes.fp_cost_inr || 0).toFixed(2)}`;
                }

                // Update Threat Mesh
                if (meshRes) {
                    document.getElementById('mesh-active-vaccines').innerText = meshRes.active_vaccines || 0;
                    document.getElementById('mesh-cuckoo-count').innerText = meshRes.cuckoo_entries || 0;
                    document.getElementById('mesh-load-factor').innerText = `Load: ${((meshRes.cuckoo_load_factor || 0) * 100).toFixed(1)}%`;
                    document.getElementById('mesh-badge').innerText = `${meshRes.active_vaccines || 0} active`;
                    renderVaccines(meshRes.vaccines || []);
                }

                // Update Alerts & Transactions
                renderAlerts(alertsRes || []);
                renderTransactions(txnsRes || []);

            } catch (err) {
                console.error("Fetch error:", err);
            }
        }

        function renderVaccines(vaccines) {
            const container = document.getElementById('vaccines-container');
            if (vaccines.length === 0) {
                container.innerHTML = `<div class="text-center py-5 text-slate-600 text-[11px]">No active threat vaccines broadcast yet.</div>`;
                return;
            }
            container.innerHTML = vaccines.map(v => `
                <div class="p-2 rounded bg-slate-950/80 border border-cyan-900/40 text-[11px] space-y-1">
                    <div class="flex items-center justify-between">
                        <span class="text-cyan-400 font-semibold flex items-center gap-1">
                            <i class="fa-solid fa-fingerprint text-[10px]"></i> ${v.fingerprint}
                        </span>
                        <span class="text-[10px] text-emerald-400 bg-emerald-950/40 border border-emerald-800/40 px-1.5 py-0.2 rounded font-sans">
                            ${v.merchant_count || 3} Merchs Quorum
                        </span>
                    </div>
                    <div class="text-[10px] text-slate-500 flex items-center justify-between">
                        <span>Expires: ${v.expires_at.substring(11, 19)}</span>
                        <span>Auto-decay: 15m TTL</span>
                    </div>
                </div>
            `).join('');
        }

        function renderAlerts(alerts) {
            const container = document.getElementById('alerts-container');
            const badge = document.getElementById('alerts-count-badge');
            
            const real = alerts.filter(a => a.attack_type && a.attack_type !== 'none');
            badge.innerText = `${real.length} active attack${real.length === 1 ? '' : 's'}`;

            if (real.length === 0) {
                container.innerHTML = `
                    <div id="no-alerts-placeholder" class="py-16 text-center text-slate-500 space-y-2">
                        <i class="fa-solid fa-shield-check text-3xl text-slate-600"></i>
                        <p class="text-xs font-medium text-slate-400">No active anomaly spikes detected</p>
                        <p class="text-[11px] text-slate-600 max-w-sm mx-auto">Transactions are streaming in real-time. Automated card-testing bursts or sequential BIN attacks will trigger instant AI analysis here.</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = real.map(alert => {
                const isCardTesting = alert.attack_type === 'card_testing';
                const typeColor = isCardTesting 
                    ? 'bg-rose-500/10 text-rose-300 border-rose-500/30' 
                    : 'bg-indigo-500/10 text-indigo-300 border-indigo-500/30';
                const icon = isCardTesting ? 'fa-credit-card' : 'fa-network-wired';
                const typeLabel = isCardTesting ? 'Card Testing Probing' : 'BIN Enumeration Attack';
                
                const time = (alert.timestamp || '').replace('T', ' ').substring(0, 19);
                const confidencePct = Math.round((alert.confidence || 0) * 100);

                const providerName = alert.llm_provider || (alert.llm_used ? 'Groq LPU' : 'Deterministic Fallback');
                const srcBadge = alert.llm_used
                    ? `<span class="inline-flex items-center gap-1 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded text-[10px] font-mono"><i class="fa-solid fa-bolt text-[9px]"></i> ${providerName}</span>`
                    : `<span class="inline-flex items-center gap-1 bg-amber-500/10 text-amber-400 border border-amber-500/30 px-2 py-0.5 rounded text-[10px] font-mono"><i class="fa-solid fa-shield text-[9px]"></i> Fallback</span>`;

                const triggers = (alert.triggered_features || []).map(f => 
                    `<span class="bg-slate-950 border border-slate-800 px-2 py-0.5 rounded text-[10px] text-slate-300 font-mono">${f}</span>`
                ).join(' ');

                const actionBadge = (alert.recommended_action === 'challenge_step_up')
                    ? '<span class="bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded text-[10px] font-mono font-medium uppercase">3DS Step-Up Challenge</span>'
                    : `<span class="bg-rose-500/10 text-rose-300 border border-rose-500/30 px-2 py-0.5 rounded text-[10px] font-mono font-medium uppercase">${alert.recommended_action || 'HOLD_FOR_REVIEW'}</span>`;

                return `
                    <div class="bg-slate-900/90 border border-slate-800 hover:border-slate-700/80 transition rounded-lg p-4 space-y-3">
                        <!-- Top Row: Type, Confidence, Action, Source -->
                        <div class="flex flex-wrap items-center justify-between gap-2.5">
                            <div class="flex items-center gap-2.5">
                                <span class="inline-flex items-center gap-1.5 border px-2.5 py-0.5 rounded text-xs font-semibold ${typeColor}">
                                    <i class="fa-solid ${icon} text-[11px]"></i>
                                    ${typeLabel}
                                </span>
                                <span class="text-[11px] font-mono text-slate-500"><i class="fa-regular fa-clock text-[10px]"></i> ${time}</span>
                            </div>

                            <div class="flex items-center gap-2.5">
                                <div class="text-[11px] text-slate-400 font-mono">
                                    Confidence: <strong class="text-slate-200">${confidencePct}%</strong>
                                </div>
                                ${actionBadge}
                                ${srcBadge}
                            </div>
                        </div>

                        <!-- AI Reasoning Explanation Box -->
                        <div class="bg-slate-950/80 border border-slate-800/80 rounded p-3 space-y-1.5">
                            <div class="flex items-center justify-between text-xs">
                                <span class="font-medium text-slate-300 flex items-center gap-1.5 text-[11px]">
                                    <i class="fa-solid fa-brain text-blue-400 text-[10px]"></i> AI Risk Diagnosis:
                                </span>
                                <span class="text-[10px] font-mono text-slate-500">Anomaly Score: ${(alert.anomaly_score || 0).toFixed(3)}</span>
                            </div>
                            <p class="text-xs text-slate-300 leading-relaxed font-normal">${alert.explanation || 'No explanation available.'}</p>
                        </div>

                        <!-- Triggered Features Badges -->
                        ${triggers ? `
                            <div class="flex flex-wrap items-center gap-1 pt-0.5">
                                <span class="text-[10px] text-slate-500 font-mono mr-1">Signals:</span>
                                ${triggers}
                            </div>
                        ` : ''}
                    </div>
                `;
            }).join('');
        }

        function renderTransactions(txns) {
            const container = document.getElementById('transactions-container');
            const countLabel = document.getElementById('txns-count');
            countLabel.innerText = `${txns.length} recent`;

            if (txns.length === 0) {
                container.innerHTML = `<div class="text-center py-6 text-slate-600 text-[11px]">Waiting for transaction stream...</div>`;
                return;
            }

            container.innerHTML = txns.map(t => {
                const isAttack = t.is_attack;
                const isFail = t.status === 'failure';
                const tagColor = isAttack ? 'text-rose-400 font-semibold' : (isFail ? 'text-amber-400' : 'text-slate-400');
                const time = (t.timestamp || '').substring(11, 19);
                return `
                    <div class="flex items-center justify-between p-1.5 rounded bg-slate-950/50 border border-slate-800/70 text-[11px]">
                        <div class="flex items-center gap-2">
                            <span class="text-slate-500">${time}</span>
                            <span class="text-slate-300 font-medium">${t.card_bin}•••${t.card_last4}</span>
                        </div>
                        <div class="flex items-center gap-2.5">
                            <span class="text-slate-300">INR ${Number(t.amount || 0).toFixed(2)}</span>
                            <span class="${tagColor} uppercase text-[10px] px-1 rounded bg-slate-900 border border-slate-800">${t.status || 'ok'}</span>
                        </div>
                    </div>
                `;
            }).join('');
        }

        // Initial fetch + Poll every 1000ms
        fetchData();
        setInterval(fetchData, 1000);
    </script>
</body>
</html>"""
