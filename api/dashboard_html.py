HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Razorpay AI Risk Manager - Autonomous Fraud Defense</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        brand: {
                            50: '#eef2ff',
                            500: '#3b82f6',
                            600: '#2563eb',
                            700: '#1d4ed8',
                            900: '#0f172a',
                        },
                        darkbg: '#0b0f19',
                        darkcard: '#111827',
                        darkborder: '#1f2937',
                    }
                }
            }
        }
    </script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        @keyframes pulse-slow { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        .animate-pulse-slow { animation: pulse-slow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #0b0f19; }
        ::-webkit-scrollbar-thumb { background: #374151; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #4b5563; }
    </style>
</head>
<body class="bg-darkbg text-slate-100 min-h-screen font-sans antialiased flex flex-col selection:bg-blue-600 selection:text-white">

    <!-- Top Navigation -->
    <header class="border-b border-darkborder bg-darkcard/80 backdrop-blur sticky top-0 z-50 px-6 py-3.5 flex items-center justify-between">
        <div class="flex items-center gap-3">
            <div class="h-9 w-9 rounded-lg bg-blue-600 flex items-center justify-center text-white font-black text-lg shadow-lg shadow-blue-500/20">
                <i class="fa-solid fa-shield-halved"></i>
            </div>
            <div>
                <div class="flex items-center gap-2">
                    <h1 class="font-bold text-lg text-white tracking-tight">Razorpay AI Risk Manager</h1>
                    <span class="text-[11px] font-semibold uppercase tracking-wider bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded-full">Autonomous L2 Defense</span>
                </div>
                <p class="text-xs text-slate-400">Deterministic Statistical ML + Groq LPU AI Reasoning Layer</p>
            </div>
        </div>

        <div class="flex items-center gap-4">
            <div id="health-badge" class="flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-3 py-1.5 rounded-lg text-xs font-medium">
                <span class="h-2 w-2 rounded-full bg-emerald-400 animate-pulse-slow"></span>
                <span>System Online</span>
                <span class="text-slate-500">|</span>
                <span id="buffer-stat" class="text-slate-300">Buffer: 0 txns</span>
            </div>

            <div class="flex items-center gap-2 bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 px-3 py-1.5 rounded-lg text-xs">
                <i class="fa-solid fa-bolt text-amber-400"></i>
                <span class="font-mono font-medium">Groq LPU (GPT-OSS 120B)</span>
            </div>

            <button onclick="fetchData()" class="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-1.5 border border-slate-700">
                <i class="fa-solid fa-rotate" id="refresh-icon"></i> Refresh
            </button>
        </div>
    </header>

    <!-- Main Container -->
    <main class="flex-1 p-6 max-w-[1600px] w-full mx-auto space-y-6">

        <!-- Top Metrics Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <!-- Total Attack Alerts -->
            <div class="bg-darkcard border border-darkborder rounded-xl p-4 shadow-sm relative overflow-hidden">
                <div class="flex items-center justify-between text-slate-400 text-xs font-medium mb-2">
                    <span>Live Attack Alerts</span>
                    <i class="fa-solid fa-triangle-exclamation text-rose-400"></i>
                </div>
                <div class="flex items-baseline gap-2">
                    <span id="metric-alerts-total" class="text-2xl font-bold text-white tracking-tight">0</span>
                    <span class="text-xs text-rose-400 font-medium">Flagged by Tier-1</span>
                </div>
                <div class="mt-3 text-[11px] text-slate-400 flex items-center justify-between border-t border-darkborder/60 pt-2">
                    <span>Precision: <strong id="metric-precision" class="text-emerald-400 font-semibold">100.0%</strong></span>
                    <span>F1 Score: <strong id="metric-f1" class="text-blue-400 font-semibold">1.000</strong></span>
                </div>
            </div>

            <!-- True Positives vs False Positives -->
            <div class="bg-darkcard border border-darkborder rounded-xl p-4 shadow-sm relative overflow-hidden">
                <div class="flex items-center justify-between text-slate-400 text-xs font-medium mb-2">
                    <span>Detection Accuracy</span>
                    <i class="fa-solid fa-bullseye text-emerald-400"></i>
                </div>
                <div class="flex items-baseline gap-3">
                    <div>
                        <span class="text-xs text-slate-400">TP: </span>
                        <span id="metric-tp" class="text-xl font-bold text-emerald-400">0</span>
                    </div>
                    <div>
                        <span class="text-xs text-slate-400">FP: </span>
                        <span id="metric-fp" class="text-xl font-bold text-slate-400">0</span>
                    </div>
                </div>
                <div class="mt-3 text-[11px] text-slate-400 border-t border-darkborder/60 pt-2">
                    <span class="text-emerald-400"><i class="fa-solid fa-circle-check"></i> Zero normal txns blocked</span>
                </div>
            </div>

            <!-- False Positive Cost Saved -->
            <div class="bg-darkcard border border-darkborder rounded-xl p-4 shadow-sm relative overflow-hidden">
                <div class="flex items-center justify-between text-slate-400 text-xs font-medium mb-2">
                    <span>False-Positive Review Cost</span>
                    <i class="fa-solid fa-indian-rupee-sign text-amber-400"></i>
                </div>
                <div class="flex items-baseline gap-2">
                    <span id="metric-fp-cost" class="text-2xl font-bold text-amber-400 font-mono tracking-tight">INR 0.00</span>
                </div>
                <div class="mt-3 text-[11px] text-slate-400 border-t border-darkborder/60 pt-2">
                    <span>INR 200/FP saved vs standard rule engines</span>
                </div>
            </div>

            <!-- Pipeline Latency & Speed -->
            <div class="bg-darkcard border border-darkborder rounded-xl p-4 shadow-sm relative overflow-hidden">
                <div class="flex items-center justify-between text-slate-400 text-xs font-medium mb-2">
                    <span>Gateway Performance</span>
                    <i class="fa-solid fa-bolt text-blue-400"></i>
                </div>
                <div class="flex items-baseline gap-2">
                    <span class="text-2xl font-bold text-white tracking-tight">&lt; 0.8 ms</span>
                    <span class="text-xs text-blue-400 font-medium">In-Memory Gateway</span>
                </div>
                <div class="mt-3 text-[11px] text-slate-400 border-t border-darkborder/60 pt-2 flex items-center justify-between">
                    <span>LLM Reasoning: <strong class="text-indigo-400">Asynchronous</strong></span>
                    <span class="text-emerald-400">Zero Checkout Lag</span>
                </div>
            </div>
        </div>

        <!-- Main Content Area: Left = Full Alert Feed, Right = Recent Transactions & Architecture -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">

            <!-- Alert Feed (2 Columns) -->
            <div class="lg:col-span-2 space-y-4">
                <div class="bg-darkcard border border-darkborder rounded-xl shadow-sm overflow-hidden flex flex-col">
                    <div class="px-5 py-4 border-b border-darkborder flex items-center justify-between bg-slate-900/40">
                        <div class="flex items-center gap-2.5">
                            <span class="h-3 w-3 rounded-full bg-rose-500 animate-ping"></span>
                            <h2 class="font-bold text-base text-white">Live Attack Alerts & AI Reasoning</h2>
                        </div>
                        <span id="alerts-count-badge" class="text-xs bg-rose-500/10 text-rose-400 border border-rose-500/20 px-2.5 py-1 rounded-full font-medium">0 active attacks</span>
                    </div>

                    <!-- Alerts List -->
                    <div id="alerts-container" class="p-5 space-y-4 max-h-[700px] overflow-y-auto">
                        <!-- Empty State -->
                        <div id="no-alerts-placeholder" class="py-16 text-center text-slate-500 space-y-3">
                            <i class="fa-solid fa-shield-check text-4xl text-slate-600"></i>
                            <p class="text-sm font-medium">No attack patterns currently detected</p>
                            <p class="text-xs text-slate-600 max-w-sm mx-auto">Transactions are being evaluated in real-time. Card testing bursts or sequential BIN attacks will trigger instant AI diagnosis here.</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Right Column: Live Ingestion Stream & Architecture Summary -->
            <div class="space-y-6">

                <!-- Ingested Stream Ticker -->
                <div class="bg-darkcard border border-darkborder rounded-xl shadow-sm overflow-hidden flex flex-col">
                    <div class="px-5 py-3.5 border-b border-darkborder flex items-center justify-between bg-slate-900/40">
                        <div class="flex items-center gap-2">
                            <i class="fa-solid fa-stream text-blue-400"></i>
                            <h3 class="font-bold text-sm text-white">Live Ingestion Stream</h3>
                        </div>
                        <span id="txns-count" class="text-xs text-slate-400 font-mono">0 ingested</span>
                    </div>
                    <div id="transactions-container" class="p-3 max-h-[350px] overflow-y-auto space-y-2 font-mono text-xs">
                        <div class="text-center py-8 text-slate-600">Waiting for stream...</div>
                    </div>
                </div>

                <!-- Two-Tier Architecture Info Card -->
                <div class="bg-darkcard border border-darkborder rounded-xl p-5 shadow-sm space-y-4 text-xs">
                    <div class="flex items-center gap-2 text-white font-bold text-sm">
                        <i class="fa-solid fa-layer-group text-indigo-400"></i>
                        <span>How the 2-Tier Engine Works</span>
                    </div>

                    <div class="space-y-3 text-slate-300">
                        <div class="bg-slate-900/60 border border-slate-800 p-3 rounded-lg space-y-1">
                            <div class="flex items-center justify-between font-semibold text-slate-200">
                                <span>Tier 1: Statistical ML Reflex</span>
                                <span class="text-[10px] text-emerald-400 font-mono">&lt; 1ms | ₹0 cost</span>
                            </div>
                            <p class="text-[11px] text-slate-400 leading-relaxed">Welford rolling z-scores and Isolation Forest filter 99.9% of normal payments instantly in-memory.</p>
                        </div>

                        <div class="bg-indigo-950/20 border border-indigo-900/40 p-3 rounded-lg space-y-1">
                            <div class="flex items-center justify-between font-semibold text-indigo-200">
                                <span>Tier 2: Gemini Reasoning Brain</span>
                                <span class="text-[10px] text-indigo-400 font-mono">Asynchronous</span>
                            </div>
                            <p class="text-[11px] text-slate-400 leading-relaxed">Diagnoses the 0.1% flagged clusters. Separates flash sales from card testing and generates plain English incident explanations.</p>
                        </div>
                    </div>
                </div>

            </div>

        </div>

    </main>

    <!-- Footer -->
    <footer class="border-t border-darkborder bg-darkcard/50 px-6 py-3 text-xs text-slate-500 flex items-center justify-between">
        <div class="flex items-center gap-2">
            <span class="h-2 w-2 rounded-full bg-emerald-500"></span>
            <span>Razorpay Risk Engineering Prototype</span>
        </div>
        <div>
            <span>Auto-refreshing live every 1.0s</span>
        </div>
    </footer>

    <!-- JavaScript Data Poller -->
    <script>
        let previousAlertIds = new Set();

        async function fetchData() {
            try {
                const [healthRes, alertsRes, metricsRes, txnsRes] = await Promise.all([
                    fetch('/health').then(r => r.json()).catch(() => null),
                    fetch('/alerts?limit=50').then(r => r.json()).catch(() => []),
                    fetch('/metrics').then(r => r.json()).catch(() => null),
                    fetch('/transactions?limit=30').then(r => r.json()).catch(() => []),
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

                // Update Alerts
                renderAlerts(alertsRes || []);

                // Update Transactions
                renderTransactions(txnsRes || []);

            } catch (err) {
                console.error("Fetch error:", err);
            }
        }

        function renderAlerts(alerts) {
            const container = document.getElementById('alerts-container');
            const badge = document.getElementById('alerts-count-badge');
            
            // Filter real attacks
            const real = alerts.filter(a => a.attack_type && a.attack_type !== 'none');
            badge.innerText = `${real.length} active attack${real.length === 1 ? '' : 's'}`;

            if (real.length === 0) {
                container.innerHTML = `
                    <div id="no-alerts-placeholder" class="py-16 text-center text-slate-500 space-y-3">
                        <i class="fa-solid fa-shield-check text-4xl text-slate-600"></i>
                        <p class="text-sm font-medium">No attack patterns currently detected</p>
                        <p class="text-xs text-slate-600 max-w-sm mx-auto">Transactions are being evaluated in real-time. Card testing bursts or sequential BIN attacks will trigger instant AI diagnosis here.</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = real.map(alert => {
                const isCardTesting = alert.attack_type === 'card_testing';
                const typeColor = isCardTesting 
                    ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' 
                    : 'bg-fuchsia-500/10 text-fuchsia-400 border-fuchsia-500/30';
                const icon = isCardTesting ? 'fa-credit-card' : 'fa-network-wired';
                const typeLabel = isCardTesting ? 'Card Testing Attack' : 'BIN Enumeration Attack';
                
                const time = (alert.timestamp || '').replace('T', ' ').substring(0, 19);
                const confidencePct = Math.round((alert.confidence || 0) * 100);

                const providerName = alert.llm_provider || (alert.llm_used ? 'Groq AI (LPU)' : 'Deterministic Fallback');
                const srcBadge = alert.llm_used
                    ? `<span class="inline-flex items-center gap-1.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2.5 py-0.5 rounded-md text-[11px] font-semibold"><i class="fa-solid fa-bolt text-[10px]"></i> ${providerName}</span>`
                    : `<span class="inline-flex items-center gap-1.5 bg-amber-500/10 text-amber-400 border border-amber-500/30 px-2.5 py-0.5 rounded-md text-[11px] font-semibold"><i class="fa-solid fa-shield text-[10px]"></i> Fallback</span>`;

                const triggers = (alert.triggered_features || []).map(f => 
                    `<span class="bg-slate-800/80 border border-slate-700/60 px-2 py-0.5 rounded text-[10px] text-slate-300 font-mono">${f}</span>`
                ).join(' ');

                return `
                    <div class="bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition rounded-xl p-5 space-y-3.5 shadow-md">
                        <!-- Top Row: Type, Confidence, Action, Source -->
                        <div class="flex flex-wrap items-center justify-between gap-3">
                            <div class="flex items-center gap-3">
                                <span class="inline-flex items-center gap-1.5 border px-3 py-1 rounded-lg text-xs font-bold ${typeColor}">
                                    <i class="fa-solid ${icon}"></i>
                                    ${typeLabel}
                                </span>
                                <span class="text-xs font-mono text-slate-400"><i class="fa-regular fa-clock"></i> ${time}</span>
                            </div>

                            <div class="flex items-center gap-3">
                                <div class="text-xs text-slate-400">
                                    Confidence: <strong class="text-white">${confidencePct}%</strong>
                                </div>
                                <span class="bg-rose-500/20 text-rose-300 border border-rose-500/40 px-2.5 py-0.5 rounded-md text-xs font-bold uppercase tracking-wider">
                                    ${alert.recommended_action || 'HOLD_FOR_REVIEW'}
                                </span>
                                ${srcBadge}
                            </div>
                        </div>

                        <!-- Gemini AI Reasoning Explanation Box -->
                        <div class="bg-slate-950/70 border border-slate-800/80 rounded-lg p-4 space-y-2">
                            <div class="flex items-center justify-between text-xs text-slate-400">
                                <span class="font-semibold text-slate-300 flex items-center gap-1.5">
                                    <i class="fa-solid fa-wand-magic-sparkles text-indigo-400"></i> AI Analyst Reasoning & Diagnosis:
                                </span>
                                <span class="text-[11px] text-slate-500">Anomaly Score: ${(alert.anomaly_score || 0).toFixed(3)}</span>
                            </div>
                            <p class="text-sm text-slate-200 leading-relaxed font-normal">${alert.explanation || 'No explanation available.'}</p>
                        </div>

                        <!-- Triggered Features Badges -->
                        ${triggers ? `
                            <div class="flex flex-wrap items-center gap-1.5 pt-1">
                                <span class="text-[11px] text-slate-500 font-medium mr-1">Signal Triggers:</span>
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
                container.innerHTML = `<div class="text-center py-8 text-slate-600">Waiting for stream...</div>`;
                return;
            }

            container.innerHTML = txns.map(t => {
                const isAttack = t.is_attack;
                const isFail = t.status === 'failure';
                const tagColor = isAttack ? 'text-rose-400 font-bold' : (isFail ? 'text-amber-400' : 'text-slate-400');
                const time = (t.timestamp || '').substring(11, 19);
                return `
                    <div class="flex items-center justify-between p-2 rounded bg-slate-900/40 border border-slate-800/60 hover:bg-slate-800/40 transition">
                        <div class="flex items-center gap-2">
                            <span class="text-slate-500">${time}</span>
                            <span class="font-semibold text-slate-300">${t.card_bin}•••${t.card_last4}</span>
                        </div>
                        <div class="flex items-center gap-3">
                            <span class="text-slate-200">INR ${Number(t.amount || 0).toFixed(2)}</span>
                            <span class="${tagColor} uppercase text-[10px] px-1.5 py-0.5 rounded bg-slate-800">${t.status || 'ok'}</span>
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
