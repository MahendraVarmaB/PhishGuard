import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid
} from 'recharts';
import {
  Shield, ShieldAlert, ShieldCheck, Activity, Download,
  Globe, Clock, Zap, AlertTriangle, Eye, Fingerprint
} from 'lucide-react';

const BACKEND = 'http://127.0.0.1:8000';

// ─────────────────────────────────────────────────────────────────────────────
// REMEDIATION 5C: IoC Export Sanitization
//
// CSV/JSON Injection attack: if a URL begins with '=', '+', '-', or '@'
// a spreadsheet application (Excel, LibreOffice, Google Sheets) will
// interpret it as a formula, potentially executing arbitrary commands
// on the SOC analyst's workstation.
//
// Fix: prefix any string field that starts with a formula character
// with a single quote ('), which forces spreadsheet apps to treat the
// cell as literal text. We apply this to EVERY string field before export.
// ─────────────────────────────────────────────────────────────────────────────
const FORMULA_CHARS = /^[=+\-@\t\r]/;

function sanitizeExportField(val) {
  if (typeof val !== 'string') return val;
  return FORMULA_CHARS.test(val) ? `'${val}` : val;
}

function sanitizeExportRow(row) {
  const out = {};
  for (const [k, v] of Object.entries(row)) {
    out[k] = Array.isArray(v)
      ? v.map(sanitizeExportField)
      : sanitizeExportField(v);
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// App
// ─────────────────────────────────────────────────────────────────────────────
function App() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedIdx, setSelectedIdx] = useState(null);

  // ───────────────────────────────────────────────────────────────────────────
  // REMEDIATION 5B: Server-Sent Events — replaces setInterval polling
  //
  // OLD: fetch('/api/v1/history') every 3 seconds → downloads entire array.
  //   At 10,000 records × 500 bytes/record = 5 MB downloaded every 3 seconds.
  //   React reconciles ALL rows on every tick → frame drops, OOM crashes.
  //
  // NEW: EventSource connects once. Backend pushes only NEW scan entries.
  //   Delta payload = ~500 bytes per event. State prepend is O(1).
  //   On mount, we do ONE initial fetch for history, then SSE handles deltas.
  // ───────────────────────────────────────────────────────────────────────────
  useEffect(() => {
    // Initial load
    fetch(`${BACKEND}/api/v1/history`)
      .then(r => r.ok ? r.json() : { history: [] })
      .then(d => setHistory(d.history || []))
      .catch(() => {})
      .finally(() => setLoading(false));

    // SSE live feed
    const es = new EventSource(`${BACKEND}/api/v1/stream`);
    es.onmessage = (evt) => {
      try {
        const entry = JSON.parse(evt.data);
        // Prepend to front — most recent first, matching server's reversed history
        setHistory(prev => [entry, ...prev].slice(0, 500));
      } catch {}
    };
    es.onerror = () => {
      // EventSource auto-reconnects; no manual retry needed
    };
    return () => es.close();
  }, []);

  // ─── Derived metrics ───────────────────────────────────────────────────────
  const totalScans      = history.length;
  const maliciousScans  = history.filter(h => h.is_malicious).length;
  const benignScans     = totalScans - maliciousScans;
  const safeRate        = totalScans > 0 ? ((benignScans / totalScans) * 100).toFixed(1) : '100.0';
  const threatRate      = totalScans > 0 ? ((maliciousScans / totalScans) * 100).toFixed(1) : '0.0';
  const avgLatency      = history.length
    ? (history.reduce((a, b) => a + b.latency_ms, 0) / history.length).toFixed(0)
    : 0;
  const typosquattingCount = history.filter(h => h.typosquatting_target).length;
  const obfuscatedCount    = history.filter(h => h.is_obfuscated).length;

  const pieData = [
    { name: 'Safe',    value: benignScans,   color: '#10b981' },
    { name: 'Blocked', value: maliciousScans, color: '#ef4444' },
  ];

  const intelMatches = (entry) => (entry.threat_intel_matches || []).filter(m => !m.startsWith('User '));
  const intelHits = history.filter(h => intelMatches(h).length > 0);

  const ctiSources = {};
  history.forEach(h => {
    intelMatches(h).forEach(src => {
      ctiSources[src] = (ctiSources[src] || 0) + 1;
    });
  });
  const ctiBarData = Object.entries(ctiSources).map(([name, count]) => ({
    name: name.length > 18 ? name.slice(0, 18) + '…' : name,
    count,
  }));

  // ─── Export with sanitization ──────────────────────────────────────────────
  const exportIoC = useCallback(() => {
    const malicious = history.filter(h => h.is_malicious);
    const iocs = malicious.map(h => sanitizeExportRow({
      indicator:           h.url,
      type:                'url',
      risk_score:          String(h.risk_score),
      threat_intel:        (h.threat_intel_matches || []).join(' | '),
      typosquatting_target: h.typosquatting_target || '',
      domain_age_days:     h.domain_age_days != null ? String(h.domain_age_days) : '',
      is_obfuscated:       String(h.is_obfuscated || false),
      timestamp:           new Date(h.timestamp * 1000).toISOString(),
    }));
    const blob = new Blob([JSON.stringify(iocs, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `phishguard-ioc-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [history]);

  const renderCenterLabel = () => (
    <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central">
      <tspan x="50%" dy="-8" fill="#f1f5f9" fontSize="28" fontWeight="700">{safeRate}%</tspan>
      <tspan x="50%" dy="22" fill="#64748b" fontSize="11" fontWeight="500">SAFE RATE</tspan>
    </text>
  );

  return (
    <div className="min-h-screen bg-[#060918] text-slate-200 font-sans">
      <div className="fixed inset-0 opacity-[0.03]" style={{
        backgroundImage: 'linear-gradient(rgba(255,255,255,.1) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.1) 1px,transparent 1px)',
        backgroundSize: '40px 40px'
      }} />

      <div className="relative z-10 p-6 lg:p-8 max-w-[1600px] mx-auto">

        {/* Header */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-8">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center shadow-lg shadow-blue-500/20">
              <Shield size={24} className="text-white" />
            </div>
            <div>
              <h1 className="text-2xl lg:text-3xl font-bold text-white tracking-tight">PhishGuard</h1>
              <p className="text-sm text-slate-500">SOC Threat Intelligence Dashboard</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20">
              <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs font-medium text-emerald-400">Live</span>
            </div>
            <button
              onClick={exportIoC}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 text-sm font-medium text-slate-300 transition-all duration-200"
            >
              <Download size={16} />
              Export IoC
            </button>
          </div>
        </div>

        {/* KPI Strip */}
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
          <KPICard icon={<Activity size={20} />}    label="Total Scans" value={totalScans}         color="blue" />
          <KPICard icon={<ShieldCheck size={20} />} label="Safe"        value={benignScans}        color="emerald" />
          <KPICard icon={<ShieldAlert size={20} />} label="Blocked"     value={maliciousScans}     sub={`${threatRate}%`} color="red" />
          <KPICard icon={<Zap size={20} />}         label="Avg Latency" value={`${avgLatency}ms`}  color="purple" />
          <KPICard icon={<Fingerprint size={20} />} label="Typosquat"   value={typosquattingCount} color="amber" />
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Donut */}
          <div className="lg:col-span-3 bg-white/[0.03] backdrop-blur-sm border border-white/[0.06] rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-1">Protection Rate</h3>
            <p className="text-xs text-slate-600 mb-4">Percentage of safe browsing sessions</p>
            <div className="h-56 relative">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={65} outerRadius={85}
                    paddingAngle={3} dataKey="value" strokeWidth={0}>
                    {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                  </Pie>
                  {renderCenterLabel()}
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1e293b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', color: '#f1f5f9', fontSize: '13px' }}
                    formatter={(value, name) => [`${value} URLs`, name]}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex justify-center gap-6 mt-2">
              <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-emerald-500" /><span className="text-xs text-slate-400">Safe ({benignScans})</span></div>
              <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-red-500" /><span className="text-xs text-slate-400">Blocked ({maliciousScans})</span></div>
            </div>
          </div>

          {/* CTI Bar */}
          <div className="lg:col-span-4 bg-white/[0.03] backdrop-blur-sm border border-white/[0.06] rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-1">Threat Intel Sources</h3>
            <p className="text-xs text-slate-600 mb-4">Detections by intelligence feed</p>
            {ctiBarData.length > 0 ? (
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={ctiBarData} layout="vertical" margin={{ left: 0, right: 16 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" horizontal={false} />
                    <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} width={110} />
                    <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', color: '#f1f5f9', fontSize: '13px' }} />
                    <Bar dataKey="count" fill="#3b82f6" radius={[0, 6, 6, 0]} barSize={20} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-56 flex items-center justify-center">
                <p className="text-slate-600 text-sm">No threat detections yet</p>
              </div>
            )}
          </div>

          {/* Mini cards */}
          <div className="lg:col-span-5 grid grid-cols-1 sm:grid-cols-2 gap-4">
            <MiniCard icon={<AlertTriangle size={18} />} title="Typosquatting" desc="Brand impersonation attempts" value={typosquattingCount} color="amber"
              items={history.filter(h => h.typosquatting_target).slice(0, 3).map(h => {
                try { return `${h.typosquatting_target} ← ${new URL(h.url).hostname}`; } catch { return h.typosquatting_target; }
              })}
            />
            <MiniCard icon={<Eye size={18} />} title="Obfuscated URLs" desc="Encoded or disguised links" value={obfuscatedCount} color="orange"
              items={history.filter(h => h.is_obfuscated).slice(0, 3).map(h => {
                try { return new URL(h.url).hostname; } catch { return h.url.slice(0, 30); }
              })}
            />
            <MiniCard icon={<Clock size={18} />} title="New Domains" desc="Registered < 30 days ago"
              value={history.filter(h => h.domain_age_days != null && h.domain_age_days < 30).length} color="rose"
              items={history.filter(h => h.domain_age_days != null && h.domain_age_days < 30).slice(0, 3).map(h => {
                try { return `${new URL(h.url).hostname} (${h.domain_age_days}d)`; } catch { return `${h.domain_age_days}d`; }
              })}
            />
            <MiniCard icon={<Globe size={18} />} title="CTI Hits" desc="Any intel match (CTI + heuristics)"
              value={intelHits.length} color="blue"
              items={intelHits.slice(0, 3).map(h => {
                try { return new URL(h.url).hostname; } catch { return h.url.slice(0, 30); }
              })}
            />
          </div>
        </div>

        {/* ─────────────────────────────────────────────────────────────────────
            REMEDIATION 5A: Virtualized Scan Table
            ─────────────────────────────────────────────────────────────────────
            OLD: history.map(...) rendered ALL rows as DOM nodes.
              At 10,000 rows × ~6 td elements = 60,000 DOM nodes.
              React reconciliation on each SSE event touched every node → OOM.

            NEW: @tanstack/react-virtual calculates which rows are visible in
              the current scroll viewport and renders ONLY those (typically 10-15).
              All other rows are represented only as empty spacer divs.
              Memory usage stays constant regardless of history size.
        ──────────────────────────────────────────────────────────────────────── */}
        <div className="mt-6 bg-white/[0.03] backdrop-blur-sm border border-white/[0.06] rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-white/[0.06] flex justify-between items-center">
            <div>
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Live Scan Feed</h3>
              <p className="text-xs text-slate-600 mt-0.5">Real-time URL analysis · SSE stream</p>
            </div>
            <span className="text-xs text-slate-500">{totalScans} entries</span>
          </div>

          <VirtualScanTable
            history={history}
            loading={loading}
            selectedIdx={selectedIdx}
            onRowClick={setSelectedIdx}
          />
        </div>

        <div className="mt-8 text-center text-xs text-slate-700">
          PhishGuard v3.0 — Production-hardened ML Phishing Detection with Cyber Threat Intelligence
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtualScanTable — renders only visible rows using @tanstack/react-virtual
// ─────────────────────────────────────────────────────────────────────────────
function VirtualScanTable({ history, loading, selectedIdx, onRowClick }) {
  const parentRef = useRef(null);

  const rowVirtualizer = useVirtualizer({
    count:            history.length,
    getScrollElement: () => parentRef.current,
    estimateSize:     () => 48,         // px per row — used for spacer math
    overscan:         5,                // render 5 extra rows above/below viewport
  });

  const items = rowVirtualizer.getVirtualItems();

  return (
    // Scrollable container with fixed height — virtualizer measures this
    <div ref={parentRef} className="overflow-auto" style={{ maxHeight: 420 }}>
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : history.length === 0 ? (
        <div className="flex flex-col items-center gap-3 py-16">
          <Globe size={32} className="text-slate-700" />
          <p className="text-slate-500 text-sm">No scans recorded yet.</p>
          <p className="text-slate-600 text-xs">Browse the web with the PhishGuard extension.</p>
        </div>
      ) : (
        <table className="w-full text-left">
          <thead>
            <tr className="bg-white/[0.02] sticky top-0 z-10">
              {['Time', 'URL', 'Risk', 'Status', 'Intel', 'Latency'].map(h => (
                <th key={h} className="px-6 py-3 text-[11px] font-semibold text-slate-500 uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {/* Top spacer — represents all rows above the visible window */}
            {items.length > 0 && items[0].start > 0 && (
              <tr style={{ height: items[0].start }}>
                <td colSpan={6} />
              </tr>
            )}
            {items.map(virtualRow => {
              const scan = history[virtualRow.index];
              const isSelected = selectedIdx === virtualRow.index;
              return (
                <tr
                  key={virtualRow.index}
                  data-index={virtualRow.index}
                  ref={rowVirtualizer.measureElement}
                  onClick={() => onRowClick(isSelected ? null : virtualRow.index)}
                  className={`hover:bg-white/[0.02] transition-colors cursor-pointer ${isSelected ? 'bg-blue-500/5' : ''}`}
                >
                  <td className="px-6 py-3.5 text-xs text-slate-500 whitespace-nowrap font-mono">
                    {new Date(scan.timestamp * 1000).toLocaleTimeString()}
                  </td>
                  <td className="px-6 py-3.5 text-sm text-slate-300 max-w-[280px] truncate font-mono" title={scan.url}>
                    {scan.url}
                  </td>
                  <td className="px-6 py-3.5"><RiskBadge score={scan.risk_score} /></td>
                  <td className="px-6 py-3.5">
                    {scan.threat_intel_matches?.includes("User Bypass (One-Time)")
                      ? <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-semibold bg-orange-500/10 text-orange-400 rounded-md border border-orange-500/20"><div className="w-1.5 h-1.5 rounded-full bg-orange-400" />BYPASSED</span>
                      : scan.threat_intel_matches?.includes("User Whitelist")
                      ? <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-semibold bg-blue-500/10 text-blue-400 rounded-md border border-blue-500/20"><div className="w-1.5 h-1.5 rounded-full bg-blue-400" />WHITELISTED</span>
                      : scan.is_malicious
                      ? <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-semibold bg-red-500/10 text-red-400 rounded-md border border-red-500/20"><div className="w-1.5 h-1.5 rounded-full bg-red-400" />BLOCKED</span>
                      : <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 rounded-md border border-emerald-500/20"><div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />SAFE</span>
                    }
                  </td>
                  <td className="px-6 py-3.5">
                    <div className="flex flex-wrap gap-1">
                      {scan.threat_intel_matches?.length > 0
                        ? scan.threat_intel_matches.filter(m => !m.startsWith('User ')).map((m, j) => (
                          <span key={j} className="px-2 py-0.5 text-[10px] font-medium bg-blue-500/10 text-blue-400 rounded border border-blue-500/20">{m}</span>
                        ))
                        : <span className="text-xs text-slate-600">—</span>
                      }
                    </div>
                  </td>
                  <td className="px-6 py-3.5 text-xs text-slate-500 font-mono">
                    {scan.latency_ms?.toFixed(0)}ms
                  </td>
                </tr>
              );
            })}
            {/* Bottom spacer — represents all rows below the visible window */}
            {items.length > 0 && (
              <tr style={{ height: Math.max(0, rowVirtualizer.getTotalSize() - (items[items.length - 1]?.end || 0)) }}>
                <td colSpan={6} />
              </tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  );
}

/* ── Reusable UI components ──────────────────────────────────────────────── */

function KPICard({ icon, label, value, sub, color }) {
  const colors = {
    blue:    'from-blue-500/20 to-blue-600/5 border-blue-500/20 text-blue-400',
    emerald: 'from-emerald-500/20 to-emerald-600/5 border-emerald-500/20 text-emerald-400',
    red:     'from-red-500/20 to-red-600/5 border-red-500/20 text-red-400',
    purple:  'from-purple-500/20 to-purple-600/5 border-purple-500/20 text-purple-400',
    amber:   'from-amber-500/20 to-amber-600/5 border-amber-500/20 text-amber-400',
  };
  const c = colors[color] || colors.blue;
  return (
    <div className={`bg-gradient-to-br ${c} border rounded-2xl p-5 transition-all duration-200 hover:scale-[1.02]`}>
      <div className="flex items-center gap-2 mb-3 opacity-70">{icon}<span className="text-xs font-semibold uppercase tracking-wider">{label}</span></div>
      <div className="flex items-baseline gap-2">
        <span className="text-2xl lg:text-3xl font-bold text-white">{value}</span>
        {sub && <span className="text-sm font-medium opacity-60">{sub}</span>}
      </div>
    </div>
  );
}

function MiniCard({ icon, title, desc, value, color, items = [] }) {
  const colors = {
    amber:  'text-amber-400 bg-amber-500/10 border-amber-500/15',
    orange: 'text-orange-400 bg-orange-500/10 border-orange-500/15',
    rose:   'text-rose-400 bg-rose-500/10 border-rose-500/15',
    blue:   'text-blue-400 bg-blue-500/10 border-blue-500/15',
  };
  const c = colors[color] || colors.blue;
  return (
    <div className="bg-white/[0.03] border border-white/[0.06] rounded-2xl p-5 flex flex-col">
      <div className="flex justify-between items-start mb-3">
        <div className={`p-2 rounded-lg ${c} border`}>{icon}</div>
        <span className="text-2xl font-bold text-white">{value}</span>
      </div>
      <h4 className="text-sm font-semibold text-slate-300">{title}</h4>
      <p className="text-[11px] text-slate-600 mb-3">{desc}</p>
      {items.length > 0 && (
        <div className="mt-auto space-y-1.5">
          {items.map((item, i) => (
            <div key={i} className="text-[11px] text-slate-500 truncate font-mono bg-white/[0.02] px-2 py-1 rounded">{item}</div>
          ))}
        </div>
      )}
    </div>
  );
}

function RiskBadge({ score }) {
  const pct = (score * 100).toFixed(0);
  let bg, text, ring;
  if (pct <= 10)      { bg = 'bg-emerald-500/10'; text = 'text-emerald-400'; ring = 'ring-emerald-500/20'; }
  else if (pct <= 50) { bg = 'bg-yellow-500/10';  text = 'text-yellow-400';  ring = 'ring-yellow-500/20'; }
  else if (pct <= 80) { bg = 'bg-orange-500/10';  text = 'text-orange-400';  ring = 'ring-orange-500/20'; }
  else                { bg = 'bg-red-500/10';     text = 'text-red-400';     ring = 'ring-red-500/20'; }
  return (
    <span className={`inline-flex items-center px-2.5 py-1 text-[11px] font-bold rounded-md ring-1 ${bg} ${text} ${ring}`}>
      {pct}%
    </span>
  );
}

export default App;
