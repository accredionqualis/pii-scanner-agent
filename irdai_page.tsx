'use client';
export const dynamic = 'force-dynamic';
import { useEffect, useState } from 'react';
import { SmartSidebar as Sidebar } from '@/components/layout/SmartSidebar';
import { Header } from '@/components/layout/Header';
import api from '@/lib/api';
import { getUser } from '@/lib/auth';
import { toast } from 'sonner';
import { Shield, Download, ChevronDown, ChevronRight, CheckCircle2, AlertTriangle, XCircle, Info } from 'lucide-react';

const AREAS = [
  { code:'DE.AE', name:'Anomalies and Events', total:1 },
  { code:'DE.CM', name:'Security Continuous Monitoring & Detection', total:100 },
  { code:'DE.DP', name:'Detection Processes', total:3 },
  { code:'ID.AM', name:'Asset Management', total:10 },
  { code:'ID.BE', name:'Business Environment', total:4 },
  { code:'ID.GV', name:'Governance', total:19 },
  { code:'ID.RA', name:'Risk Assessment', total:4 },
  { code:'ID.RM', name:'Risk Management', total:2 },
  { code:'ID.SC', name:'Supply Chain Risk Management', total:8 },
  { code:'PR.AC', name:'Identity Mgmt Authentication and Access Control', total:15 },
  { code:'PR.AT', name:'Awareness and Training', total:10 },
  { code:'PR.DS', name:'Data Security', total:14 },
  { code:'PR.IP', name:'Information Protection Processes and Procedures', total:19 },
  { code:'PR.MA', name:'Maintenance', total:7 },
  { code:'PR.PT', name:'Protective Technology', total:7 },
  { code:'RC.CO', name:'Communications (Recovery)', total:1 },
  { code:'RC.IM', name:'Improvements (Recovery)', total:2 },
  { code:'RC.RP', name:'Recovery Planning', total:1 },
  { code:'RS.AN', name:'Analysis (Response)', total:4 },
  { code:'RS.CO', name:'Communications (Response)', total:7 },
  { code:'RS.IM', name:'Improvements (Response)', total:4 },
  { code:'RS.MI', name:'Mitigation', total:3 },
  { code:'RS.RP', name:'Response Planning', total:15 },
  { code:'WFRL', name:'Work From Remote Location', total:50 },
  { code:'WFRL.IN', name:'Work From Remote Location Investment', total:24 },
  { code:'IGDM', name:'IT Intermediary Guidelines and Digital Media', total:13 },
];

type ControlStatus = {
  controlId: string;
  code: string;
  title: string;
  na: boolean;
  h: boolean;
  m: boolean;
  l: boolean;
  c: boolean;
  comments: string;
};

export default function IrdaiPage() {
  const user = getUser();
  const [domains, setDomains] = useState<any[]>([]);
  const [controls, setControls] = useState<any[]>([]);
  const [statuses, setStatuses] = useState<Record<string, ControlStatus>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [activeTab, setActiveTab] = useState<'summary' | 'details'>('summary');

  useEffect(() => { load(); }, []);

  const load = async () => {
    setLoading(true);
    try {
      // Load IRDAI domains and controls
      const [dRes, cRes] = await Promise.all([
        api.get('/domains?portal=security&framework=IRDAI_CSF').catch(() => ({ data: [] })),
        api.get('/controls?framework=IRDAI_CSF&limit=500').catch(() => ({ data: { data: [] } })),
      ]);
      setDomains(dRes.data || []);
      const ctrlData = cRes.data?.data || cRes.data || [];
      setControls(ctrlData);

      // Load saved statuses from localStorage
      const saved = localStorage.getItem(`irdai_status_${user?.tenantId}`);
      if (saved) setStatuses(JSON.parse(saved));
    } catch (e) {
      toast.error('Failed to load IRDAI data');
    } finally {
      setLoading(false);
    }
  };

  const updateStatus = (ctrlId: string, field: keyof ControlStatus, value: any) => {
    setStatuses(prev => {
      const updated = { ...prev, [ctrlId]: { ...(prev[ctrlId] || { controlId: ctrlId, na: false, h: false, m: false, l: false, c: false, comments: '' }), [field]: value } };
      localStorage.setItem(`irdai_status_${user?.tenantId}`, JSON.stringify(updated));
      return updated;
    });
  };

  // Calculate area stats
  const getAreaStats = (areaCode: string) => {
    const areaControls = controls.filter(c => c.code?.includes(`.${areaCode}.`));
    const total = AREAS.find(a => a.code === areaCode)?.total || areaControls.length;
    let na = 0, h = 0, m = 0, l = 0, c = 0, ac = 0;
    areaControls.forEach(ctrl => {
      const s = statuses[ctrl.id];
      if (!s) return;
      if (s.na) na++;
      else { ac++; if (s.h) h++; if (s.m) m++; if (s.l) l++; if (s.c) c++; }
    });
    const riskMark = h * 3 + m * 2 + l * 1;
    return { total, na, ac: total - na, h, m, l, c, riskMark };
  };

  const totals = AREAS.reduce((acc, area) => {
    const s = getAreaStats(area.code);
    return { total: acc.total + s.total, na: acc.na + s.na, ac: acc.ac + s.ac, h: acc.h + s.h, m: acc.m + s.m, l: acc.l + s.l, c: acc.c + s.c, riskMark: acc.riskMark + s.riskMark };
  }, { total: 347, na: 0, ac: 0, h: 0, m: 0, l: 0, c: 0, riskMark: 0 });

  const exportCsv = () => {
    const rows = [['Area Code', 'Area', 'Total Controls', 'NA', 'AC', 'H', 'M', 'L', 'C', 'Risk Mark']];
    AREAS.forEach(area => {
      const s = getAreaStats(area.code);
      rows.push([area.code, area.name, s.total, s.na, s.ac, s.h, s.m, s.l, s.c, s.riskMark].map(String));
    });
    rows.push(['', 'TOTAL', totals.total, totals.na, totals.ac, totals.h, totals.m, totals.l, totals.c, totals.riskMark].map(String));
    const csv = rows.map(r => r.join(',')).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = `IRDAI_CSF_Status_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
  };

  const riskColor = (mark: number) => mark === 0 ? 'text-green-600' : mark <= 5 ? 'text-yellow-600' : mark <= 15 ? 'text-orange-600' : 'text-red-600';
  const riskBg = (mark: number) => mark === 0 ? 'bg-green-50' : mark <= 5 ? 'bg-yellow-50' : mark <= 15 ? 'bg-orange-50' : 'bg-red-50';

  return (
    <div className="min-h-screen bg-gray-50">
      <Sidebar />
      <main className="ml-64 min-h-screen">
        <Header title="IRDAI Cyber Security Framework" subtitle="Annexure III — Audit Status & Compliance Dashboard" />
        <div className="p-6 space-y-5">

          {/* Summary KPIs */}
          <div className="grid grid-cols-5 gap-4">
            {[
              { l: 'Total Controls', v: totals.total, c: 'text-gray-700', bg: 'bg-white' },
              { l: 'High Risk', v: totals.h, c: 'text-red-700', bg: 'bg-red-50' },
              { l: 'Medium Risk', v: totals.m, c: 'text-orange-700', bg: 'bg-orange-50' },
              { l: 'Low Risk', v: totals.l, c: 'text-yellow-700', bg: 'bg-yellow-50' },
              { l: 'Complied', v: totals.c, c: 'text-green-700', bg: 'bg-green-50' },
            ].map(s => (
              <div key={s.l} className={`${s.bg} rounded-xl border p-4 shadow-sm`}>
                <p className="text-xs text-gray-400 font-medium uppercase tracking-wide mb-1">{s.l}</p>
                <p className={`text-3xl font-bold ${s.c}`}>{s.v}</p>
              </div>
            ))}
          </div>

          {/* Tabs */}
          <div className="flex items-center justify-between">
            <div className="flex gap-1 bg-white border rounded-lg p-1">
              {(['summary', 'details'] as const).map(t => (
                <button key={t} onClick={() => setActiveTab(t)}
                  className={'px-4 py-1.5 rounded-md text-xs font-medium capitalize ' + (activeTab === t ? 'bg-blue-800 text-white' : 'text-gray-500 hover:bg-gray-100')}>
                  {t === 'summary' ? '📊 Annexure III Summary' : '📋 Control Details'}
                </button>
              ))}
            </div>
            <button onClick={exportCsv} className="flex items-center gap-2 border text-gray-700 px-4 py-2 rounded-lg text-sm hover:bg-gray-50">
              <Download className="w-4 h-4" />Export CSV
            </button>
          </div>

          {/* Summary Table — Annexure III format */}
          {activeTab === 'summary' && (
            <div className="bg-white rounded-xl border shadow-sm overflow-hidden">
              <div className="p-4 border-b bg-blue-900 text-white">
                <h2 className="font-bold text-sm">Part B — Overall Status of Findings</h2>
                <p className="text-xs text-blue-200 mt-1">Note: NA=Not Applicable, AC=Applicable Controls, H=High, M=Medium, L=Low, C=Complied, Risk Mark = Hx3+Mx2+Lx1+Cx0</p>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs border-collapse">
                  <thead>
                    <tr className="bg-gray-100">
                      <th className="border border-gray-300 px-3 py-2 text-left font-bold">Area Code</th>
                      <th className="border border-gray-300 px-3 py-2 text-left font-bold">Area</th>
                      <th className="border border-gray-300 px-3 py-2 text-center font-bold">No. of Controls (A)</th>
                      <th className="border border-gray-300 px-3 py-2 text-center font-bold">NA (B)</th>
                      <th className="border border-gray-300 px-3 py-2 text-center font-bold">AC (C=A-B)</th>
                      <th className="border border-gray-300 px-3 py-2 text-center font-bold bg-red-50">H</th>
                      <th className="border border-gray-300 px-3 py-2 text-center font-bold bg-orange-50">M</th>
                      <th className="border border-gray-300 px-3 py-2 text-center font-bold bg-yellow-50">L</th>
                      <th className="border border-gray-300 px-3 py-2 text-center font-bold bg-green-50">C</th>
                      <th className="border border-gray-300 px-3 py-2 text-center font-bold">Risk Mark</th>
                    </tr>
                  </thead>
                  <tbody>
                    {AREAS.map((area, i) => {
                      const s = getAreaStats(area.code);
                      return (
                        <tr key={area.code} className={i % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                          <td className="border border-gray-300 px-3 py-2 font-mono font-bold text-blue-800">{area.code}</td>
                          <td className="border border-gray-300 px-3 py-2">{area.name}</td>
                          <td className="border border-gray-300 px-3 py-2 text-center font-bold">{s.total}</td>
                          <td className="border border-gray-300 px-3 py-2 text-center">{s.na || ''}</td>
                          <td className="border border-gray-300 px-3 py-2 text-center">{s.ac || ''}</td>
                          <td className="border border-gray-300 px-3 py-2 text-center bg-red-50 font-bold text-red-700">{s.h || ''}</td>
                          <td className="border border-gray-300 px-3 py-2 text-center bg-orange-50 font-bold text-orange-700">{s.m || ''}</td>
                          <td className="border border-gray-300 px-3 py-2 text-center bg-yellow-50 font-bold text-yellow-700">{s.l || ''}</td>
                          <td className="border border-gray-300 px-3 py-2 text-center bg-green-50 font-bold text-green-700">{s.c || ''}</td>
                          <td className={`border border-gray-300 px-3 py-2 text-center font-bold ${riskColor(s.riskMark)} ${riskBg(s.riskMark)}`}>{s.riskMark || ''}</td>
                        </tr>
                      );
                    })}
                    <tr className="bg-blue-900 text-white font-bold">
                      <td className="border border-blue-700 px-3 py-2" colSpan={2}>TOTAL</td>
                      <td className="border border-blue-700 px-3 py-2 text-center">{totals.total}</td>
                      <td className="border border-blue-700 px-3 py-2 text-center">{totals.na || ''}</td>
                      <td className="border border-blue-700 px-3 py-2 text-center">{totals.ac || ''}</td>
                      <td className="border border-blue-700 px-3 py-2 text-center">{totals.h || ''}</td>
                      <td className="border border-blue-700 px-3 py-2 text-center">{totals.m || ''}</td>
                      <td className="border border-blue-700 px-3 py-2 text-center">{totals.l || ''}</td>
                      <td className="border border-blue-700 px-3 py-2 text-center">{totals.c || ''}</td>
                      <td className="border border-blue-700 px-3 py-2 text-center">{totals.riskMark || ''}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Detail view — all controls */}
          {activeTab === 'details' && (
            <div className="space-y-3">
              {AREAS.map(area => {
                const areaControls = controls.filter(c => c.code?.includes(`.${area.code}.`));
                const s = getAreaStats(area.code);
                const isOpen = expanded[area.code];
                return (
                  <div key={area.code} className="bg-white rounded-xl border shadow-sm overflow-hidden">
                    <button className="w-full flex items-center justify-between p-4 hover:bg-gray-50" onClick={() => setExpanded(prev => ({ ...prev, [area.code]: !prev[area.code] }))}>
                      <div className="flex items-center gap-3">
                        {isOpen ? <ChevronDown className="w-4 h-4 text-gray-400" /> : <ChevronRight className="w-4 h-4 text-gray-400" />}
                        <span className="font-mono font-bold text-blue-800 text-sm">{area.code}</span>
                        <span className="text-sm font-medium">{area.name}</span>
                        <span className="text-xs text-gray-400">({area.total} controls)</span>
                      </div>
                      <div className="flex items-center gap-4 text-xs">
                        {s.h > 0 && <span className="bg-red-100 text-red-700 px-2 py-0.5 rounded font-bold">H:{s.h}</span>}
                        {s.m > 0 && <span className="bg-orange-100 text-orange-700 px-2 py-0.5 rounded font-bold">M:{s.m}</span>}
                        {s.l > 0 && <span className="bg-yellow-100 text-yellow-700 px-2 py-0.5 rounded font-bold">L:{s.l}</span>}
                        {s.c > 0 && <span className="bg-green-100 text-green-700 px-2 py-0.5 rounded font-bold">C:{s.c}</span>}
                        {s.riskMark > 0 && <span className={`px-2 py-0.5 rounded font-bold ${riskColor(s.riskMark)} ${riskBg(s.riskMark)}`}>Risk:{s.riskMark}</span>}
                      </div>
                    </button>
                    {isOpen && (
                      <div className="border-t">
                        <table className="w-full text-xs border-collapse">
                          <thead>
                            <tr className="bg-gray-50">
                              <th className="border-b border-r border-gray-200 px-3 py-2 text-left w-16">No.</th>
                              <th className="border-b border-r border-gray-200 px-3 py-2 text-left">Audit Questionnaire</th>
                              <th className="border-b border-r border-gray-200 px-3 py-2 text-center w-12">NA</th>
                              <th className="border-b border-r border-gray-200 px-3 py-2 text-center w-12 bg-red-50">H</th>
                              <th className="border-b border-r border-gray-200 px-3 py-2 text-center w-12 bg-orange-50">M</th>
                              <th className="border-b border-r border-gray-200 px-3 py-2 text-center w-12 bg-yellow-50">L</th>
                              <th className="border-b border-r border-gray-200 px-3 py-2 text-center w-12 bg-green-50">C</th>
                              <th className="border-b border-gray-200 px-3 py-2 text-left">Comments / Reason</th>
                            </tr>
                          </thead>
                          <tbody>
                            {areaControls.map((ctrl, i) => {
                              const s = statuses[ctrl.id] || { na: false, h: false, m: false, l: false, c: false, comments: '' };
                              return (
                                <tr key={ctrl.id} className={i % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                                  <td className="border-b border-r border-gray-200 px-3 py-2 text-gray-500 font-mono">{ctrl.code?.split('.').pop()}</td>
                                  <td className="border-b border-r border-gray-200 px-3 py-2 text-gray-700 max-w-md">{ctrl.title}</td>
                                  {(['na', 'h', 'm', 'l', 'c'] as const).map(f => (
                                    <td key={f} className={`border-b border-r border-gray-200 px-3 py-2 text-center ${f === 'h' ? 'bg-red-50' : f === 'm' ? 'bg-orange-50' : f === 'l' ? 'bg-yellow-50' : f === 'c' ? 'bg-green-50' : ''}`}>
                                      <input type="checkbox" checked={!!s[f]} onChange={e => updateStatus(ctrl.id, f, e.target.checked)}
                                        className="w-4 h-4 rounded cursor-pointer" />
                                    </td>
                                  ))}
                                  <td className="border-b border-gray-200 px-2 py-1">
                                    <input type="text" value={s.comments || ''} onChange={e => updateStatus(ctrl.id, 'comments', e.target.value)}
                                      placeholder="Add observation..." className="w-full text-xs border-0 bg-transparent outline-none focus:bg-white focus:border focus:border-blue-300 rounded px-1 py-0.5" />
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

        </div>
      </main>
    </div>
  );
}
