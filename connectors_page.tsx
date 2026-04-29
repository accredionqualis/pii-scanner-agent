'use client';
export const dynamic = 'force-dynamic';
import { useEffect, useState } from 'react';
import { PrivacySidebar } from '@/components/layout/PrivacySidebar';
import { Header } from '@/components/layout/Header';
import api from '@/lib/api';
import { toast } from 'sonner';
import { Plus, Trash2, TestTube, CheckCircle2, XCircle, Clock, Settings, Zap, Database, Globe, AlertTriangle, RefreshCw } from 'lucide-react';

const SYSTEM_ICONS: Record<string, string> = {
  freshservice: '🎫', zendesk: '💬', gupshup: '📱', ozonetel: '📞',
  rise_sfa: '📊', pcc_loyalty: '🏆', sap_s4hana: '🏭', iconnect_hrms: '👥', custom: '🔧',
};

const SYSTEM_COLORS: Record<string, string> = {
  freshservice: 'bg-green-50 border-green-200', zendesk: 'bg-blue-50 border-blue-200',
  gupshup: 'bg-purple-50 border-purple-200', ozonetel: 'bg-orange-50 border-orange-200',
  rise_sfa: 'bg-teal-50 border-teal-200', pcc_loyalty: 'bg-yellow-50 border-yellow-200',
  sap_s4hana: 'bg-sky-50 border-sky-200', iconnect_hrms: 'bg-pink-50 border-pink-200',
};

export default function ConnectorsPage() {
  const [connectors, setConnectors] = useState<any[]>([]);
  const [templates, setTemplates] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<any>(null);
  const [formConfig, setFormConfig] = useState<Record<string,string>>({});
  const [formName, setFormName] = useState('');
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string|null>(null);

  useEffect(() => { load(); }, []);

  const load = async () => {
    setLoading(true);
    try {
      const [cRes, tRes] = await Promise.all([
        api.get('/connectors'),
        api.get('/connectors/templates'),
      ]);
      setConnectors(cRes.data || []);
      setTemplates(tRes.data || []);
    } catch { toast.error('Failed to load connectors'); }
    finally { setLoading(false); }
  };

  const save = async () => {
    if (!selectedTemplate) return;
    setSaving(true);
    try {
      await api.post('/connectors', {
        system_type: selectedTemplate.system_type,
        name: formName || selectedTemplate.name,
        config: formConfig,
      });
      toast.success('Connector added');
      setShowForm(false); setSelectedTemplate(null); setFormConfig({}); setFormName('');
      load();
    } catch { toast.error('Failed to add connector'); }
    finally { setSaving(false); }
  };

  const testConn = async (id: string) => {
    setTesting(id);
    try {
      const r = await api.post(`/connectors/${id}/test`, {});
      const status = r.data.status;
      if (status === 'success') toast.success(r.data.message);
      else toast.error(r.data.message);
      load();
    } catch { toast.error('Test failed'); }
    finally { setTesting(null); }
  };

  const deleteConn = async (id: string) => {
    if (!confirm('Remove this connector?')) return;
    try { await api.delete(`/connectors/${id}`); toast.success('Removed'); load(); }
    catch { toast.error('Failed to remove'); }
  };

  const statusIcon = (s: string) => {
    if (s === 'success') return <CheckCircle2 className="w-4 h-4 text-green-500"/>;
    if (s === 'failed') return <XCircle className="w-4 h-4 text-red-500"/>;
    return <Clock className="w-4 h-4 text-gray-400"/>;
  };

  const capBadge = (label: string, enabled: boolean) => (
    <span className={`text-xs px-2 py-0.5 rounded-full ${enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-400'}`}>
      {enabled ? '✓' : '✗'} {label}
    </span>
  );

  return (
    <div className="min-h-screen bg-gray-50">
      <PrivacySidebar />
      <main className="ml-64 min-h-screen">
        <Header title="Data Source Connectors" subtitle="Connect external systems for Consent Management and Data Subject Rights automation"/>
        <div className="p-6 space-y-5">

          {/* Stats */}
          <div className="grid grid-cols-4 gap-4">
            {[
              { l: 'Total Connectors', v: connectors.length, c: 'text-gray-700' },
              { l: 'Active', v: connectors.filter(c=>c.is_active).length, c: 'text-green-700' },
              { l: 'Consent Push', v: connectors.filter(c=>c.supports_consent_push).length, c: 'text-blue-700' },
              { l: 'DSR Enabled', v: connectors.filter(c=>c.supports_dsr_access).length, c: 'text-purple-700' },
            ].map(s => (
              <div key={s.l} className="bg-white rounded-xl border p-4 shadow-sm">
                <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">{s.l}</p>
                <p className={`text-3xl font-bold ${s.c}`}>{s.v}</p>
              </div>
            ))}
          </div>

          {/* Add connector button */}
          <div className="flex justify-between items-center">
            <h2 className="font-semibold text-gray-900">Configured Connectors</h2>
            <button onClick={() => setShowForm(true)} className="flex items-center gap-2 bg-purple-700 text-white px-4 py-2 rounded-lg text-sm hover:bg-purple-800">
              <Plus className="w-4 h-4"/>Add Connector
            </button>
          </div>

          {/* Connector list */}
          {loading ? <div className="text-center py-12 text-gray-400">Loading...</div> : (
            <div className="grid grid-cols-2 gap-4">
              {connectors.length === 0 && (
                <div className="col-span-2 text-center py-12 bg-white rounded-xl border">
                  <p className="text-gray-400 text-sm">No connectors configured yet. Add your first system.</p>
                </div>
              )}
              {connectors.map(conn => (
                <div key={conn.id} className={`bg-white rounded-xl border-2 p-4 shadow-sm ${SYSTEM_COLORS[conn.system_type] || 'bg-gray-50 border-gray-200'}`}>
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <span className="text-2xl">{SYSTEM_ICONS[conn.system_type] || '🔧'}</span>
                      <div>
                        <h3 className="font-semibold text-gray-900 text-sm">{conn.name}</h3>
                        <p className="text-xs text-gray-400 capitalize">{conn.connection_type.replace('_',' ')} · {conn.system_type.replace(/_/g,' ')}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      {statusIcon(conn.last_test_status)}
                      <span className={`text-xs px-2 py-0.5 rounded-full ${conn.is_active ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
                        {conn.is_active ? 'Active' : 'Disabled'}
                      </span>
                    </div>
                  </div>

                  {/* Capabilities */}
                  <div className="flex flex-wrap gap-1 mb-3">
                    {capBadge('Consent', conn.supports_consent_push)}
                    {capBadge('Access', conn.supports_dsr_access)}
                    {capBadge('Erasure', conn.supports_dsr_erasure)}
                    {capBadge('Portability', conn.supports_dsr_portability)}
                  </div>

                  {/* Last test */}
                  {conn.last_tested_at && (
                    <p className="text-xs text-gray-400 mb-3">
                      Last tested: {new Date(conn.last_tested_at).toLocaleString()} —{' '}
                      <span className={conn.last_test_status === 'success' ? 'text-green-600' : 'text-red-500'}>{conn.last_test_message}</span>
                    </p>
                  )}

                  {/* Actions */}
                  <div className="flex gap-2">
                    <button onClick={() => testConn(conn.id)} disabled={testing === conn.id}
                      className="flex items-center gap-1 text-xs border border-blue-200 text-blue-700 px-3 py-1.5 rounded-lg hover:bg-blue-50 disabled:opacity-50">
                      {testing === conn.id ? <RefreshCw className="w-3 h-3 animate-spin"/> : <TestTube className="w-3 h-3"/>}
                      Test
                    </button>
                    <button onClick={() => deleteConn(conn.id)}
                      className="flex items-center gap-1 text-xs border border-red-200 text-red-700 px-3 py-1.5 rounded-lg hover:bg-red-50">
                      <Trash2 className="w-3 h-3"/>Remove
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Add connector modal */}
          {showForm && (
            <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
              <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg p-6">
                <h2 className="font-bold text-gray-900 mb-4">Add Data Source Connector</h2>

                {!selectedTemplate ? (
                  <div className="grid grid-cols-2 gap-3 max-h-96 overflow-y-auto">
                    {templates.map(t => (
                      <button key={t.system_type} onClick={() => { setSelectedTemplate(t); setFormName(t.name); }}
                        className="flex items-center gap-3 p-3 border-2 rounded-xl hover:border-purple-400 hover:bg-purple-50 text-left">
                        <span className="text-2xl">{SYSTEM_ICONS[t.system_type] || '🔧'}</span>
                        <div>
                          <p className="font-medium text-sm">{t.name}</p>
                          <p className="text-xs text-gray-400 capitalize">{t.connection_type.replace('_',' ')}</p>
                        </div>
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="flex items-center gap-3 p-3 bg-purple-50 rounded-xl mb-4">
                      <span className="text-2xl">{SYSTEM_ICONS[selectedTemplate.system_type]}</span>
                      <div>
                        <p className="font-medium">{selectedTemplate.name}</p>
                        <p className="text-xs text-gray-500 capitalize">{selectedTemplate.connection_type.replace('_',' ')}</p>
                      </div>
                    </div>

                    <div>
                      <label className="text-xs font-medium text-gray-600">Display Name</label>
                      <input value={formName} onChange={e => setFormName(e.target.value)}
                        className="w-full border rounded-lg px-3 py-2 text-sm mt-1" placeholder={selectedTemplate.name}/>
                    </div>

                    {selectedTemplate.config_fields?.map((field: string) => (
                      <div key={field}>
                        <label className="text-xs font-medium text-gray-600 capitalize">{field.replace(/_/g,' ')}</label>
                        <input type={field.includes('password') || field.includes('token') || field.includes('key') ? 'password' : 'text'}
                          value={formConfig[field] || ''} onChange={e => setFormConfig(p => ({...p, [field]: e.target.value}))}
                          className="w-full border rounded-lg px-3 py-2 text-sm mt-1" placeholder={field.replace(/_/g,' ')}/>
                      </div>
                    ))}

                    {(selectedTemplate.system_type === 'sap_s4hana' || selectedTemplate.system_type === 'iconnect_hrms') && (
                      <div className="flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-lg p-3 text-xs text-amber-700">
                        <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0"/>
                        <p>DB connectors require network access from this server to your database host. Credentials are stored encrypted. DSR actions for this system will require manual processing with task assignments.</p>
                      </div>
                    )}
                  </div>
                )}

                <div className="flex gap-3 mt-6">
                  {selectedTemplate && <button onClick={() => setSelectedTemplate(null)} className="px-4 py-2 text-sm text-gray-500 hover:bg-gray-100 rounded-lg">← Back</button>}
                  <button onClick={() => { setShowForm(false); setSelectedTemplate(null); setFormConfig({}); }} className="px-4 py-2 text-sm text-gray-500 hover:bg-gray-100 rounded-lg ml-auto">Cancel</button>
                  {selectedTemplate && <button onClick={save} disabled={saving} className="px-4 py-2 text-sm bg-purple-700 text-white rounded-lg hover:bg-purple-800 disabled:opacity-50">
                    {saving ? 'Saving...' : 'Add Connector'}
                  </button>}
                </div>
              </div>
            </div>
          )}

        </div>
      </main>
    </div>
  );
}
