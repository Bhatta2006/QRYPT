import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../lib/api';
import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

const AlertsFeed = () => {
  const { data } = useQuery({
    queryKey: ['alerts'],
    queryFn: () => apiClient.getAdminAlerts(),
    refetchInterval: 30000,
  });

  if (!data) return <div>Loading alerts...</div>;

  return (
    <div className="flex flex-col gap-2 max-h-96 overflow-y-auto">
      {data.items.map((alert: any, i: number) => (
        <div key={i} className="flex flex-col border p-3 rounded bg-slate-50 text-sm shadow-sm gap-2">
          <div className="flex justify-between items-center text-slate-500 text-xs">
            <span>{new Date(alert.timestamp).toLocaleString()}</span>
            <span className="font-mono">{alert.trace_id.slice(-8)}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="font-bold">{alert.trigger}</span>
          </div>
          <div className="w-full bg-slate-200 rounded-full h-1.5 mt-1">
             <div className="bg-red-500 h-1.5 rounded-full" style={{ width: `${alert.severity * 100}%` }}></div>
          </div>
        </div>
      ))}
    </div>
  );
};

const Heatmap = ({ traceId }: { traceId: string }) => {
  const { data } = useQuery({
    queryKey: ['heatmap', traceId],
    queryFn: () => apiClient.getScanHeatmap(traceId),
  });

  if (!data) return <div>Loading heatmap...</div>;

  // Render chart
  const chartData = {
    labels: data.items.map((_: any, i: number) => i),
    datasets: [
      {
        label: 'Scans',
        data: data.items.map((d: any) => d.count),
        backgroundColor: data.items.map((d: any) => {
          if (d.count < 10) return 'rgba(34, 197, 94, 0.8)'; // green
          if (d.count <= 50) return 'rgba(245, 158, 11, 0.8)'; // amber
          return 'rgba(220, 38, 38, 0.8)'; // red
        }),
      }
    ]
  };

  return <Bar data={chartData} options={{ responsive: true }} />;
};

const Admin = () => {
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [searchPrefix, setSearchPrefix] = useState('');
  const [selectedTraceId, setSelectedTraceId] = useState<string | null>(null);

  const queryClient = useQueryClient();

  // For Admin, it sees all tokens. We just use limit: 1000 for simplicity or fetch properly based on requirement. 
  const { data } = useQuery({
    queryKey: ['admin-tokens'],
    queryFn: () => apiClient.listTokens(undefined, 1000), 
  });

  const tokens = data?.items || [];
  
  const filteredTokens = tokens.filter((t: any) => 
    (filterStatus === 'ALL' || t.status === filterStatus) &&
    (searchPrefix === '' || t.trace_id.startsWith(searchPrefix))
  );

  const handleAction = async (traceId: string, action: string) => {
    if (action === 'REVOKE') await apiClient.revokeToken(traceId);
    if (action === 'UNBLOCK') await apiClient.unblockToken(traceId);
    queryClient.invalidateQueries({ queryKey: ['admin-tokens'] });
  };

  return (
    <div className="p-6 max-w-7xl mx-auto flex flex-col h-screen">
      <h1 className="text-3xl font-bold mb-6">Security Admin</h1>
      
      <div className="flex gap-6 h-full min-h-0">
        {/* Token Table */}
        <div className="w-2/3 flex flex-col bg-white border rounded shadow-sm">
          <div className="p-4 border-b flex gap-4">
             <input type="text" placeholder="Search prefix..." className="border rounded px-2 w-48 text-sm" value={searchPrefix} onChange={e => setSearchPrefix(e.target.value)} />
             <select className="border rounded px-2 text-sm" value={filterStatus} onChange={e => setFilterStatus(e.target.value)}>
                <option value="ALL">All Status</option>
                <option value="ACTIVE">Active</option>
                <option value="SUSPICIOUS">Suspicious</option>
                <option value="BLOCKED">Blocked</option>
             </select>
          </div>
          <div className="flex-1 overflow-y-auto">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-slate-50 border-b">
                <tr>
                  <th className="px-4 py-2 font-medium text-slate-500">Trace ID</th>
                  <th className="px-4 py-2 font-medium text-slate-500">Issuer</th>
                  <th className="px-4 py-2 font-medium text-slate-500">Status</th>
                  <th className="px-4 py-2 font-medium text-slate-500">Created</th>
                  <th className="px-4 py-2 font-medium text-slate-500">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredTokens.map((t: any) => (
                  <tr key={t.trace_id} className="border-b hover:bg-slate-50 cursor-pointer" onClick={() => setSelectedTraceId(t.trace_id)}>
                     <td className="px-4 py-2 font-mono">{t.trace_id.slice(-8)}</td>
                     <td className="px-4 py-2">{t.issuer_display_name}</td>
                     <td className="px-4 py-2">
                       <span className={`px-2 py-1 rounded text-xs text-white font-medium
                        ${t.status === 'ACTIVE' ? 'bg-green-600' : t.status === 'SUSPICIOUS' ? 'bg-amber-500' : 'bg-red-600'}`}>
                        {t.status}
                       </span>
                     </td>
                     <td className="px-4 py-2">{new Date(t.created_at).toLocaleDateString()}</td>
                     <td className="px-4 py-2 flex gap-2">
                       {(t.status === 'ACTIVE' || t.status === 'SUSPICIOUS') && 
                         <button onClick={(e) => { e.stopPropagation(); handleAction(t.trace_id, 'REVOKE'); }} className="text-red-600 hover:underline">Revoke</button>}
                       {t.status === 'BLOCKED' && 
                         <button onClick={(e) => { e.stopPropagation(); handleAction(t.trace_id, 'UNBLOCK'); }} className="text-green-600 hover:underline">Unblock</button>}
                     </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Panel: Event Feed & Analytics */}
        <div className="w-1/3 flex flex-col gap-6">
           <div className="bg-white border rounded shadow-sm p-4">
              <h2 className="text-lg font-bold mb-4">Live Alerts</h2>
              <AlertsFeed />
           </div>

           {selectedTraceId && (
             <div className="bg-white border rounded shadow-sm p-4 flex-1">
                <h2 className="text-lg font-bold mb-4">Heatmap (7d)</h2>
                <div className="text-xs font-mono mb-2 text-slate-500">{selectedTraceId}</div>
                <Heatmap traceId={selectedTraceId} />
             </div>
           )}
        </div>
      </div>
    </div>
  );
};

export default Admin;
