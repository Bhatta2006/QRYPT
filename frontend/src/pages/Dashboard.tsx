import React, { useEffect, useRef, useState } from 'react';
import { useInfiniteQuery, useQueryClient } from '@tanstack/react-query';
import { useVirtualizer } from '@tanstack/react-virtual';
import { fetchEventSource } from '@microsoft/fetch-event-source';
import { apiClient, getAccessToken, setAccessToken } from '../lib/api';

/*
 * SSE Approach Documentation:
 * Decided to use @microsoft/fetch-event-source instead of an SSE token endpoint.
 * This approach natively supports sending standard HTTP headers (like Authorization: Bearer <token>)
 * over the SSE connection initialization, avoiding backend complexity with temporary query-param tokens.
 */
function useRevocationStream() {
  const queryClient = useQueryClient();
  
  useEffect(() => {
    let ctrl = new AbortController();
    let lastEventId = '';
    let retryDelay = 1000;
    
    function connect() {
      const token = getAccessToken();
      if (!token) return;
      
      fetchEventSource('/api/v1/events/stream', {
        headers: {
          'Authorization': `Bearer ${token}`,
          ...(lastEventId ? { 'Last-Event-Id': lastEventId } : {})
        },
        signal: ctrl.signal,
        async onopen(response) {
          if (response.ok) {
            retryDelay = 1000;
          } else {
            throw new Error('Connection failed');
          }
        },
        onmessage(msg) {
          if (msg.id) lastEventId = msg.id;
          if (msg.event === 'revocation' || msg.data) {
            try {
              const data = JSON.parse(msg.data);
              // Optimistically update Tanstack query cache
              queryClient.setQueryData(['tokens'], (oldData: any) => {
                if (!oldData) return oldData;
                return {
                  ...oldData,
                  pages: oldData.pages.map((page: any) => ({
                    ...page,
                    items: page.items.map((token: any) => 
                      token.trace_id === data.trace_id ? { ...token, status: 'BLOCKED' } : token
                    )
                  }))
                };
              });

              // Broadcast update for Offline Service Worker caching SW.ts
              if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
                navigator.serviceWorker.controller.postMessage({
                  type: 'SYNC_REVOCATION',
                  payload: { trace_id: data.trace_id, action: 'BLOCKED' }
                });
              }

            } catch (e) {}
          }
        },
        onclose() {
          throw new Error('Server closed connection');
        },
        onerror(err) {
          console.error('SSE Error:', err);
          retryDelay = Math.min(retryDelay * 2, 30000); 
          setTimeout(() => {
            if (!ctrl.signal.aborted) connect();
          }, retryDelay);
          throw err; 
        }
      });
    }
    
    connect();
    
    // E2E Test Mock Override
    const e2eHandler = (e: any) => {
      const data = e.detail;
      queryClient.setQueryData(['tokens'], (oldData: any) => {
        if (!oldData) return oldData;
        return {
          ...oldData,
          pages: oldData.pages.map((page: any) => ({
            ...page,
            items: page.items.map((token: any) => 
              token.trace_id === data.trace_id ? { ...token, status: 'BLOCKED' } : token
            )
          }))
        };
      });
    };
    window.addEventListener('test:sse', e2eHandler);

    return () => {
      ctrl.abort();
      window.removeEventListener('test:sse', e2eHandler);
    };
  }, [queryClient]);
}

const Dashboard = () => {
  const [isLoggedIn, setIsLoggedIn] = useState(!!getAccessToken());
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [generateOpen, setGenerateOpen] = useState(false);
  const idempotencyKeyRef = useRef<string>('');
  
  const [payloadUrl, setPayloadUrl] = useState('');
  const [ttlSeconds, setTtlSeconds] = useState<number>(3600);
  const [qrCode, setQrCode] = useState<{b64: string, traceId: string} | null>(null);

  const queryClient = useQueryClient();

  useEffect(() => {
    const onLogout = () => setIsLoggedIn(false);
    window.addEventListener('auth:logout', onLogout);
    return () => window.removeEventListener('auth:logout', onLogout);
  }, []);

  useRevocationStream();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiClient.login({ username: email, password });
      setAccessToken(res.access_token);
      setIsLoggedIn(true);
    } catch (e) {
      alert('Login failed');
    }
  };

  const { data, fetchNextPage, hasNextPage, isFetchingNextPage } = useInfiniteQuery({
    queryKey: ['tokens'],
    queryFn: ({ pageParam }) => apiClient.listTokens(pageParam, 50),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor || undefined,
    enabled: isLoggedIn,
  });

  const allItems = data ? data.pages.flatMap(d => d.items) : [];
  const parentRef = useRef<HTMLDivElement>(null);
  
  const rowVirtualizer = useVirtualizer({
    count: hasNextPage ? allItems.length + 1 : allItems.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 64,
    overscan: 5,
  });

  useEffect(() => {
    const [lastItem] = rowVirtualizer.getVirtualItems().slice(-1);
    if (!lastItem) return;
    if (lastItem.index >= allItems.length - 1 && hasNextPage && !isFetchingNextPage) {
      fetchNextPage();
    }
  }, [hasNextPage, fetchNextPage, allItems.length, isFetchingNextPage, rowVirtualizer.getVirtualItems()]);

  const handleOpenGenerate = () => {
    idempotencyKeyRef.current = crypto.randomUUID();
    setPayloadUrl('');
    setTtlSeconds(3600);
    setQrCode(null);
    setGenerateOpen(true);
  };

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!payloadUrl.startsWith('https://')) {
      alert('Must be HTTPS URL');
      return;
    }
    try {
      const res = await apiClient.generateToken(idempotencyKeyRef.current, payloadUrl, ttlSeconds);
      setQrCode({ b64: res.qr_png_b64, traceId: res.trace_id });
      queryClient.invalidateQueries({ queryKey: ['tokens'] });
    } catch (e) {
      alert('Generation failed');
    }
  };

  const handleRevoke = async (traceId: string) => {
    if (confirm('Are you sure you want to revoke this token?')) {
      await apiClient.revokeToken(traceId);
      queryClient.invalidateQueries({ queryKey: ['tokens'] });
    }
  };

  if (!isLoggedIn) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <form onSubmit={handleLogin} className="w-96 rounded shadow-lg p-6 bg-white border">
          <h2 className="mb-4 text-2xl font-bold">Issuer Login</h2>
          <input type="email" placeholder="Email" className="w-full mb-3 p-2 border rounded" value={email} onChange={e=>setEmail(e.target.value)} />
          <input type="password" placeholder="Password" className="w-full mb-4 p-2 border rounded" value={password} onChange={e=>setPassword(e.target.value)} />
          <button type="submit" className="w-full bg-blue-600 text-white rounded p-2">Login</button>
        </form>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-6xl mx-auto flex flex-col h-screen">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">Issuer Dashboard</h1>
        <button className="bg-green-600 text-white px-4 py-2 rounded font-medium" onClick={handleOpenGenerate}>Generate Token</button>
      </div>

      <div ref={parentRef} className="flex-1 overflow-y-auto border rounded bg-white shadow-sm">
        <div style={{ height: `${rowVirtualizer.getTotalSize()}px`, width: '100%', position: 'relative' }}>
          {rowVirtualizer.getVirtualItems().map((virtualRow) => {
            const isLoaderRow = virtualRow.index > allItems.length - 1;
            const token = allItems[virtualRow.index];
            
            return (
              <div
                key={virtualRow.index}
                style={{
                  position: 'absolute', top: 0, left: 0, width: '100%', height: `${virtualRow.size}px`, transform: `translateY(${virtualRow.start}px)`
                }}
                className="flex items-center px-4 border-b hover:bg-slate-50"
              >
                {isLoaderRow ? (
                  hasNextPage ? 'Loading more...' : 'Nothing more to load'
                ) : (
                  <>
                    <div className="w-1/4 font-mono text-sm">{token.trace_id.slice(-12)}</div>
                    <div className="w-1/4">
                      <span className={`px-2 py-1 rounded text-xs text-white font-medium
                        ${token.status === 'ACTIVE' ? 'bg-green-600' : token.status === 'SUSPICIOUS' ? 'bg-amber-500' : 'bg-red-600'}`}>
                        {token.status}
                      </span>
                    </div>
                    <div className="w-1/3 truncate text-sm text-slate-500">{token.payload_url_preview || token.payload_url}</div>
                    <div className="w-1/4 flex gap-4">
                      {(token.status === 'ACTIVE' || token.status === 'SUSPICIOUS') && (
                         <button onClick={() => handleRevoke(token.trace_id)} className="text-red-500 text-sm hover:underline hover:text-red-700">Revoke</button>
                      )}
                    </div>
                  </>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {generateOpen && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded shadow-xl w-full max-w-md">
            <h2 className="text-2xl font-bold mb-4">Generate Secure Token</h2>
            
            {qrCode ? (
              <div className="flex flex-col items-center">
                <img src={`data:image/png;base64,${qrCode.b64}`} alt="QR Code" className="w-64 h-64 border mb-4" />
                <a href={`data:image/png;base64,${qrCode.b64}`} download={`svt-${qrCode.traceId}.png`} className="bg-blue-600 text-white px-4 py-2 rounded">
                  Download
                </a>
                <button onClick={() => setGenerateOpen(false)} className="mt-4 text-slate-500">Close</button>
              </div>
            ) : (
              <form onSubmit={handleGenerate}>
                <label className="block mb-2 text-sm font-medium">Payload URL</label>
                <input 
                  type="url" 
                  required 
                  className="w-full border p-2 rounded mb-4"
                  value={payloadUrl}
                  onChange={e => setPayloadUrl(e.target.value)}
                />
                
                <label className="block mb-2 text-sm font-medium">TTL</label>
                <input 
                  type="range" 
                  min="0" max="2" 
                  step="1"
                  className="w-full mb-2"
                  value={ttlSeconds === 3600 ? 0 : ttlSeconds === 21600 ? 1 : 2}
                  onChange={e => setTtlSeconds([3600, 21600, 86400][parseInt(e.target.value)])}
                />
                <div className="flex justify-between text-xs text-slate-500 mb-6">
                  <span>1h</span><span>6h</span><span>24h</span>
                </div>

                <div className="flex justify-end gap-2">
                  <button type="button" onClick={() => setGenerateOpen(false)} className="px-4 py-2 border rounded">Cancel</button>
                  <button type="submit" className="px-4 py-2 bg-blue-600 text-white rounded">Obtain Token</button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
