/// <reference lib="webworker" />
import { clientsClaim } from 'workbox-core';
import { precacheAndRoute } from 'workbox-precaching';
import { registerRoute } from 'workbox-routing';

declare let self: ServiceWorkerGlobalScope;

self.skipWaiting();
clientsClaim();

precacheAndRoute(self.__WB_MANIFEST);

const SCAN_API_VERIFY_URL = '/api/v1/scan/verify';

// Handle offline logic for scan verify
registerRoute(
  ({ url }) => url.pathname === SCAN_API_VERIFY_URL,
  async ({ request }) => {
    try {
      // Always attempt network first
      const response = await fetch(request.clone());
      return response;
    } catch (err) {
      // Offline fallback activated
      try {
        const clonedReq = request.clone();
        const body = await clonedReq.json();
        
        let traceId = '';
        if (body.qr_payload) {
          // Weak decode assuming traceId is discernible or passed explicitly
          // Wait, the specification says: extract from request body.
          // Since it's CBOR encoded and we already parsed it in frontend, maybe we should pass trace_id in the body?
          // If body just has qr_payload, let's parse it or we can expect it from body.trace_id if added by Scanner.
          // Let's assume Scanner adds trace_id to the body explicitly for offline caching lookup.
          traceId = body.trace_id;
        }

        if (!traceId) {
          return new Response(JSON.stringify({ result: 'CANNOT_VERIFY', reason: 'offline_unverified' }), {
            headers: { 'Content-Type': 'application/json' },
            status: 200
          });
        }

        // Open IndexedDB cache
        const db = await new Promise<IDBDatabase>((resolve, reject) => {
          const req = indexedDB.open('revocation_cache', 1);
          req.onupgradeneeded = () => {
            if (!req.result.objectStoreNames.contains('tokens')) {
              req.result.createObjectStore('tokens', { keyPath: 'trace_id' });
            }
          };
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });

        const tx = db.transaction('tokens', 'readonly');
        const store = tx.objectStore('tokens');
        const getReq = store.get(traceId);

        const record = await new Promise<any>((resolve, reject) => {
          getReq.onsuccess = () => resolve(getReq.result);
          getReq.onerror = () => reject(getReq.error);
        });

        if (!record) {
          return new Response(JSON.stringify({ result: 'CANNOT_VERIFY', reason: 'offline_unverified' }), {
            headers: { 'Content-Type': 'application/json' },
            status: 200
          });
        }

        const ageMs = Date.now() - record.cache_updated_at;
        if (ageMs > 300 * 1000) {
          return new Response(JSON.stringify({ result: 'CANNOT_VERIFY', reason: 'cache_stale' }), {
            headers: { 'Content-Type': 'application/json' },
            status: 200
          });
        }

        if (record.action === 'BLOCKED') {
          return new Response(JSON.stringify({ result: 'DENY', reason: 'offline_revoked' }), {
            headers: { 'Content-Type': 'application/json' },
            status: 200
          });
        }

        return new Response(JSON.stringify({ result: 'CANNOT_VERIFY', reason: 'offline_unverified' }), {
          headers: { 'Content-Type': 'application/json' },
          status: 200
        });

      } catch (fallbackErr) {
        return new Response(JSON.stringify({ result: 'CANNOT_VERIFY', reason: 'offline_error' }), {
          headers: { 'Content-Type': 'application/json' },
          status: 200
        });
      }
    }
  },
  'POST'
);

// Listen for broadcast messages from main thread
self.addEventListener('message', async (event) => {
  if (event.data && event.data.type === 'SYNC_REVOCATION') {
    const { trace_id, action } = event.data.payload;
    
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const req = indexedDB.open('revocation_cache', 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains('tokens')) {
          req.result.createObjectStore('tokens', { keyPath: 'trace_id' });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });

    const tx = db.transaction('tokens', 'readwrite');
    const store = tx.objectStore('tokens');
    
    store.put({
      trace_id,
      action,
      cache_updated_at: Date.now()
    });
    
    // LRU Eviction: if over 10000, delete oldest
    const countReq = store.count();
    countReq.onsuccess = async () => {
      if (countReq.result > 10000) {
        const excess = countReq.result - 10000;
        const keysWithTime: {key: string, time: number}[] = [];
        
        await new Promise<void>((resolve) => {
          store.openCursor().onsuccess = (e: any) => {
            const cursor = e.target.result;
            if (cursor) {
              keysWithTime.push({ key: cursor.key, time: cursor.value.cache_updated_at });
              cursor.continue();
            } else {
              resolve();
            }
          };
        });
        
        keysWithTime.sort((a, b) => a.time - b.time);
        
        for (let i = 0; i < excess; i++) {
          store.delete(keysWithTime[i].key);
        }
      }
    };
  }
});
