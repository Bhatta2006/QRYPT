import React, { useEffect, useRef, useState } from 'react';
import jsQR from 'jsqr';
import { decode, encode } from 'cbor-x';
import * as ed from '@noble/ed25519';
import { apiClient } from '../lib/api';
import { deviceId, signRequest } from '../lib/hmac';

// Base64URL to Uint8Array
const fromBase64url = (str: string) => {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes;
};

// Global cache for public keys
const pubKeyCache = new Map<string, Uint8Array>();

const Scanner = () => {
  const [scannerApiKey, setScannerApiKey] = useState(sessionStorage.getItem('scannerApiKey') || '');
  const [setupMode, setSetupMode] = useState(!sessionStorage.getItem('scannerApiKey'));
  const videoRef = useRef<HTMLVideoElement>(null);
  const [resultOverlay, setResultOverlay] = useState<{
    type: 'ALLOW' | 'WARN' | 'DENY' | 'CANNOT_VERIFY';
    traceId: string;
    issuerName: string;
    preview: string;
    reason?: string;
  } | null>(null);
  const isScanning = useRef(false);
  const lastScanTimestamp = useRef<{ [payload: string]: number }>({});

  const scheduleDismiss = () => {
    setTimeout(() => setResultOverlay(null), 3000);
  };
  
  async function handleScan(rawQrString: string) {
    try {
      const buffer = fromBase64url(rawQrString);
      const envelope = decode(buffer);

      if (envelope.v !== 1) {
        setResultOverlay({ type: 'DENY', traceId: '', issuerName: '', preview: '', reason: 'invalid_version' });
        scheduleDismiss();
        return;
      }

      const { d: D, trace_id, sig } = envelope;

      if (!pubKeyCache.has(trace_id)) {
        const keyData = await apiClient.getPublicKey(trace_id);
        const pubKeyBytes = fromBase64url(keyData.public_key);
        pubKeyCache.set(trace_id, pubKeyBytes);
      }

      const pubKey = pubKeyCache.get(trace_id)!;
      
      const canonicalCbor = (msg: Record<string, unknown>) => encode(msg);
      // CRITICAL: Construct message canonically. CBOR-X serializes object properties in insertion order,
      // but standard dictates shortest keys first. 'd' (length 1) comes before 'trace_id' (length 8).
      const canonicalMsg = canonicalCbor({ d: D, trace_id }); 

      const isValid = await ed.verify(sig, canonicalMsg, pubKey);

      if (!isValid) {
        setResultOverlay({ type: 'DENY', traceId: trace_id, issuerName: '', preview: '', reason: 'invalid_signature' });
        scheduleDismiss();
        return;
      }

      // Prepare Backend verification
      const timestampMs = Date.now();
      const body = { qr_payload: rawQrString, timestamp_ms: timestampMs };
      const bodyStr = JSON.stringify(body);
      const hmacSig = await signRequest(scannerApiKey, deviceId, timestampMs, bodyStr);

      const res = await apiClient.verifyScan(deviceId, hmacSig, timestampMs, body);

      setResultOverlay({
        type: res.result as 'ALLOW' | 'DENY' | 'CANNOT_VERIFY',
        traceId: trace_id,
        issuerName: res.issuer_display_name || '',
        preview: res.payload_preview || ''
      });
      scheduleDismiss();

    } catch (err: unknown) {
      const e = err as { response?: { status?: number, data?: { result?: string } } };
      if (e.response && e.response.status === 401) return; // Ignore standard auth errors on UX? Or wait, scanner is not auth'd by JWT, it uses API key inside HMAC.
      
      const res = e.response?.data || {};
      
      if (res.result) {
         setResultOverlay({
           type: res.result || 'CANNOT_VERIFY',
           traceId: res.trace_id || 'unknown',
           issuerName: '',
           preview: '',
           reason: res.reason || 'network_error'
         });
      } else {
         setResultOverlay({
           type: 'CANNOT_VERIFY',
           traceId: 'unknown',
           issuerName: '',
           preview: '',
           reason: 'network_error'
         });
      }
      scheduleDismiss();
    }
  }

  useEffect(() => {
    if (setupMode) return;

    let stream: MediaStream | null = null;
    let animId: number;

    const startCamera = async () => {
      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'environment', width: { ideal: 1280 } }
        });
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          videoRef.current.play();
          requestAnimationFrame(scanLoop);
        }
      } catch (err) {
        console.error('Camera access error', err);
      }
    };

    const scanLoop = async () => {
      if (videoRef.current && videoRef.current.readyState === videoRef.current.HAVE_ENOUGH_DATA && !isScanning.current) {
        const canvas = document.createElement('canvas');
        canvas.width = videoRef.current.videoWidth;
        canvas.height = videoRef.current.videoHeight;
        const ctx = canvas.getContext('2d');
        if (ctx) {
          ctx.drawImage(videoRef.current, 0, 0, canvas.width, canvas.height);
          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, canvas.width, canvas.height, { inversionAttempts: "dontInvert" });
          
          if (code) {
            const now = Date.now();
            const lastTime = lastScanTimestamp.current[code.data] || 0;
            if (now - lastTime > 500) {
              lastScanTimestamp.current[code.data] = now;
              isScanning.current = true;
              await handleScan(code.data);
              isScanning.current = false;
            }
          }
        }
      }
      animId = requestAnimationFrame(scanLoop);
    };

    startCamera();

    return () => {
      if (stream) stream.getTracks().forEach(t => t.stop());
      cancelAnimationFrame(animId);
    };
  }, [setupMode]);





  const handleSetup = (e: React.FormEvent) => {
    e.preventDefault();
    if (scannerApiKey) {
      sessionStorage.setItem('scannerApiKey', scannerApiKey);
      setSetupMode(false);
    }
  };

  if (setupMode) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-900 p-4">
        <form onSubmit={handleSetup} className="bg-white p-6 rounded shadow-md w-full max-w-sm">
          <h2 className="text-xl font-bold mb-4">Scanner Setup</h2>
          <label className="block mb-2 text-sm font-medium">Scanner API Key</label>
          <input 
            type="text" 
            className="w-full border p-2 rounded mb-4" 
            value={scannerApiKey}
            onChange={e => setScannerApiKey(e.target.value)}
            required
          />
          <button type="submit" className="w-full bg-blue-600 text-white p-2 rounded">Start Scanning</button>
        </form>
      </div>
    );
  }

  return (
    <div className="relative h-screen w-full bg-black overflow-hidden">
      <video ref={videoRef} className="absolute inset-0 w-full h-full object-cover" muted playsInline autoPlay />
      
      {resultOverlay && (
        <div 
          onClick={() => setResultOverlay(null)}
          className={`absolute inset-0 z-50 flex flex-col items-center justify-center p-4 text-white
          ${resultOverlay.type === 'ALLOW' ? 'bg-green-600' :
            resultOverlay.type === 'WARN' ? 'bg-amber-500' :
            resultOverlay.type === 'DENY' ? 'bg-red-600' : 'bg-orange-500'}`}
        >
          <h1 className="text-6xl font-bold mb-4">{resultOverlay.type}</h1>
          <p className="text-xl mb-2">ID: {resultOverlay.traceId.slice(-8)}</p>
          <p className="text-lg font-medium">{resultOverlay.issuerName}</p>
          <p className="text-md opacity-80 mt-4 max-w-sm text-center">{resultOverlay.preview}</p>
          {resultOverlay.reason && <p className="text-sm mt-8 opacity-60">Reason: {resultOverlay.reason}</p>}
        </div>
      )}
    </div>
  );
};

export default Scanner;
