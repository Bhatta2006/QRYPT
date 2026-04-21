export const deviceId: string = (() => {
  let id = sessionStorage.getItem('deviceId');
  if (!id) {
    id = crypto.randomUUID();
    sessionStorage.setItem('deviceId', id);
  }
  return id;
})();

export async function signRequest(
  scannerApiKey: string,
  deviceId: string,
  timestampMs: number,
  bodyJson: string
): Promise<string> {
  const enc = new TextEncoder();
  
  // Create HMAC key
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(scannerApiKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  // Message: deviceId + timestampMs + bodyJson
  const message = `${deviceId}${timestampMs}${bodyJson}`;
  const signatureBuffer = await crypto.subtle.sign(
    'HMAC',
    keyMaterial,
    enc.encode(message)
  );
  
  // Convert ArrayBuffer to hex string
  const hashArray = Array.from(new Uint8Array(signatureBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
