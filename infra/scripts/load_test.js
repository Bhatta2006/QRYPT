import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  vus: 100,
  duration: "5m",
  thresholds: {
    http_req_duration: ["p(99)<200"],
    http_req_failed: ["rate<0.001"],
  },
};

const BASE_URL = __ENV.BASE_URL || "https://staging.svt.internal";
const SCANNER_KEY = __ENV.SCANNER_KEY;
const DEVICE_ID = __ENV.DEVICE_ID;

export default function () {
  const ts = Date.now();
  const body = JSON.stringify({
    qr_payload: __ENV.TEST_QR_PAYLOAD,
    timestamp_ms: ts,
  });
  // HMAC-SHA256 not available natively in k6 — use pre-computed static test signature
  const sig = __ENV.TEST_SIGNATURE;
  const res = http.post(`${BASE_URL}/api/v1/scan/verify`, body, {
    headers: {
      "Content-Type": "application/json",
      "X-Device-Id": DEVICE_ID,
      "X-Timestamp": String(ts),
      "X-Signature-SHA256": sig,
    },
  });
  check(res, { "status 200": (r) => r.status === 200 });
  sleep(0.1);
}
