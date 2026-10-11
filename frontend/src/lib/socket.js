import { API_BASE_URL } from './api';

const apiUrl = new URL(API_BASE_URL);
const WS_BASE = `${apiUrl.protocol === 'https:' ? 'wss:' : 'ws:'}//${apiUrl.host}/ws`;

export async function createScanSocket(scanId, { onMessage, onClose, onError }) {
  let ws = null;
  let reconnectDelay = 500;
  let maxDelay = 30000;
  let shouldReconnect = true;
  let token = null;

  async function fetchToken() {
    const res = await fetch(`${API_BASE_URL}/api/auth/token`);
    const data = await res.json();
    return data.token;
  }

  async function connect() {
    if (!token) {
      token = await fetchToken();
    }

    ws = new WebSocket(`${WS_BASE}/${scanId}`);

    ws.onopen = () => {
      // Send token as first message after connection — avoids token in URL/logs
      ws.send(JSON.stringify({ type: 'auth', token }));
      reconnectDelay = 500;
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        // Skip auth-related messages
        if (data.type === 'auth') return;
        onMessage?.(data);
      } catch (e) {
        console.error('WebSocket parse error:', e);
      }
    };

    ws.onclose = () => {
      onClose?.();
      if (shouldReconnect) {
        setTimeout(() => {
          reconnectDelay = Math.min(reconnectDelay * 2, maxDelay);
          connect();
        }, reconnectDelay);
      }
    };

    ws.onerror = (err) => {
      onError?.(err);
    };
  }

  await connect();

  return {
    close: () => {
      shouldReconnect = false;
      ws?.close();
    },
  };
}
