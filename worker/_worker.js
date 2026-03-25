// @ts-ignore
import { connect } from 'cloudflare:sockets';

const UUID = 'ffde63e1-e924-4477-a496-d68402a09caf';

export default {
  async fetch(request, env) {
    const upgrade = request.headers.get('Upgrade') || '';

    if (upgrade.toLowerCase() === 'websocket') {
      return handleVLESS(request);
    }

    const url = new URL(request.url);
    if (url.pathname.startsWith('/' + UUID)) {
      const host = request.headers.get('Host') || url.hostname;
      const link = `vless://${UUID}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2F${UUID}#CF-VLESS`;
      return new Response(link, { status: 200, headers: { 'Content-Type': 'text/plain' } });
    }

    return new Response('OK', { status: 200 });
  }
};

async function handleVLESS(request) {
  const { 0: client, 1: server } = new WebSocketPair();
  server.accept();

  // Use ReadableStream to bridge WS messages
  const readable = new ReadableStream({
    start(controller) {
      server.addEventListener('message', ({ data }) => {
        if (typeof data === 'string') {
          controller.enqueue(new TextEncoder().encode(data));
        } else if (data instanceof ArrayBuffer) {
          controller.enqueue(new Uint8Array(data));
        } else {
          controller.enqueue(data);
        }
      });
      server.addEventListener('close', () => controller.close());
      server.addEventListener('error', (e) => controller.error(e));
    }
  });

  // Run VLESS processing in background
  processVLESS(readable, server).catch(err => {
    console.error('VLESS error:', err.message || err);
    try { server.close(1011, 'Internal error'); } catch (_) {}
  });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

async function processVLESS(readable, ws) {
  const reader = readable.getReader();

  // Read first chunk (VLESS header)
  const { value: buf, done } = await reader.read();
  if (done || !buf || buf.length < 18) {
    ws.close(1000, 'No header');
    return;
  }

  // Parse VLESS header
  const version = buf[0];
  const uuidStr = bytesToUUID(buf.slice(1, 17));

  if (uuidStr !== UUID) {
    ws.close(1000, 'Invalid UUID');
    return;
  }

  const addonLen = buf[17];
  let offset = 18 + addonLen;

  if (buf.length < offset + 4) {
    ws.close(1000, 'Header truncated');
    return;
  }

  const cmd = buf[offset++];
  const port = (buf[offset++] << 8) | buf[offset++];
  const addrType = buf[offset++];

  let addr = '';
  if (addrType === 1) {        // IPv4
    addr = Array.from(buf.slice(offset, offset + 4)).join('.');
    offset += 4;
  } else if (addrType === 2) { // Domain
    const len = buf[offset++];
    addr = new TextDecoder().decode(buf.slice(offset, offset + len));
    offset += len;
  } else if (addrType === 3) { // IPv6
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((buf[offset + i] << 8) | buf[offset + i + 1]).toString(16));
    }
    addr = parts.join(':');
    offset += 16;
  } else {
    ws.close(1000, 'Unknown addr type');
    return;
  }

  // Send VLESS response
  ws.send(new Uint8Array([version, 0]));

  if (cmd !== 1) {
    ws.close(1000, 'UDP not supported');
    return;
  }

  // Connect to target
  let tcpConn;
  try {
    tcpConn = connect({ hostname: addr, port });
  } catch (e) {
    console.error('connect failed:', addr, port, e.message);
    ws.close(1011, 'Connect failed');
    return;
  }

  const tcpWriter = tcpConn.writable.getWriter();

  // Send remaining data from first chunk
  if (buf.length > offset) {
    await tcpWriter.write(buf.slice(offset));
  }

  // WS -> TCP pump
  const wsTCPPump = (async () => {
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        await tcpWriter.write(value);
      }
    } catch (_) {}
    try { await tcpWriter.close(); } catch (_) {}
  })();

  // TCP -> WS pump
  const tcpReader = tcpConn.readable.getReader();
  try {
    while (true) {
      const { value, done } = await tcpReader.read();
      if (done) break;
      ws.send(value);
    }
  } catch (_) {}

  await wsTCPPump;
  try { ws.close(1000, 'Done'); } catch (_) {}
}

function bytesToUUID(bytes) {
  const h = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
