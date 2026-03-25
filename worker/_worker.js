// Minimal VLESS WebSocket worker - battle tested version
// Based on: https://github.com/zizifn/edgetunnel

const UUID = 'ffde63e1-e924-4477-a496-d68402a09caf';

export default {
  async fetch(request, env) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      const url = new URL(request.url);
      if (url.pathname === `/${UUID}`) {
        const host = request.headers.get('Host');
        return new Response(
          `vless://${UUID}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2F${UUID}#CF-VLESS`,
          { headers: { 'Content-Type': 'text/plain' } }
        );
      }
      return new Response('OK', { status: 200 });
    }
    return await vlessOverWSHandler(request);
  },
};

async function vlessOverWSHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let address = '';
  let portWithRandomLog = '';
  const log = (info, event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
  };

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWapper = {
    value: null,
  };
  let isDns = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDns) {
            return await handleDNSQuery(chunk, webSocket, null, log);
          }
          if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            hasError,
            message,
            portRemote = 443,
            addressRemote = '',
            rawDataIndex,
            vlessVersion = new Uint8Array([0, 0]),
            isUDP,
          } = processVlessHeader(chunk, UUID);

          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} tcp`;

          if (hasError) {
            controller.error(message);
            return;
          }

          if (isUDP) {
            if (portRemote === 53) {
              isDns = true;
            } else {
              controller.error('UDP proxy only for DNS (53)');
              return;
            }
          }

          const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isDns) {
            return handleDNSQuery(rawClientData, webSocket, vlessResponseHeader, log);
          }

          handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
        },
        close() {
          log(`readableWebSocketStream is closed`);
        },
        abort(reason) {
          log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log('readableWebSocketStream pipeTo error', err);
    });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
  async function connectAndWrite(address, port) {
    const { connect } = await import('cloudflare:sockets');
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    tcpSocket.closed
      .catch((error) => {
        console.log('retry tcpSocket closed error', error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });

      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener('error', (err) => {
        log('webSocketServer has error');
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
  return stream;
}

function processVlessHeader(vlessBuffer, userID) {
  if (vlessBuffer.byteLength < 24) {
    return {
      hasError: true,
      message: 'invalid data',
    };
  }
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  let isValidUser = false;
  let isUDP = false;
  
  if (stringify(new Uint8Array(vlessBuffer.slice(1, 17))) === userID) {
    isValidUser = true;
  }
  if (!isValidUser) {
    return {
      hasError: true,
      message: 'invalid user',
    };
  }

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

  if (command === 1) {
    // TCP
  } else if (command === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${command} is not support`,
    };
  }

  const portIndex = 18 + optLength + 1;
  const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  
  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));
  const addressType = addressBuffer[0];
  
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = '';
  
  switch (addressType) {
    case 1: // IPv4
      addressLength = 4;
      addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
      break;
    case 2: // Domain
      addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: // IPv6
      addressLength = 16;
      const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(':');
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
  let remoteChunkCount = 0;
  let chunks = [];
  let vlessHeader = vlessResponseHeader;
  let hasError = false;
  
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          remoteChunkCount++;
          if (webSocket.readyState !== WebSocket.OPEN) {
            controller.error('webSocket.readyState is not open');
            return;
          }
          if (vlessHeader) {
            webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
            vlessHeader = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log(`remoteConnection!.readable is closed, remoteChunkCount is ${remoteChunkCount}`);
        },
        abort(reason) {
          hasError = true;
          console.error('remoteConnection!.readable abort', reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS has exception `, error.stack || error);
      safeCloseWebSocket(webSocket);
    });

  if (hasError) {
    return;
  }
  
  if (remoteChunkCount === 0 && retry) {
    log(`retry`);
    retry();
  } else {
    log('remoteSocket has no data, close webSocket');
    safeCloseWebSocket(webSocket);
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error('safeCloseWebSocket error', error);
  }
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset + 0]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    '-' +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    '-' +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    '-' +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    '-' +
    byteToHex[arr[offset + 10]] +
    byteToHex[arr[offset + 11]] +
    byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] +
    byteToHex[arr[offset + 14]] +
    byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) {
    throw new TypeError('Stringified UUID is invalid');
  }
  return uuid;
}

function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

async function handleDNSQuery(udpChunk, webSocket, vlessResponseHeader, log) {
  // simple DNS over HTTPS
  const resp = await fetch('https://cloudflare-dns.com/dns-query', {
    method: 'POST',
    headers: {
      'content-type': 'application/dns-message',
    },
    body: udpChunk,
  });
  const dnsQueryResult = await resp.arrayBuffer();
  const udpSize = dnsQueryResult.byteLength;
  const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
  if (webSocket.readyState === WebSocket.OPEN) {
    log(`dns udpSize is ${udpSize}`);
    if (vlessResponseHeader) {
      webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
    } else {
      webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
    }
  }
}
