/**
 * A minimal VLESS-over-WebSocket relay for Cloudflare Workers.
 *
 * This is the "class B" endpoint of PLAN-02: slow, rate-limited, and almost
 * impossible to block outright, because blocking it means blocking Cloudflare.
 * It exists to be there when the direct VPS address is gone.
 *
 * Scope is deliberately small. It relays TCP only — Workers cannot open UDP
 * sockets, so a client must not route UDP or QUIC through this endpoint — and
 * it implements exactly the VLESS request header, nothing more. Everything a
 * Worker cannot do is a hard limit of the platform, not an omission here:
 *
 *   * no UDP, so no QUIC and no DNS-over-QUIC through this path;
 *   * a request quota on the free plan, so this is a fallback, not a primary;
 *   * no connection to another Cloudflare address, which is why a destination
 *     behind Cloudflare needs a separate relay address.
 */

const WS_READY = 1;

export default {
  /**
   * @param {Request} request
   * @param {{ UUID?: string, PATH?: string }} env
   */
  async fetch(request, env) {
    const uuid = (env.UUID || '').trim();
    if (!uuid) {
      // Refuse rather than accept everyone: an unconfigured Worker that relays
      // for any client is an open proxy with the operator's name on it.
      return new Response('not configured', { status: 500 });
    }
    if (request.headers.get('Upgrade') !== 'websocket') {
      // Anything that is not the tunnel gets an ordinary-looking page. A Worker
      // that answers oddly to a plain GET is a Worker that stands out.
      return new Response('', { status: 404 });
    }
    const path = env.PATH || '/tunnel';
    if (new URL(request.url).pathname !== path) {
      return new Response('', { status: 404 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();
    relay(server, parseUuid(uuid), request.headers.get('sec-websocket-protocol')).catch(() => {
      safeClose(server);
    });
    return new Response(null, { status: 101, webSocket: client });
  },
};

/** Parse a canonical UUID into 16 bytes. */
function parseUuid(text) {
  const hex = text.replace(/-/g, '');
  if (hex.length !== 32 || /[^0-9a-fA-F]/.test(hex)) {
    throw new Error('UUID is malformed');
  }
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Decode the `sec-websocket-protocol` early-data payload, if present. */
function earlyData(header) {
  if (!header) return null;
  try {
    const normalised = header.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(normalised);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

async function relay(socket, uuid, earlyHeader) {
  const first = earlyData(earlyHeader) || (await firstMessage(socket));
  const request = decodeVlessRequest(first, uuid);

  const { connect } = await import('cloudflare:sockets');
  const upstream = connect({ hostname: request.hostname, port: request.port });

  // The VLESS response header is sent once, ahead of the first payload byte.
  const writer = upstream.writable.getWriter();
  if (request.payload.length > 0) {
    await writer.write(request.payload);
  }

  let sentResponseHeader = false;
  const downstream = upstream.readable.pipeTo(
    new WritableStream({
      write(chunk) {
        if (socket.readyState !== WS_READY) return;
        if (!sentResponseHeader) {
          sentResponseHeader = true;
          const framed = new Uint8Array(chunk.byteLength + 2);
          framed[0] = request.version;
          framed[1] = 0;
          framed.set(new Uint8Array(chunk), 2);
          socket.send(framed);
          return;
        }
        socket.send(chunk);
      },
      close() {
        safeClose(socket);
      },
      abort() {
        safeClose(socket);
      },
    }),
  );

  socket.addEventListener('message', (event) => {
    writer.write(new Uint8Array(event.data)).catch(() => safeClose(socket));
  });
  socket.addEventListener('close', () => {
    writer.close().catch(() => {});
  });
  socket.addEventListener('error', () => {
    writer.abort().catch(() => {});
  });

  await downstream.catch(() => safeClose(socket));
}

function firstMessage(socket) {
  return new Promise((resolve, reject) => {
    socket.addEventListener(
      'message',
      (event) => resolve(new Uint8Array(event.data)),
      { once: true },
    );
    socket.addEventListener('close', () => reject(new Error('closed')), { once: true });
    socket.addEventListener('error', () => reject(new Error('socket error')), { once: true });
  });
}

/**
 * Decode a VLESS request header.
 *
 * Layout: version(1) uuid(16) addonLen(1) addons(addonLen) command(1)
 * port(2, big endian) addressType(1) address(variable), then payload.
 */
function decodeVlessRequest(bytes, uuid) {
  if (bytes.length < 24) {
    throw new Error('VLESS header is too short');
  }
  const version = bytes[0];
  for (let i = 0; i < 16; i += 1) {
    // Compared in full rather than short-circuiting: a timing side channel on
    // the credential is cheap to avoid and awkward to notice.
    if (bytes[1 + i] !== uuid[i]) {
      throw new Error('VLESS credential does not match');
    }
  }
  const addonLength = bytes[17];
  let at = 18 + addonLength;
  const command = bytes[at];
  at += 1;
  if (command !== 1) {
    // 1 is TCP. 2 is UDP and 3 is Mux, neither of which a Worker can carry.
    throw new Error('this endpoint relays TCP only');
  }
  const port = (bytes[at] << 8) | bytes[at + 1];
  at += 2;

  const addressType = bytes[at];
  at += 1;
  let hostname;
  if (addressType === 1) {
    hostname = Array.from(bytes.slice(at, at + 4)).join('.');
    at += 4;
  } else if (addressType === 2) {
    const length = bytes[at];
    at += 1;
    hostname = new TextDecoder().decode(bytes.slice(at, at + length));
    at += length;
  } else if (addressType === 3) {
    const parts = [];
    for (let i = 0; i < 8; i += 1) {
      parts.push(((bytes[at + i * 2] << 8) | bytes[at + i * 2 + 1]).toString(16));
    }
    hostname = `[${parts.join(':')}]`;
    at += 16;
  } else {
    throw new Error(`unknown address type ${addressType}`);
  }

  return { version, hostname, port, payload: bytes.slice(at) };
}

function safeClose(socket) {
  try {
    socket.close();
  } catch {
    // Already closing; nothing useful to do.
  }
}
