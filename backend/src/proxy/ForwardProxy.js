import http from 'http';
import https from 'https';
import net from 'net';

// ForwardProxy encapsulates an HTTP/HTTPS forward proxy with CONNECT support.
// Dependencies are injected to keep it decoupled and testable.

export default class ForwardProxy {
  constructor({ port, config, emitRecord, startSpider, detectRuntimeVulns, addRuntimeFindings, lastSpideredAt }) {
    this.port = port || 8081;
    this.config = config || {};
    this.emitRecord = emitRecord;
    this.startSpider = startSpider;
    this.detectRuntimeVulns = detectRuntimeVulns;
    this.addRuntimeFindings = addRuntimeFindings;
    this.lastSpideredAt = lastSpideredAt || new Map();
    this.server = null;
  }

  start(host = '0.0.0.0') {
    if (this.server) return this.server;

    this.server = http.createServer((req, res) => {
      let targetUrl = req.url;
      let parsed;
      try {
        parsed = new URL(targetUrl);
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Forward proxy requires absolute URL in request line' }));
        return;
      }

      const isHttps = parsed.protocol === 'https:';
      const lib = isHttps ? https : http;

      const headers = { ...req.headers };
      delete headers['proxy-connection'];
      delete headers['connection'];
      delete headers['upgrade'];
      delete headers['keep-alive'];
      delete headers['transfer-encoding'];
      delete headers['te'];
      delete headers['trailer'];
      delete headers['proxy-authenticate'];
      delete headers['proxy-authorization'];
      headers['host'] = parsed.host;

      const requestOptions = {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        method: req.method,
        path: parsed.pathname + parsed.search,
        headers,
        timeout: 30000,
      };

      const proxyReq = lib.request(requestOptions, (proxyRes) => {
        res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
        const chunks = [];
        proxyRes.on('data', (chunk) => { try { chunks.push(chunk); } catch {} });
        proxyRes.pipe(res);
        proxyRes.on('end', () => {
          let fpHeadersRaw = [];
          try {
            if (Array.isArray(proxyRes.rawHeaders) && proxyRes.rawHeaders.length) fpHeadersRaw = proxyRes.rawHeaders;
            else if (proxyRes.headers) {
              for (const [hk, hv] of Object.entries(proxyRes.headers)) {
                if (Array.isArray(hv)) for (const v of hv) fpHeadersRaw.push(hk, String(v));
                else fpHeadersRaw.push(hk, String(hv));
              }
            }
          } catch {}
          let fpReqHeadersRaw = [];
          try {
            if (Array.isArray(req.rawHeaders) && req.rawHeaders.length) fpReqHeadersRaw = req.rawHeaders;
            else if (req.headers) {
              for (const [hk, hv] of Object.entries(req.headers)) {
                if (Array.isArray(hv)) for (const v of hv) fpReqHeadersRaw.push(hk, String(v));
                else fpReqHeadersRaw.push(hk, String(hv));
              }
            }
          } catch {}
          const body = Buffer.concat(chunks).toString('utf8');

          try {
            const rec = { url: parsed.toString(), host: parsed.host, method: req.method, timestamp: new Date().toISOString() };
            const newFindings = this.detectRuntimeVulns(rec, body, proxyRes.headers);
            if (newFindings && newFindings.length && typeof this.addRuntimeFindings === 'function') {
              this.addRuntimeFindings(newFindings);
            }
          } catch {}

          try {
            this.emitRecord({ method: req.method, url: parsed.toString(), status: proxyRes.statusCode || 0, headers: proxyRes.headers, reqHeaders: req.headers, headersRaw: fpHeadersRaw, reqHeadersRaw: fpReqHeadersRaw });
          } catch {}

          try {
            const status = proxyRes.statusCode || 0;
            const ct = String(proxyRes.headers['content-type'] || '').toLowerCase();
            if (this.config.spiderDepth > 0 && status === 200 && ct.includes('text/html')) {
              const ua = String(req.headers['user-agent'] || '');
              setImmediate(() => this.startSpider(parsed.toString(), body, this.config, ua, this.emitRecord).catch(() => {}));
            }
          } catch {}
        });
      });

      proxyReq.on('timeout', () => { proxyReq.destroy(new Error('Upstream timeout')); });
      proxyReq.on('error', (err) => {
        try {
          if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Forward proxy error', details: err.message }));
        } catch {}
      });

      req.pipe(proxyReq);
    });

    this.server.on('connect', (req, clientSocket, head) => {
      const [host, portStr] = (req.url || '').split(':');
      const port = Number(portStr) || 443;
      if (!host) {
        clientSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
        clientSocket.destroy();
        return;
      }
      const serverSocket = net.connect(port, host, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: SnapShot\r\n\r\n');
        if (head && head.length) serverSocket.write(head);
        serverSocket.pipe(clientSocket);
        clientSocket.pipe(serverSocket);
        const connectUrl = `https://${host}:${port}`;
        try { this.emitRecord({ method: 'CONNECT', url: connectUrl, status: 200, headers: {}, reqHeaders: req.headers, headersRaw: [], reqHeadersRaw: Array.isArray(req.rawHeaders) ? req.rawHeaders : [] }); } catch {}
        try {
          if (this.config.spiderDepth > 0) {
            const origin = `https://${host}${port && Number(port) !== 443 ? ':' + port : ''}/`;
            const last = this.lastSpideredAt.get(origin) || 0;
            if (Date.now() - last > 60000) {
              this.lastSpideredAt.set(origin, Date.now());
              setImmediate(() => this.startSpider(origin, '', this.config, '', this.emitRecord).catch(() => {}));
            }
          }
        } catch {}
      });
      const onErr = () => {
        try { clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); } catch {}
        clientSocket.destroy();
      };
      serverSocket.on('error', onErr);
      clientSocket.on('error', () => {});
    });

    this.server.listen(this.port, host, () => {
      console.log(`Forward proxy listening on http://${host}:${this.port}`);
    });

    return this.server;
  }
}
