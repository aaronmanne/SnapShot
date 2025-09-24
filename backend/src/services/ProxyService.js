import http from 'http';
import https from 'https';
import httpProxy from 'http-proxy';
import {v4 as uuidv4} from 'uuid';
import {getSpiderStatus, startSpider} from '../utils/Spider.js';

/**
 * Configure proxy service for HTTP requests
 */
class ProxyService {
    /**
     * Maximum number of requests to store
     * @type {number}
     */
    MAX_REQUESTS = 1000;

    /**
     * Create a proxy service
     * @param {Object} config - Service configuration
     * @param {Object} dependencies - Injected dependencies
     */
    constructor(config, {
        uniqueHosts,
        uniquePaths,
        requests,
        runtimeOptions,
        openApiDocs,
        emitRecord,
        detectOpenApiForHost,
        identifyTechnologies,
        detectRuntimeVulns,
        addRuntimeFindings,
        queueCveLookup,
        registerTechVersionsForHost,
        aggressiveFingerprint,
        io
    }) {
        this.config = config;
        this.uniqueHosts = uniqueHosts;
        this.uniquePaths = uniquePaths;
        this.requests = requests;
        this.runtimeOptions = runtimeOptions;
        this.openApiDocs = openApiDocs;
        this._emitRecord = emitRecord;
        this.detectOpenApiForHost = detectOpenApiForHost;
        this.identifyTechnologies = identifyTechnologies;
        this.detectRuntimeVulns = detectRuntimeVulns;
        this.addRuntimeFindings = addRuntimeFindings;
        this.queueCveLookup = queueCveLookup;
        this.registerTechVersionsForHost = registerTechVersionsForHost;
        this._aggressiveFingerprint = aggressiveFingerprint;
        this.io = io;

        // Create proxy server
        this.proxy = httpProxy.createProxyServer({
            changeOrigin: true,
            secure: false,
        });

        this._setupProxyHandlers();
    }

    /**
     * Set up event handlers for the proxy
     * @private
     */
    _setupProxyHandlers() {
        this.proxy.on('proxyReq', (proxyReq, req, res, options) => {
            // You could adjust headers here if needed
        });

        this.proxy.on('proxyRes', (proxyRes, req, res) => {
            const chunks = [];
            proxyRes.on('data', chunk => chunks.push(chunk));
            proxyRes.on('end', () => {
                const body = Buffer.concat(chunks).toString('utf8');

                // Determine the true target URL robustly
                let targetUrl = req.proxiedTargetUrl || '';
                if (!targetUrl) {
                    try {
                        // Try to extract from original request URL query (?url=...)
                        const idx = (req.url || '').indexOf('?');
                        if (idx !== -1) {
                            const qs = new URLSearchParams((req.url || '').slice(idx + 1));
                            const candidate = qs.get('url');
                            if (candidate) targetUrl = candidate;
                        }
                    } catch {
                    }
                }

                // Fallback to header if provided
                if (!targetUrl) {
                    const hdr = req.headers?.['x-target-url'] || req.headers?.['X-Target-URL'];
                    if (hdr) targetUrl = String(hdr);
                }

                // Final fallback to req.url (may be absolute-form in some deployments)
                if (!targetUrl) targetUrl = req.url;

                // Parse URL safely
                let u;
                try {
                    u = new URL(targetUrl);
                } catch {
                }

                // Build raw header arrays with fallbacks so UI always has something
                let headersRawArr = [];
                try {
                    if (Array.isArray(proxyRes.rawHeaders) && proxyRes.rawHeaders.length) headersRawArr = proxyRes.rawHeaders;
                    else if (proxyRes.headers) {
                        for (const [hk, hv] of Object.entries(proxyRes.headers)) {
                            if (Array.isArray(hv)) for (const v of hv) headersRawArr.push(hk, String(v));
                            else headersRawArr.push(hk, String(hv));
                        }
                    }
                } catch {
                }

                let reqHeadersRawArr = [];
                try {
                    if (Array.isArray(req.rawHeaders) && req.rawHeaders.length) reqHeadersRawArr = req.rawHeaders;
                    else if (req.headers) {
                        for (const [hk, hv] of Object.entries(req.headers)) {
                            if (Array.isArray(hv)) for (const v of hv) reqHeadersRawArr.push(hk, String(v));
                            else reqHeadersRawArr.push(hk, String(hv));
                        }
                    }
                } catch {
                }

                const record = {
                    id: uuidv4(),
                    timestamp: new Date().toISOString(),
                    method: req.method,
                    url: u ? u.toString() : String(targetUrl || ''),
                    host: u ? u.host : '',
                    path: u ? (u.pathname + (u.search || '') + (u.hash || '')) : '',
                    status: proxyRes.statusCode,
                    reqHeaders: req.headers,
                    headers: proxyRes.headers,
                    // Provide raw header arrays for reliable rendering
                    headersRaw: headersRawArr,
                    reqHeadersRaw: reqHeadersRawArr,
                    tech: this.identifyTechnologies(proxyRes.headers),
                    hasOpenApi: false,
                };

                // Heuristic vulnerability detection on response body
                try {
                    const newFindings = this.detectRuntimeVulns(record, body, proxyRes.headers);
                    if (newFindings && newFindings.length) this.addRuntimeFindings(newFindings);
                } catch {
                }

                // Diagnostic log to help verify correctness in user environment
                try {
                    console.log(`[PROXY] ${record.method} ${record.status} ${record.url} (path=${record.path || '/'})`);
                } catch {
                }

                // Maintain sets
                const isNewHost = record.host && !this.uniqueHosts.has(record.host);
                if (record.host) this.uniqueHosts.add(record.host);
                if (record.path) this.uniquePaths.add(record.path);

                // Store
                this.requests.push(record);
                if (this.requests.length > this.MAX_REQUESTS) this.requests.shift();

                // Trigger background CVE lookup for versioned technologies
                try {
                    this.queueCveLookup(proxyRes.headers);
                } catch {
                }

                // Track host attribution for tech@version pairs
                try {
                    this.registerTechVersionsForHost(proxyRes.headers, record.host);
                } catch {
                }

                // Trigger OpenAPI detection async
                if (u) {
                    this.detectOpenApiForHost(record.host, u.protocol, this.openApiDocs).then(() => {
                        const docs = this.openApiDocs.get(record.host) || [];
                        record.hasOpenApi = docs.length > 0;
                    });
                }

                // Emit via socket
                this.io.emit('request', record);

                // Aggressive fingerprinting on first sight of host
                try {
                    if (isNewHost && this.runtimeOptions.aggressiveFingerprinting) {
                        const proto = u ? u.protocol : 'http:';
                        setImmediate(() => this._aggressiveFingerprint(record.host, proto).catch(() => {
                        }));
                    }
                } catch {
                }

                // Fire-and-forget spidering of discovered links when HTML and enabled
                try {
                    const ct = String(proxyRes.headers['content-type'] || '').toLowerCase();
                    if (u && this.config.spiderDepth > 0 && proxyRes.statusCode === 200 && ct.includes('text/html')) {
                        const urlStr = u.toString();
                        const ua = String(req.headers['user-agent'] || '');
                        // Pass the emitRecord function to display spider results in the UI
                        if (getSpiderStatus) {
                            setImmediate(() => startSpider(urlStr, body, this.config, ua, this._emitRecord).catch(() => {
                            }));
                        }

                    }
                } catch {
                }
            });
        });

        this.proxy.on('error', (err, req, res) => {
            console.error('Proxy error:', err.message);
            if (!res.headersSent) {
                res.writeHead(502, {'Content-Type': 'application/json'});
            }
            res.end(JSON.stringify({error: 'Proxy failed', details: err.message}));
        });
    }

    /**
     * Get the configured proxy server
     * @returns {Object} - HTTP proxy instance
     */
    getProxy() {
        return this.proxy;
    }
}

export default ProxyService;