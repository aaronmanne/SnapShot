import http from 'http';
import https from 'https';
import { v4 as uuidv4 } from 'uuid';

/**
 * Service to handle analytics-related functionality
 */
class AnalyticsService {
  /**
   * Create analytics service
   * 
   * @param {Object} dependencies - Required dependencies
   */
  constructor({
    requests, 
    uniqueHosts, 
    uniquePaths, 
    openApiDocs,
    io,
    identifyTechnologies,
    queueCveLookup,
    registerTechVersionsForHost,
    detectOpenApiForHost,
    runtimeOptions,
    getVulnerabilitiesAnalytics
  }) {
    this.requests = requests;
    this.uniqueHosts = uniqueHosts;
    this.uniquePaths = uniquePaths;
    this.openApiDocs = openApiDocs;
    this.io = io;
    this.identifyTechnologies = identifyTechnologies;
    this.queueCveLookup = queueCveLookup;
    this.registerTechVersionsForHost = registerTechVersionsForHost;
    this.detectOpenApiForHost = detectOpenApiForHost;
    this.runtimeOptions = runtimeOptions;
    this.getVulnerabilitiesAnalytics = getVulnerabilitiesAnalytics;
    this.MAX_REQUESTS = 1000;
  }
  
  /**
   * Emit a record to be stored and broadcasted
   * 
   * @param {Object} params - Record parameters
   * @returns {Object} - Created record
   */
  emitRecord({ method, url, status, headers = {}, reqHeaders = {}, headersRaw = [], reqHeadersRaw = [] }) {
    try {
      const u = new URL(url);
      const record = {
        id: uuidv4(),
        timestamp: new Date().toISOString(),
        method,
        url,
        host: u.host,
        path: (u.pathname + (u.search || '') + (u.hash || '')),
        status,
        reqHeaders,
        headers,
        headersRaw,
        reqHeadersRaw,
        tech: this.identifyTechnologies(headers),
        hasOpenApi: false,
      };
      
      const isNewHost = record.host && !this.uniqueHosts.has(record.host);
      this.uniqueHosts.add(record.host);
      this.uniquePaths.add(record.path);
      
      this.requests.push(record);
      if (this.requests.length > this.MAX_REQUESTS) this.requests.shift();
      
      try { this.queueCveLookup(headers); } catch {}
      try { this.registerTechVersionsForHost(headers, record.host); } catch {}
      
      this.detectOpenApiForHost(record.host, u.protocol, this.openApiDocs).then(() => {
        const docs = this.openApiDocs.get(record.host) || [];
        record.hasOpenApi = docs.length > 0;
      });
      
      this.io.emit('request', record);
      
      // Aggressive fingerprinting when a host is first seen
      try {
        if (isNewHost && this.runtimeOptions.aggressiveFingerprinting) {
          setImmediate(() => this.aggressiveFingerprint(record.host, u.protocol).catch(() => {}));
        }
      } catch {}
      
      return record;
    } catch (e) {
      // ignore analytics failures
      console.error("Failed to emit record:", e);
      return null;
    }
  }
  
  /**
   * Perform aggressive fingerprinting for a host
   * 
   * @param {string} host - Hostname to fingerprint
   * @param {string} protocol - Protocol to use (http: or https:)
   * @returns {Promise<void>}
   */
  async aggressiveFingerprint(host, protocol = 'http:') {
    try {
      if (!host) return;
      const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];
      const path = '/%25%25?__snapshot_fp=1';
      const baseUrl = `${protocol}//${host}${path}`;
      const isHttps = protocol === 'https:';
      const lib = isHttps ? https : http;
  
      for (const m of methods) {
        await new Promise(resolve => {
          const headers = {
            'User-Agent': 'SnapShot-Aggressive/1.0',
            'Accept': '*/*',
            'X-Fingerprint': '1',
          };
          const u = new URL(baseUrl);
          const opts = {
            protocol: u.protocol,
            hostname: u.hostname,
            port: u.port || (isHttps ? 443 : 80),
            method: m,
            path: u.pathname + (u.search || ''),
            headers,
            rejectUnauthorized: false,
          };
          
          const req = lib.request(opts, resp => {
            const resHeaders = resp.headers || {};
            const status = resp.statusCode || 0;
            const raw = Array.isArray(resp.rawHeaders) ? resp.rawHeaders : [];
            this.emitRecord({ 
              method: m, 
              url: baseUrl, 
              status, 
              headers: resHeaders, 
              reqHeaders: headers, 
              headersRaw: raw, 
              reqHeadersRaw: [] 
            });
            // Drain
            resp.on('data', () => {});
            resp.on('end', () => resolve());
          });
          
          req.on('error', () => resolve());
          if (m === 'POST' || m === 'PUT' || m === 'PATCH') {
            try { req.write('malformed=%25%25'); } catch {}
          }
          try { req.end(); } catch { resolve(); }
        });
      }
    } catch (e) {
      console.error("Fingerprint error:", e);
    }
  }
  
  /**
   * Generate analytics data from collected information
   * 
   * @returns {Object} - Analytics data
   */
  generateAnalytics() {
    const hostnames = Array.from(this.uniqueHosts);
    const techCount = {};
    const statusCount = {};
    const methodCount = {};
  
    for (const r of this.requests) {
      (statusCount[r.status] = (statusCount[r.status] || 0) + 1);
      (methodCount[r.method] = (methodCount[r.method] || 0) + 1);
      for (const t of r.tech || []) techCount[t] = (techCount[t] || 0) + 1;
    }
  
    const openApiList = [];
    for (const [host, urls] of this.openApiDocs.entries()) {
      if (urls && urls.length) {
        openApiList.push({ host, urls });
      }
    }
  
    return {
      totals: { requests: this.requests.length },
      hostnames,
      technologies: techCount,
      methods: methodCount,
      statuses: statusCount,
      openApi: openApiList,
      vulnerabilities: this.getVulnerabilitiesAnalytics(),
    };
  }
}

export default AnalyticsService;