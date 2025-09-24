import axios from 'axios';
import config from '../../config.js';

// SecurityService encapsulates technology identification, runtime vuln detection, CVE lookups and analytics.
// To minimize changes to existing code, we export both a singleton instance and plain functions that delegate.

class SecurityService {
  constructor() {
    this.vulnsByTechVersion = new Map(); // key: `${product}@${version}` -> { product, version, items: [...] }
    this.pendingCveLookups = new Set();
    this.techVersionHosts = new Map(); // key: `${product}@${version}` -> Set(hostnames)
    this.runtimeFindings = [];
    this.MAX_RUNTIME_FINDINGS = 200;
  }

  identifyTechnologies(headers = {}) {
    const tech = new Set();
    const lower = {};
    for (const [k, v] of Object.entries(headers || {})) lower[k.toLowerCase()] = String(v || '');
    const server = lower['server'];
    const powered = lower['x-powered-by'];
    const via = lower['via'];
    const setCookie = lower['set-cookie'] || '';

    if (server) {
      const s = server.toLowerCase();
      if (s.includes('nginx')) tech.add('nginx');
      if (s.includes('apache')) tech.add('apache');
      if (s.includes('cloudflare')) tech.add('cloudflare');
      if (s.includes('iis')) tech.add('microsoft iis');
      if (s.includes('caddy')) tech.add('caddy');
      if (s.includes('gunicorn')) tech.add('gunicorn');
      if (s.includes('tomcat')) tech.add('apache tomcat');
      if (s.includes('jetty')) tech.add('eclipse jetty');
      if (s.includes('litepeed') || s.includes('litespeed')) tech.add('litespeed');
    }

    const poweredStr = [powered, lower['x-generator'], lower['x-runtime'], lower['x-drupal-cache'], lower['x-aspnet-version'], lower['x-aspnetmvc-version']].filter(Boolean).join(' | ').toLowerCase();
    if (poweredStr.includes('express')) tech.add('express');
    if (poweredStr.includes('php')) tech.add('php');
    if (poweredStr.includes('asp.net')) tech.add('asp.net');
    if (poweredStr.includes('next.js')) tech.add('next.js');
    if (poweredStr.includes('nestjs')) tech.add('nestjs');
    if (poweredStr.includes('rails') || poweredStr.includes('x-runtime')) tech.add('rails');
    if (poweredStr.includes('laravel')) tech.add('laravel');
    if (poweredStr.includes('django')) tech.add('django');
    if (poweredStr.includes('spring')) tech.add('spring');
    if (poweredStr.includes('wordpress') || poweredStr.includes('wp')) tech.add('wordpress');
    if (poweredStr.includes('drupal')) tech.add('drupal');

    if (via && via.toLowerCase().includes('varnish')) tech.add('varnish');
    if (lower['cf-ray'] || lower['cf-cache-status'] || (server && server.toLowerCase().includes('cloudflare'))) tech.add('cloudflare');
    if (lower['x-akamai-transformed'] || lower['akamai-grn'] || lower['x-akamai-request-id']) tech.add('akamai');
    if (lower['x-served-by'] && lower['x-served-by'].toLowerCase().includes('cache-')) tech.add('fastly');
    if ((lower['x-cache'] || '').toLowerCase().includes('hit')) tech.add('edge cache');

    const cookieStr = setCookie.toLowerCase();
    if (cookieStr.includes('phpsessid') || cookieStr.includes('wordpress_') || cookieStr.includes('wp-settings')) tech.add('wordpress');
    if (cookieStr.includes('laravel_session')) tech.add('laravel');
    if (cookieStr.includes('django') || cookieStr.includes('csrftoken') || cookieStr.includes('sessionid')) tech.add('django');
    if (cookieStr.includes('jsessionid')) tech.add('java');
    if (cookieStr.includes('mage-cache') || cookieStr.includes('magento')) tech.add('magento');

    return Array.from(tech);
  }

  extractTechVersions(headers = {}) {
    const out = [];
    const seen = new Set();
    const lower = {};
    for (const [k, v] of Object.entries(headers || {})) lower[k.toLowerCase()] = String(v || '');
    const candidates = [lower['server'], lower['x-powered-by'], lower['x-aspnet-version'], lower['x-aspnetmvc-version']].filter(Boolean);
    const re = /([A-Za-z][A-Za-z0-9+._\- ]{0,40})\/(\d+[A-Za-z0-9+._\-]*)/g; // product/version
    for (const cand of candidates) {
      let m;
      const str = String(cand);
      while ((m = re.exec(str)) !== null) {
        let product = (m[1] || '').trim().replace(/\s+/g, ' ');
        const version = (m[2] || '').trim();
        if (!product || !version) continue;
        const pl = product.toLowerCase();
        if (pl.includes('microsoft-iis') || pl === 'iis') product = 'Microsoft IIS';
        else if (pl === 'apache') product = 'Apache HTTP Server';
        else if (pl.includes('tomcat')) product = 'Apache Tomcat';
        else if (pl.includes('jetty')) product = 'Eclipse Jetty';
        else if (pl.includes('express')) product = 'Express';
        else if (pl === 'php') product = 'PHP';
        else if (pl === 'nginx') product = 'nginx';
        const key = `${product}@${version}`;
        if (!seen.has(key)) { seen.add(key); out.push({ product, version }); }
      }
    }
    return out;
  }

  registerTechVersionsForHost(headers = {}, host = '') {
    try {
      if (!host) return;
      const pairs = this.extractTechVersions(headers);
      for (const { product, version } of pairs) {
        const key = `${product}@${version}`;
        let set = this.techVersionHosts.get(key);
        if (!set) { set = new Set(); this.techVersionHosts.set(key, set); }
        set.add(host);
      }
    } catch {}
  }

  async fetchCvesFor(product, version) {
    try {
      if (!config.cveLookupEnabled) return [];
      const key = `${product}@${version}`;
      if (this.vulnsByTechVersion.has(key)) return this.vulnsByTechVersion.get(key).items;
      const base = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
      const keyword = encodeURIComponent(`${product} ${version}`);
      const url = `${base}?keywordSearch=${keyword}&resultsPerPage=${encodeURIComponent(config.nvdResultsPerTech || 5)}`;
      const headers = {};
      if (config.nvdApiKey) headers['apiKey'] = config.nvdApiKey;
      const res = await axios.get(url, { timeout: 12000, headers, validateStatus: () => true });
      const items = [];
      if (res.status < 400 && res.data && Array.isArray(res.data.vulnerabilities)) {
        for (const v of res.data.vulnerabilities) {
          const c = v.cve || {};
          const id = c.id || c.CVEID || c.cveId;
          if (!id) continue;
          let title = '';
          const descArr = (c.descriptions || c.description || []);
          if (Array.isArray(descArr) && descArr.length) {
            const en = descArr.find(d => (d.lang || d.lang === 'en' || d.lang === 'EN') && d.value) || descArr[0];
            title = (en && (en.value || en.text)) || '';
          }
          let severity = '';
          try {
            const m31 = c.metrics?.cvssMetricV31 || c.metrics?.cvssMetricV30;
            if (Array.isArray(m31) && m31.length) severity = m31[0].cvssData?.baseSeverity || '';
            if (!severity && Array.isArray(c.metrics?.cvssMetricV2) && c.metrics.cvssMetricV2.length) severity = c.metrics.cvssMetricV2[0].baseSeverity || '';
          } catch {}
          const url = `https://nvd.nist.gov/vuln/detail/${id}`;
          items.push({ tech: product, version, cveId: id, severity, title, url });
        }
      }
      this.vulnsByTechVersion.set(key, { product, version, items });
      return items;
    } catch (e) {
      return [];
    }
  }

  queueCveLookup(headers = {}) {
    try {
      if (!config.cveLookupEnabled) return;
      const pairs = this.extractTechVersions(headers);
      for (const { product, version } of pairs) {
        const key = `${product}@${version}`;
        if (this.vulnsByTechVersion.has(key) || this.pendingCveLookups.has(key)) continue;
        this.pendingCveLookups.add(key);
        setImmediate(async () => {
          try { await this.fetchCvesFor(product, version); }
          catch {}
          finally { this.pendingCveLookups.delete(key); }
        });
      }
    } catch {}
  }

  getVulnerabilitiesAnalytics() {
    const out = [];
    for (const f of this.runtimeFindings) out.push(f);
    for (const entry of this.vulnsByTechVersion.values()) {
      const key = `${entry.product}@${entry.version}`;
      const hosts = this.techVersionHosts.get(key);
      if (hosts && hosts.size) {
        for (const item of entry.items || []) {
          for (const h of hosts) {
            out.push({ ...item, host: h });
          }
        }
      } else {
        for (const item of entry.items || []) out.push(item);
      }
    }
    const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    out.sort((a, b) => (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0) || String(b.cveId).localeCompare(String(a.cveId)));
    return out;
  }

  detectRuntimeVulns(record, body, headers = {}) {
    try {
      const findings = [];
      const url = record?.url || '';
      const method = record?.method || '';
      const host = record?.host || '';
      const ct = String(headers['content-type'] || headers['Content-Type'] || '').toLowerCase();
      const isText = ct.includes('text') || ct.includes('json') || ct.includes('html') || ct.includes('xml');
      const text = isText ? String(body || '') : '';

      if (isText && text) {
        const xssPatterns = [
          /<script[^>]*>.*?<\/script>/is,
          /onerror\s*=\s*"?\w+\(/i,
          /<img[^>]+onerror=/i,
          /<svg[^>]+onload=/i,
        ];
        const m = xssPatterns.find(re => re.test(text));
        if (m) {
          findings.push({ type: 'XSS', cveId: '[XSS]'.toUpperCase(), severity: 'MEDIUM', title: `Response looks like it may reflect unsanitized HTML/JS`, url, tech: 'XSS', version: host || '', indicator: m.toString(), method, at: record?.timestamp });
        }
      }

      if (isText && text) {
        const sqliPatterns = [ /You have an error in your SQL syntax/i, /warning:\s*mysql/i, /pg_query\(/i, /sqlite_error/i, /ORA-\d{5}/i ];
        const m = sqliPatterns.find(re => re.test(text));
        if (m) {
          findings.push({ type: 'SQLi', cveId: '[SQLI]'.toUpperCase(), severity: 'HIGH', title: `Response contains SQL error indicator: ${m.toString()}`, url, tech: 'SQL', version: host || '', indicator: m.toString(), method, at: record?.timestamp });
        }
      }

      if (isText && text) {
        const lfiPatterns = [/root:x:0:0:.*:.*:.*\n/i, /failed to open stream:.*No such file or directory/i, /in\s+.*\.(php|inc)\s+on line\s+\d+/i, /allow_url_fopen/i, /<\?php/i];
        const m = lfiPatterns.find(re => re.test(text));
        if (m) {
          findings.push({ type: 'LFI', cveId: '[LFI]'.toUpperCase(), severity: 'HIGH', title: `Response contains file inclusion/disclosure indicator: ${m.toString()}`, url, tech: 'File Inclusion', version: host || '', indicator: m.toString(), method, at: record?.timestamp });
        }
      }

      return findings;
    } catch {
      return [];
    }
  }

  addRuntimeFindings(items = []) {
    if (!Array.isArray(items) || !items.length) return;
    for (const it of items) {
      this.runtimeFindings.push(it);
      if (this.runtimeFindings.length > this.MAX_RUNTIME_FINDINGS) this.runtimeFindings.shift();
    }
  }
}

const security = new SecurityService();

// Export instance state for code that serializes state
const vulnsByTechVersion = security.vulnsByTechVersion;
const techVersionHosts = security.techVersionHosts;
const runtimeFindings = security.runtimeFindings;

// Plain function exports to minimize changes in index.js
const identifyTechnologies = (...args) => security.identifyTechnologies(...args);
const extractTechVersions = (...args) => security.extractTechVersions(...args);
const registerTechVersionsForHost = (...args) => security.registerTechVersionsForHost(...args);
const fetchCvesFor = (...args) => security.fetchCvesFor(...args);
const queueCveLookup = (...args) => security.queueCveLookup(...args);
const getVulnerabilitiesAnalytics = (...args) => security.getVulnerabilitiesAnalytics(...args);
const detectRuntimeVulns = (...args) => security.detectRuntimeVulns(...args);
const addRuntimeFindings = (...args) => security.addRuntimeFindings(...args);

export default security;
export { identifyTechnologies, extractTechVersions, registerTechVersionsForHost, fetchCvesFor, queueCveLookup, getVulnerabilitiesAnalytics, detectRuntimeVulns, addRuntimeFindings, vulnsByTechVersion, techVersionHosts, runtimeFindings };
