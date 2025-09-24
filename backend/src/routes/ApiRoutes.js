import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { performInvestigation, generatePrompt } from '../services/LlmService.js';
import { exportProject, importProject, purgeData } from '../services/ProjectService.js';
import { startSpider, stopSpider, getSpiderStatus, enableSpider } from '../utils/Spider.js';

/**
 * Configure and return API routes
 * 
 * @param {Object} dependencies - Injected dependencies
 * @returns {express.Router} - Configured router
 */
function configureRoutes({ 
  requests,
  uniqueHosts,
  uniquePaths,
  openApiDocs,
  vulnsByTechVersion,
  techVersionHosts,
  runtimeFindings,
  llmInvestigations,
  config,
  security,
  io,
  proxy,
  FORWARD_PROXY_PORT,
  runtimeOptions,
  analyticsService
}) {
  const router = express.Router();
  
  // Health/info root route
  router.get('/', (req, res) => {
    res.status(200).json({
      service: 'SnapShot backend',
      status: 'ok',
      message: 'This is the API service. Open the UI at the frontend (e.g., port 3000) to use the app.',
      endpoints: ['/api/requests', '/api/analytics', '/api/fuzz/generate', '/proxy']
    });
  });

  // Requests API
  router.get('/api/requests', (req, res) => {
    const { q, method, status, host } = req.query;
    let data = [...requests].reverse();
    
    if (q) {
      const k = String(q).toLowerCase();
      data = data.filter(r =>
        r.url.toLowerCase().includes(k) ||
        r.method.toLowerCase().includes(k) ||
        (r.status + '').includes(k) ||
        (r.host && r.host.toLowerCase().includes(k)) ||
        (r.path && r.path.toLowerCase().includes(k))
      );
    }
    
    if (host) data = data.filter(r => r.host === String(host));
    if (method) data = data.filter(r => r.method.toUpperCase() === String(method).toUpperCase());
    if (status) data = data.filter(r => String(r.status) === String(status));
    
    res.json({ items: data });
  });

  // Analytics API
  router.get('/api/analytics', (req, res) => {
    res.json(analyticsService.generateAnalytics());
  });

  // Options API
  router.get('/api/options', (req, res) => {
    res.json({ ...runtimeOptions });
  });
  
  router.post('/api/options', (req, res) => {
    try {
      const { aggressiveFingerprinting, llmEnabled, llmApiType } = req.body || {};
      if (typeof aggressiveFingerprinting === 'boolean') runtimeOptions.aggressiveFingerprinting = aggressiveFingerprinting;
      if (typeof llmEnabled === 'boolean') runtimeOptions.llmEnabled = llmEnabled;
      
      // Handle LLM API type
      if (llmApiType && typeof llmApiType === 'string') {
        // Validate that it's one of the supported types
        const validTypes = ['LMStudio', 'Ollama', 'OpenAI', 'Gemini'];
        if (validTypes.includes(llmApiType)) {
          runtimeOptions.llmApiType = llmApiType;
          // Also update in the global config
          config.llmApiType = llmApiType;
        } else {
          return res.status(400).json({ error: 'Invalid LLM API type', validTypes });
        }
      }
      
      res.json({ ...runtimeOptions });
    } catch (e) {
      res.status(400).json({ error: 'Invalid options payload', message: e?.message || String(e) });
    }
  });

  // LLM Investigation API
  router.post('/api/llm/prompt', async (req, res) => {
    try {
      const { vulnerability, requestId } = req.body || {};
      if (!vulnerability || typeof vulnerability !== 'object') {
        res.status(400).json({ error: 'Missing vulnerability' });
        return;
      }
      
      const { key, input, prompt } = generatePrompt(vulnerability, requestId, requests);
      res.json({ key, input, prompt });
    } catch (e) {
      res.status(500).json({ error: 'Failed to build prompt', message: e?.message || String(e) });
    }
  });

  router.post('/api/llm/investigate', async (req, res) => {
    try {
      const { vulnerability, requestId, force, customPrompt } = req.body || {};
      if (!vulnerability || typeof vulnerability !== 'object') {
        res.status(400).json({ error: 'Missing vulnerability' });
        return;
      }
      
      // Create a config with the runtime options
      const configWithRuntime = {
        ...config,
        // Override with current runtime options if they exist
        llmApiType: runtimeOptions.llmApiType || config.llmApiType
      };
      
      // If customPrompt is provided, use it instead of generating one
      let result;
      if (customPrompt) {
        // Use the custom prompt directly with the LLM
        const key = vulnerability.cveId || vulnerability.type || '';
        result = await performInvestigation(vulnerability, requestId, force, configWithRuntime, requests, customPrompt);
      } else {
        // Use the default generated prompt
        result = await performInvestigation(vulnerability, requestId, force, configWithRuntime, requests);
      }
      
      res.json(result);
    } catch (e) {
      const msg = e?.message || String(e);
      res.status(500).json({ error: 'Investigation failed', message: msg });
    }
  });

  // Purge API
  router.post('/api/purge', (req, res) => {
    try {
      const success = purgeData(
        requests,
        uniqueHosts,
        uniquePaths,
        openApiDocs,
        vulnsByTechVersion,
        runtimeFindings,
        techVersionHosts,
        security
      );
      
      io.emit('purged', { at: new Date().toISOString() });
      res.json({ ok: success });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // Fuzz test generation
  router.post('/api/fuzz/generate', (req, res) => {
    const { q, method, status, host, fuzzOptions } = req.body || {};
    let data = [...requests];
    
    if (q) {
      const k = String(q).toLowerCase();
      data = data.filter(r =>
        r.url.toLowerCase().includes(k) ||
        r.method.toLowerCase().includes(k) ||
        (r.status + '').includes(k) ||
        (r.host && r.host.toLowerCase().includes(k)) ||
        (r.path && r.path.toLowerCase().includes(k))
      );
    }
    
    if (host) data = data.filter(r => r.host === String(host));
    if (method) data = data.filter(r => r.method.toUpperCase() === String(method).toUpperCase());
    if (status) data = data.filter(r => String(r.status) === String(status));

    // Build unique host+path targets (per URL path)
    const byPath = new Map();
    for (const r of data) {
      try {
        const u = new URL(r.url);
        const key = `${u.host}${u.pathname}`;
        if (!byPath.has(key)) {
          // Determine preferred User-Agent: config override, else original client UA
          let ua = String((config.fuzzUserAgent || '').trim());
          if (!ua) {
            const rh = r.reqHeaders || {};
            ua = String(rh['user-agent'] || rh['User-Agent'] || '').trim();
          }
          byPath.set(key, { host: u.host, origin: u.origin, path: u.pathname, search: u.search, ua });
        } else {
          const entry = byPath.get(key);
          if (!entry.ua) {
            const rh = r.reqHeaders || {};
            const ua = String(rh['user-agent'] || rh['User-Agent'] || '').trim();
            if (ua) entry.ua = ua;
          }
        }
      } catch {}
    }

    const selected = new Set();
    const opts = fuzzOptions || {};
    for (const [k, v] of Object.entries(opts)) { if (v) selected.add(k); }
    
    // Minimal built-in fuzzdb-style payload sets
    const FUZZDB = {
      xss: ["<script>alert(1)</script>", '\"/><img src=x onerror=alert(1)>', "<svg/onload=alert(1)>", "'></script><script>alert(1)</script>"],
      sqli: ["' OR 1=1 -- ", '" OR "1"="1', "') OR ('1'='1", "or 1=1--"],
      path_traversal: ['../etc/passwd', '..\\..\\..\\windows\\win.ini', '..%2f..%2f..%2fetc%2fpasswd'],
      lfi: ['../../../../etc/passwd', '/etc/passwd', '../app/config.php'],
      rfi: ['http://example.com/shell.txt', 'http://evil.com/evil.txt'],
      command_injection: ['; id', '&& whoami', '| cat /etc/passwd'],
      headers_common: ['../../etc/passwd', "<script>alert(1)</script>", "' OR 1=1 --"],
    };

    // Determine which payloads to use
    let payloads = [];
    if (selected.size) {
      for (const cat of selected) {
        if (FUZZDB[cat]) payloads = payloads.concat(FUZZDB[cat]);
      }
    } else {
      // default to a safe small set if nothing selected
      payloads = FUZZDB.xss.slice(0,2).concat(FUZZDB.sqli.slice(0,2));
    }
    // Deduplicate and clamp
    payloads = Array.from(new Set(payloads)).slice(0, 100);

    const lines = [];
    for (const t of byPath.values()) {
      const baseUrl = `${t.origin}${t.path}`;
      const methods = ['GET', 'POST'];
      const uaHeader = String((config.fuzzUserAgent || '').trim() || t.ua || 'SnapShotFuzzer/1.0');
      for (const m of methods) {
        for (const pay of payloads) {
          const headers = [];
          // Include some fuzz headers; if headers_common selected, embed payload
          const headerSamples = [
            ['X-Forwarded-For', '127.0.0.1'],
            ['X-Originating-IP', '127.0.0.1'],
            ['X-Test', selected.has('headers_common') ? String(pay) : 'fuzz'],
            ['User-Agent', uaHeader],
          ];
          for (const [hk, hv] of headerSamples) headers.push(`-H ${JSON.stringify(hk + ': ' + hv)}`);

          const proxyArg = `--proxy http://localhost:${FORWARD_PROXY_PORT}`;
          if (m === 'GET') {
            const hasQuery = Boolean(t.search && t.search.length > 0);
            const qs = hasQuery ? '&' : '?';
            const urlWithQuery = baseUrl + (hasQuery ? t.search : '') + `${qs}fuzz=${encodeURIComponent(pay)}`;
            lines.push(`curl -i -k -X ${m} ${proxyArg} ${headers.join(' ')} ${JSON.stringify(urlWithQuery)}`.replace(/\s+/g, ' ').trim());
          } else {
            const dataArg = `--data ${JSON.stringify('fuzz=' + pay)}`;
            lines.push(`curl -i -k -X ${m} ${proxyArg} ${headers.join(' ')} ${dataArg} ${JSON.stringify(baseUrl)}`.replace(/\s+/g, ' ').trim());
          }
        }
      }
    }

    const output = lines.join('\n');
    const filename = `snapshot-fuzz-${Date.now()}.txt`;
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
    res.send(output);
  });

  // Project export/import
  router.get('/api/project/export', (req, res) => {
    try {
      const snapshot = exportProject(
        requests,
        uniqueHosts,
        uniquePaths,
        openApiDocs,
        vulnsByTechVersion,
        techVersionHosts,
        runtimeFindings,
        llmInvestigations,
        config
      );
      
      res.setHeader('Content-Type', 'application/json');
      res.json(snapshot);
    } catch (e) {
      res.status(500).json({ error: 'Export failed', message: e?.message || String(e) });
    }
  });

  router.post('/api/project/import', (req, res) => {
    try {
      const result = importProject(
        req.body || {},
        requests,
        uniqueHosts,
        uniquePaths,
        openApiDocs,
        vulnsByTechVersion,
        runtimeFindings,
        techVersionHosts,
        llmInvestigations
      );
      
      // Notify clients without triggering spidering or lookups
      io.emit('imported', { at: new Date().toISOString(), counts: { requests: requests.length } });
      res.json({ ok: true, counts: { requests: requests.length } });
    } catch (e) {
      res.status(500).json({ error: 'Import failed', message: e?.message || String(e) });
    }
  });

  // Spider API
  router.post('/api/spider/from', (req, res) => {
    try {
      const { url, userAgent } = req.body || {};
      if (!url) {
        res.status(400).json({ error: 'Missing url' });
        return;
      }
      
      try {
        new URL(url);
      } catch {
        res.status(400).json({ error: 'Invalid url' });
        return;
      }
      
      // Explicitly enable spidering when requested through the API
      // This ensures spidering is only enabled when directly requested by the user
      // We use the dedicated enableSpider function to set the global flag
      enableSpider();
      
      setImmediate(() => startSpider(url, '', config, String(userAgent || ''), analyticsService.emitRecord.bind(analyticsService)).catch(() => {}));
      res.json({ started: true });
    } catch (e) {
      res.status(500).json({ error: 'Failed to start spider', message: e?.message || String(e) });
    }
  });
  
  // Spider status API
  router.get('/api/spider/status', (req, res) => {
    try {
      const status = getSpiderStatus();
      res.json(status);
    } catch (e) {
      res.status(500).json({ error: 'Failed to get spider status', message: e?.message || String(e) });
    }
  });
  
  // Stop spider API
  router.post('/api/spider/stop', (req, res) => {
    try {
      const result = stopSpider();
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: 'Failed to stop spider', message: e?.message || String(e) });
    }
  });
  
  // Proxy API
  router.all('/proxy', async (req, res) => {
    try {
      const target = req.query.url || req.headers['x-target-url'];
      if (!target) {
        return res.status(400).json({ error: 'Missing target URL. Provide ?url=... or X-Target-URL header.' });
      }
      
      // Validate URL
      let parsed;
      try {
        parsed = new URL(target);
      } catch (e) {
        return res.status(400).json({ error: 'Invalid target URL.' });
      }
      
      req.proxiedTargetUrl = parsed.toString();
      proxy.web(req, res, { target: parsed.toString(), ignorePath: true, changeOrigin: true, secure: false });
    } catch (e) {
      res.status(500).json({ error: 'Proxy exception', details: e.message });
    }
  });

  return router;
}

export default configureRoutes;