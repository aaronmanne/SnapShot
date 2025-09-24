import axios from 'axios';

// Lightweight spider with per-domain throttling and optional robots.txt respect.
// Public API: extractLinks, filterLinks, startSpider(seedUrl, seedHtml, cfg, seedUserAgent), stopSpider()
// Internally backed by a Spider class to follow OOP principles while keeping existing call sites unchanged.

const lastSpideredAt = new Map(); // export for callers that coordinate spidering cadence
let spiderEnabled = true; // global flag to enable/disable spidering

function extractLinks(html = '', baseUrl) {
    const results = new Set();
    if (!html || typeof html !== 'string') return [];
    const attrs = ['href', 'src'];
    for (const attr of attrs) {
        const regex = new RegExp(attr + '\\s*=\\s*(?:"([^"]*)"|' + "'([^']*)'" + '|([^\\s\"\'<>]+))', 'gi');
        let m;
        while ((m = regex.exec(html)) !== null) {
            const raw = (m[1] || m[2] || m[3] || '').trim();
            if (!raw) continue;
            const lower = raw.toLowerCase();
            if (lower.startsWith('#')) continue;
            if (lower.startsWith('javascript:') || lower.startsWith('mailto:') || lower.startsWith('tel:') || lower.startsWith('data:')) continue;
            try {
                const u = new URL(raw, baseUrl);
                if (u.protocol === 'http:' || u.protocol === 'https:') results.add(u.toString());
            } catch (_) {
            }
        }
    }
    const patterns = [
        /fetch\(\s*(["'`])([^"'`]+?)\1/gi,
        /axios\.(get|post|put|delete|patch|head)\(\s*(["'`])([^"'`]+?)\2/gi,
        /axios\(\s*{[\s\S]*?url\s*:\s*(["'`])([^"'`]+?)\1[\s\S]*?}\s*\)/gi,
        /\$\.ajax\(\s*{[\s\S]*?url\s*:\s*(["'`])([^"'`]+?)\1[\s\S]*?}\s*\)/gi,
        /jQuery\.ajax\(\s*{[\s\S]*?url\s*:\s*(["'`])([^"'`]+?)\1[\s\S]*?}\s*\)/gi,
        /\.open\(\s*(["'`])[A-Z]+\1\s*,\s*(["'`])([^"'`]+?)\2/gi,
    ];
    for (const re of patterns) {
        let m;
        while ((m = re.exec(html)) !== null) {
            const raw = (m[2] && m[3]) ? m[3] : m[2];
            if (!raw) continue;
            const lower = String(raw).toLowerCase().trim();
            if (!lower || lower.startsWith('javascript:') || lower.startsWith('data:')) continue;
            try {
                const u = new URL(raw, baseUrl);
                if (u.protocol === 'http:' || u.protocol === 'https:') results.add(u.toString());
            } catch (_) {
            }
        }
    }
    return Array.from(results);
}

function filterLinks(links, seedUrl, cfg = {}) {
    const out = [];
    const seed = new URL(seedUrl);
    for (const l of links) {
        try {
            const u = new URL(l);
            if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
            if (/[\.](?:png|jpg|jpeg|gif|webp|svg|ico|css|woff|woff2|ttf|otf|eot|pdf|zip|tar|gz|mp4|mp3|mov|avi)(?:[?#].*)?$/i.test(u.pathname)) continue;
            if (cfg.spiderSameOriginOnly && u.origin !== seed.origin) continue;
            out.push(u.toString());
        } catch (_) {
        }
    }
    return out;
}

class Spider {
    constructor(cfg = {}) {
        this.cfg = cfg;
        this.domainState = new Map();
        this.robotsCache = new Map();
        // We don't have direct access to emitRecord, but we can expose it later
        this.emitRecord = null;
    }

    getDomain(u) {
        try {
            return new URL(u).host;
        } catch {
            return '';
        }
    }

    enqueue(domain, fn) {
        return new Promise((resolve, reject) => {
            let st = this.domainState.get(domain);
            if (!st) {
                st = {queue: [], running: false, nextAt: 0};
                this.domainState.set(domain, st);
            }
            st.queue.push({fn, resolve, reject});
            this.runDomain(domain);
        });
    }

    runDomain(domain) {
        const state = this.domainState.get(domain);
        if (!state || state.running) return;
        state.running = true;
        (async () => {
            while (state.queue.length) {
                const now = Date.now();
                const rps = Math.max(1, Number(this.cfg.spiderRequestsPerSec || 1)); // 1 request per second is a reasonable default
                const intervalMs = Math.floor(1000 / rps);
                const delay = Math.max(0, state.nextAt - now);
                if (delay > 0) await new Promise(r => setTimeout(r, delay));
                const job = state.queue.shift();
                state.nextAt = Date.now() + intervalMs;
                try {
                    job.resolve(await job.fn());
                } catch (e) {
                    job.reject(e);
                }
            }
            state.running = false;
        })().catch(() => {
            state.running = false;
        });
    }

    async isAllowedByRobots(urlStr, defaultUA) {
        if (!this.cfg.spiderRespectRobots) return true;
        let u;
        try {
            u = new URL(urlStr);
        } catch {
            return true;
        }
        const origin = u.origin;
        const ua = (defaultUA || '').toLowerCase();
        let entry = this.robotsCache.get(origin);
        if (!entry) {
            try {
                const res = await axios.get(origin + '/robots.txt', {
                    timeout: Math.min(4000, this.cfg.spiderTimeoutMs || 8000),
                    maxRedirects: 2,
                    validateStatus: () => true,
                    headers: {'User-Agent': defaultUA, 'Accept': 'text/plain,*/*;q=0.1'},
                });
                if (res.status === 200 && typeof res.data === 'string') {
                    entry = {groups: this.parseRobots(res.data)};
                } else {
                    entry = {groups: []};
                }
            } catch {
                entry = {groups: []};
            }
            this.robotsCache.set(origin, entry);
        }
        const uaGroups = (entry.groups || []).filter(g => (g.agents || []).some(a => a === '*' || (ua && ua.includes(a))));
        const rules = uaGroups.length ? uaGroups.flatMap(g => g.rules || []) : [];
        if (!rules.length) return true;
        const decision = this.longestRuleDecision(rules, u.pathname);
        if (!decision) return true;
        return decision !== 'disallow';
    }

    parseRobots(text) {
        const lines = String(text || '').split(/\r?\n/).map(l => l.replace(/#.*/, '').trim()).filter(Boolean);
        const groups = [];
        let current = null;
        for (const line of lines) {
            const idx = line.indexOf(':');
            if (idx === -1) continue;
            const key = line.slice(0, idx).trim().toLowerCase();
            const value = line.slice(idx + 1).trim();
            if (key === 'user-agent') {
                if (!current || current.rules.length || current.agents.length === 0) {
                    current = {agents: [], rules: []};
                    groups.push(current);
                }
                current.agents.push(value.toLowerCase());
            } else if (key === 'allow' || key === 'disallow') {
                if (!current) {
                    current = {agents: ['*'], rules: []};
                    groups.push(current);
                }
                current.rules.push({type: key, path: value});
            }
        }
        return groups;
    }

    longestRuleDecision(rules, path) {
        let decided = null;
        let maxLen = -1;
        for (const r of rules) {
            const p = r.path || '';
            if (!p) continue;
            if (path.startsWith(p) && p.length > maxLen) {
                decided = r.type;
                maxLen = p.length;
            }
        }
        return decided;
    }

    async start(seedUrl, seedHtml, seedUserAgent = '') {
        try {
            console.log(`[SPIDER] Starting to spider from ${seedUrl}`);

            // Check if spidering is globally enabled
            if (!spiderEnabled) {
                console.log('[SPIDER] Spidering is currently disabled');
                return;
            }

            const cfg = this.cfg;
            const maxDepth = Number(cfg.spiderDepth || 0);
            if (!maxDepth) {
                console.log('[SPIDER] Spidering disabled (spiderDepth is 0)');
                return;
            }
            const maxPages = Number(cfg.spiderMaxPerSeed || 10);
            const defaultUA = seedUserAgent && String(seedUserAgent).trim() ? String(seedUserAgent).trim() : 'Mozilla/5.0 Firefox/143.0';

            const hasSeedHtml = !!(seedHtml && typeof seedHtml === 'string' && seedHtml.length > 0);
            const seedAbs = new URL(seedUrl).toString();
            const visited = new Set(hasSeedHtml ? [seedAbs] : []);
            let frontier = hasSeedHtml ? filterLinks(extractLinks(seedHtml, seedUrl), seedUrl, cfg) : [seedAbs];

            const allToFetch = new Set();
            for (const url of frontier) {
                if (visited.has(url)) continue;
                allToFetch.add(url);
            }

            let depth = 1;
            while (depth <= maxDepth && allToFetch.size && spiderEnabled) {
                // Exit the loop if spidering has been disabled
                if (!spiderEnabled) {
                    console.log('[SPIDER] Spidering stopped due to global disable');
                    break;
                }

                const batch = Array.from(allToFetch);
                allToFetch.clear();
                const concurrency = 5;
                for (let i = 0; i < batch.length && spiderEnabled; i += concurrency) {
                    const slice = batch.slice(i, i + concurrency);
                    await Promise.all(slice.map(async (url) => {
                        if (visited.has(url)) return;
                        visited.add(url);
                        const domain = this.getDomain(url);
                        try {
                            if (!(await this.isAllowedByRobots(url, defaultUA))) return;
                            const res = await this.enqueue(domain, async () => {
                                console.log(`[SPIDER] Fetching ${url}`);
                                return axios.get(url, {
                                    timeout: cfg.spiderTimeoutMs || 8000,
                                    maxRedirects: 3,
                                    validateStatus: () => true,
                                    headers: {
                                        'User-Agent': defaultUA,
                                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                                    },
                                });
                            });
                            const headers = res.headers || {};
                            const status = res.status || 0;
                            console.log(`[SPIDER] Fetched ${url} - Status: ${status}`);

                            // Emit record to UI if emitRecord function is available
                            if (typeof this.emitRecord === 'function') {
                                try {
                                    // Extract raw headers
                                    let headersRaw = [];
                                    let reqHeadersRaw = [];

                                    if (res.headers) {
                                        for (const [hk, hv] of Object.entries(res.headers)) {
                                            if (Array.isArray(hv)) {
                                                for (const v of hv) headersRaw.push(hk, String(v));
                                            } else {
                                                headersRaw.push(hk, String(hv));
                                            }
                                        }
                                    }

                                    // Build request headers with user-agent
                                    const reqHeaders = {
                                        'User-Agent': defaultUA,
                                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                                    };

                                    // Convert reqHeaders to raw format
                                    for (const [hk, hv] of Object.entries(reqHeaders)) {
                                        reqHeadersRaw.push(hk, String(hv));
                                    }

                                    // Emit the record with [SPIDER] tag
                                    this.emitRecord({
                                        method: 'GET',
                                        url: url,
                                        status: status,
                                        headers: res.headers,
                                        reqHeaders: reqHeaders,
                                        headersRaw: headersRaw,
                                        reqHeadersRaw: reqHeadersRaw,
                                        spider: true // Mark as coming from the spider
                                    });
                                } catch (err) {
                                    console.error('[SPIDER] Error emitting record:', err);
                                }
                            }
                            if (depth < maxDepth && status === 200 && String(headers['content-type'] || '').toLowerCase().includes('text/html')) {
                                const more = filterLinks(extractLinks(String(res.data || ''), url), seedUrl, cfg);
                                for (const m of more) if (!visited.has(m)) allToFetch.add(m);
                            }
                        } catch (_) {
                        }
                    }));
                }
                depth += 1;
            }
        } catch (_) {
        }
    }
}

// Keep call sites unchanged by exposing a function
function startSpider(seedUrl, seedHtml, cfg, seedUserAgent, emitRecord) {
    if (!spiderEnabled) {
        //console.log('[SPIDER] Spidering is disabled, not starting spider.');
        return;
    }
    console.log(`[SPIDER] startSpider called for ${seedUrl} with config:`, {
        spiderDepth: cfg.spiderDepth,
        spiderMaxPerSeed: cfg.spiderMaxPerSeed,
        spiderSameOriginOnly: cfg.spiderSameOriginOnly
    });

    // We do NOT automatically re-enable spidering if it was explicitly disabled
    // This allows the Stop Spider button to work effectively
    // spiderEnabled can only be set to true by explicit user action through the UI

    const spider = new Spider(cfg);

    // Set emitRecord function if provided
    if (typeof emitRecord === 'function') {
        spider.emitRecord = emitRecord;
    } else {
        console.log('[SPIDER] No emitRecord function provided, spider results won\'t appear in UI');
    }

    return spider.start(seedUrl, seedHtml, seedUserAgent);
}

/**
 * Stops all spidering operations by setting the global flag to false
 * @returns {Object} Status object indicating spidering is disabled
 */
function stopSpider() {
    console.log('[SPIDER] Stopping all spider operations');
    spiderEnabled = false;
    return {spidering: false};
}

/**
 * Returns the current status of the spider
 * @returns {Object} Status object with spidering flag
 */
function getSpiderStatus() {
    return {spidering: spiderEnabled};
}

/**
 * Explicitly enables the spider
 * This function should only be called when a user explicitly requests to start spidering
 * @returns {Object} Status object indicating spidering is enabled
 */
function enableSpider() {
    console.log('[SPIDER] Explicitly enabling spider');
    spiderEnabled = true;
    return {spidering: true};
}

export {extractLinks, filterLinks, startSpider, stopSpider, getSpiderStatus, enableSpider, lastSpideredAt};
export default Spider;
