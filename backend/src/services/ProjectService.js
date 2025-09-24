// Project Service
// Handles import/export functionality and data management

/**
 * Exports the current project state
 * @param {Array} requests - Request history
 * @param {Set} uniqueHosts - Set of unique hosts
 * @param {Set} uniquePaths - Set of unique paths
 * @param {Map} openApiDocs - OpenAPI documentation map
 * @param {Map} vulnsByTechVersion - Vulnerabilities by tech version
 * @param {Map} techVersionHosts - Tech versions by host
 * @param {Array} runtimeFindings - Runtime vulnerability findings
 * @param {Map} llmInvestigations - LLM investigations
 * @param {Object} config - Project configuration
 * @returns {Object} - Serialized project data
 */
function exportProject(
  requests = [],
  uniqueHosts = new Set(),
  uniquePaths = new Set(),
  openApiDocs = new Map(),
  vulnsByTechVersion = new Map(),
  techVersionHosts = new Map(),
  runtimeFindings = [],
  llmInvestigations = new Map(),
  config = {}
) {
  try {
    const snapshot = {
      type: 'snapshot-project',
      version: 1,
      exportedAt: new Date().toISOString(),
      backend: {
        config: {
          spiderDepth: config.spiderDepth,
          spiderMaxPerSeed: config.spiderMaxPerSeed,
          spiderSameOriginOnly: config.spiderSameOriginOnly,
          spiderTimeoutMs: config.spiderTimeoutMs,
          spiderRequestsPerSec: config.spiderRequestsPerSec,
          spiderRespectRobots: config.spiderRespectRobots,
        }
      },
      state: {
        requests,
        uniqueHosts: Array.from(uniqueHosts),
        uniquePaths: Array.from(uniquePaths),
        openApiDocs: Array.from(openApiDocs.entries()),
        vulnsByTechVersion: Array.from(vulnsByTechVersion.entries()),
        techVersionHosts: Array.from(techVersionHosts.entries()).map(([k, v]) => [k, Array.from(v || [])]),
        runtimeFindings,
        llmInvestigations: Array.from(llmInvestigations.entries()),
      }
    };
    
    return snapshot;
  } catch (e) {
    throw new Error(`Export failed: ${e.message || String(e)}`);
  }
}

/**
 * Imports project data
 * @param {Object} data - Project data to import
 * @param {Array} requests - Request history reference to update
 * @param {Set} uniqueHosts - Set of unique hosts to update
 * @param {Set} uniquePaths - Set of unique paths to update
 * @param {Map} openApiDocs - OpenAPI documentation map to update
 * @param {Map} vulnsByTechVersion - Vulnerabilities by tech version to update
 * @param {Map} techVersionHosts - Tech versions by host to update
 * @param {Array} runtimeFindings - Runtime vulnerability findings to update
 * @param {Map} llmInvestigations - LLM investigations to update
 * @returns {Object} - Import result summary
 */
function importProject(
  data,
  requests,
  uniqueHosts,
  uniquePaths,
  openApiDocs,
  vulnsByTechVersion,
  runtimeFindings,
  techVersionHosts,
  llmInvestigations
) {
  try {
    const state = data.state || data;
    if (!state || typeof state !== 'object') {
      throw new Error('Invalid import format');
    }

    // Clear current state
    requests.length = 0;
    uniqueHosts.clear();
    uniquePaths.clear();
    openApiDocs.clear();
    if (vulnsByTechVersion) vulnsByTechVersion.clear();
    if (runtimeFindings) runtimeFindings.length = 0;
    if (techVersionHosts) techVersionHosts.clear();
    if (llmInvestigations) llmInvestigations.clear();

    // Assign from state
    if (Array.isArray(state.requests)) {
      for (const r of state.requests) {
        if (r && r.url && r.method) requests.push(r);
      }
    }
    
    if (Array.isArray(state.uniqueHosts)) {
      for (const h of state.uniqueHosts) uniqueHosts.add(String(h));
    } else {
      for (const r of requests) if (r.host) uniqueHosts.add(r.host);
    }
    
    if (Array.isArray(state.uniquePaths)) {
      for (const p of state.uniquePaths) uniquePaths.add(String(p));
    } else {
      for (const r of requests) if (r.path) uniquePaths.add(r.path);
    }
    
    if (Array.isArray(state.openApiDocs)) {
      for (const [host, urls] of state.openApiDocs) openApiDocs.set(String(host), Array.isArray(urls) ? urls : []);
    }
    
    if (Array.isArray(state.vulnsByTechVersion)) {
      for (const [key, val] of state.vulnsByTechVersion) vulnsByTechVersion.set(String(key), val);
    }
    
    if (Array.isArray(state.techVersionHosts)) {
      for (const [key, arr] of state.techVersionHosts) techVersionHosts.set(String(key), new Set(Array.isArray(arr) ? arr : []));
    }
    
    if (Array.isArray(state.runtimeFindings)) {
      for (const f of state.runtimeFindings) runtimeFindings.push(f);
    }
    
    if (Array.isArray(state.llmInvestigations)) {
      for (const [k, v] of state.llmInvestigations) llmInvestigations.set(String(k), v);
    }

    return { success: true, counts: { requests: requests.length } };
  } catch (e) {
    throw new Error(`Import failed: ${e.message || String(e)}`);
  }
}

/**
 * Purges all collected data
 * @param {Array} requests - Request history reference to clear
 * @param {Set} uniqueHosts - Set of unique hosts to clear
 * @param {Set} uniquePaths - Set of unique paths to clear
 * @param {Map} openApiDocs - OpenAPI documentation map to clear
 * @param {Map} vulnsByTechVersion - Vulnerabilities by tech version to clear
 * @param {Array} runtimeFindings - Runtime vulnerability findings to clear
 * @param {Map} techVersionHosts - Tech versions by host to clear
 * @param {Object} security - Security service with pendingCveLookups
 * @returns {boolean} - Success status
 */
function purgeData(
  requests,
  uniqueHosts,
  uniquePaths,
  openApiDocs,
  vulnsByTechVersion,
  runtimeFindings,
  techVersionHosts,
  security
) {
  try {
    requests.length = 0;
    uniqueHosts.clear();
    uniquePaths.clear();
    openApiDocs.clear();
    if (vulnsByTechVersion) vulnsByTechVersion.clear();
    if (security && security.pendingCveLookups) security.pendingCveLookups.clear();
    if (runtimeFindings) runtimeFindings.length = 0;
    if (techVersionHosts) techVersionHosts.clear();
    
    return true;
  } catch (e) {
    throw new Error(`Purge failed: ${e.message || String(e)}`);
  }
}

export {
  exportProject,
  importProject,
  purgeData
};