import axios from 'axios';

// Common paths to check for OpenAPI documentation
const COMMON_DOC_PATHS = [
  '/openapi.json',
  '/openapi.yaml',
  '/swagger.json',
  '/swagger/v1/swagger.json',
  '/v3/api-docs',
  '/v3/api-docs/swagger-config',
  '/swagger-ui.html',
  '/docs',
  '/api-docs'
];

/**
 * Detects OpenAPI documentation for a given hostname
 * @param {string} hostname - The hostname to check
 * @param {string} protocol - The protocol to use (http: or https:)
 * @param {Map} openApiDocs - Map to store results
 * @returns {Promise<Array>} - Array of found OpenAPI doc URLs
 */
async function detectOpenApiForHost(hostname, protocol = 'https:', openApiDocs) {
  if (!hostname) return [];
  if (openApiDocs.has(hostname)) return openApiDocs.get(hostname); // already checked
  
  const found = [];
  for (const path of COMMON_DOC_PATHS) {
    const url = `${protocol}//${hostname}${path}`;
    try {
      const res = await axios.get(url, { timeout: 4000, validateStatus: () => true });
      const ct = (res.headers['content-type'] || '').toLowerCase();
      if (res.status < 400 && (ct.includes('json') || ct.includes('yaml') || path.includes('swagger-ui'))) {
        found.push(url);
      }
    } catch (e) {
      // ignore
    }
  }
  openApiDocs.set(hostname, found);
  return found;
}

export {
  COMMON_DOC_PATHS,
  detectOpenApiForHost
};