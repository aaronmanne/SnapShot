import axios from 'axios';
import OpenAI from 'openai';

// LLM Investigation Service
// Handles LLM queries, caching, and response parsing

// Store LLM investigation results
const llmInvestigations = new Map(); // key -> { at, input, raw, parsed }

/**
 * Generates a unique key for vulnerability tracking
 * @param {Object} v - Vulnerability object
 * @returns {string} - Unique key
 */
function vulnKey(v = {}) {
  const id = (v.cveId || v.type || '').toString().trim();
  const host = (v.host || '').toString().trim();
  const tech = (v.tech || '').toString().trim();
  const ver = (v.version || '').toString().trim();
  return `${id}::${host}::${tech}@${ver}`;
}

/**
 * Find an associated request for a vulnerability
 * @param {Object} v - Vulnerability object
 * @param {string} requestId - Optional specific request ID
 * @param {Array} requests - Array of requests to search
 * @returns {Object|null} - Found request or null
 */
function findAssociatedRequest(v = {}, requestId = '', requests = []) {
  // Prefer exact requestId if given
  if (requestId) {
    const r = requests.find(r => r.id === requestId);
    if (r) return r;
  }
  // Next, try by URL
  if (v.url) {
    try {
      const u = new URL(v.url);
      const path = u.pathname + (u.search || '') + (u.hash || '');
      const r = [...requests].reverse().find(r => r.host === u.host && (r.path === path || r.url === v.url));
      if (r) return r;
    } catch {}
  }
  // Fallback: latest by host
  if (v.host) {
    const r = [...requests].reverse().find(r => r.host === v.host);
    if (r) return r;
  }
  // Last resort: any recent request
  return requests.length ? requests[requests.length - 1] : null;
}

/**
 * Build structured payload for LLM
 * @param {Object} v - Vulnerability object
 * @param {Object} reqRec - Request record
 * @returns {Object} - Structured payload
 */
function buildStructuredPayload(v = {}, reqRec = null) {
  const reqInfo = reqRec ? {
    hostname: reqRec.host || '',
    fullUrl: reqRec.url || '',
    urlPath: reqRec.path || '',
    method: reqRec.method || '',
    headers: reqRec.reqHeaders || {},
    body: null
  } : null;
  
  return {
    vulnerability: {
      cveId: v.cveId || v.type || '',
      title: v.title || '',
      severity: v.severity || '',
      tech: v.tech || '',
      version: v.version || '',
      referenceUrl: v.url || ''
    },
    request: reqInfo
  };
}

/**
 * Extract structured data from LLM response
 * @param {string} text - Raw LLM response
 * @returns {Object} - Parsed response
 */
function extractFromResponse(text = '') {
    // If text is an object with a content property, use it
    const t = typeof text === 'object' && text !== null && 'content' in text
        ? String(text.content || '')
        : String(text || '');
    let jsonStr = '';
    const fence = t.match(/```(?:json)?\n([\s\S]*?)\n```/i);

    if (fence && fence[1]) jsonStr = fence[1].trim();
    else {
        const start = t.indexOf('{');
        const end = t.lastIndexOf('}');
        if (start !== -1 && end !== -1 && end > start) jsonStr = t.slice(start, end + 1);
    }

    let parsed = null;
    if (jsonStr) {
        try { parsed = JSON.parse(jsonStr); } catch {}
    }

    // Create the default structure with standard fields
    const out = { exploitationTechniques: [], attackVectors: [], pocCode: '', mitigationAdvice: '', raw: t };

    // Add the original JSON response
    out.originalJson = parsed;

    if (parsed && typeof parsed === 'object') {
        const p = parsed;
        // Still populate standard fields for backward compatibility
        if (Array.isArray(p.exploitation_techniques)) out.exploitationTechniques = p.exploitation_techniques;
        if (Array.isArray(p.attack_vectors)) out.attackVectors = p.attack_vectors;
        if (!out.exploitationTechniques.length && Array.isArray(p.techniques)) out.exploitationTechniques = p.techniques;
        if (!out.attackVectors.length && Array.isArray(p.vectors)) out.attackVectors = p.vectors;
        out.pocCode = String(p.poc_code || p.poc || p.exploit || '');
        out.mitigationAdvice = String(p.mitigation_advice || p.mitigation || p.remediation || '');
    }

    if (!out.pocCode) {
        const m = t.match(/(?:(?:PoC|Proof[ -]of[ -]Concept)[^\n]*?:|```[^`\n]*\n)([\s\S]{0,4000})/i);
        if (m) out.pocCode = m[1].trim();
    }

    if (!out.mitigationAdvice) {
        const m = t.match(/(?:Mitigation|Remediation|Fix):?\s*([\s\S]{0,1000})/i);
        if (m) out.mitigationAdvice = m[1].trim();
    }

    return out;
}

/**
 * Generate LLM investigation prompt
 * @param {Object} vulnerability - Vulnerability information
 * @param {string} requestId - Optional specific request ID
 * @param {Array} requests - Array of requests
 * @returns {Object} - Prompt and metadata
 */
function generatePrompt(vulnerability, requestId = '', requests = []) {
  if (!vulnerability || typeof vulnerability !== 'object') {
    throw new Error('Missing vulnerability');
  }
  
  const key = vulnKey(vulnerability);
  const reqRec = findAssociatedRequest(vulnerability, requestId, requests);
  const data = buildStructuredPayload(vulnerability, reqRec);
  
  const prompt = [
    'You are assisting with hypothetical security research. Do NOT perform any real-world attacks. This is for analysis only.',
    'Given the following CVE context and an associated captured HTTP request, analyze potential exploitation techniques and attack vectors.',
    'Then generate proof-of-concept (PoC) code strictly for educational understanding, and provide mitigation advice.',
    'IMPORTANT! Respond ONLY in JSON with the following keys: exploitation_techniques (array of strings), attack_vectors (array of strings), poc_code (string), mitigation_advice (string).',
    '',
    'INPUT_JSON:',
    JSON.stringify(data, null, 2)
  ].join('\n');
  
  return { key, input: data, prompt };
}

/**
 * Perform LLM investigation
 * @param {Object} vulnerability - Vulnerability information
 * @param {string} requestId - Optional specific request ID
 * @param {boolean} force - Force refresh cache
 * @param {Object} config - LLM configuration
 * @param {Array} requests - Array of requests
 * @param {string} customPrompt - Optional custom prompt to use instead of generating one
 * @returns {Promise<Object>} - Investigation results
 */
async function performInvestigation(vulnerability, requestId = '', force = false, config = {}, requests = [], customPrompt = '') {
  if (!vulnerability || typeof vulnerability !== 'object') {
    throw new Error('Missing vulnerability');
  }
  
  const key = vulnKey(vulnerability);
  if (!force && llmInvestigations.has(key)) {
    return { cached: true, key, ...llmInvestigations.get(key) };
  }
  
  let prompt;
  let input;
  
  if (customPrompt) {
    // Use the custom prompt provided by the user
    prompt = customPrompt;
    input = { vulnerability };
  } else {
    // Generate the default prompt
    const generated = generatePrompt(vulnerability, requestId, requests);
    prompt = generated.prompt;
    input = generated.input;
  }
  
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error('timeout')), Math.max(1000, Number(config.llmTimeoutMs || 300000)));
  
  // Determine which LLM API to use based on config or runtime options
  // Runtime options take precedence as they can be changed via the UI
  const llmApiType = (config.runtimeOptions && config.runtimeOptions.llmApiType) || config.llmApiType || 'LMStudio';
  let llmText = '';
  
  try {
    let resp;
    
    switch(llmApiType) {
      case 'LMStudio': {
          // LMStudio - OpenAI-like API
          const openai = new OpenAI({
              base_url: `${config.lmStudioHost}:${config.lmStudioPort}`, // Set the base URL to your LM Studio server's address
              default_model: `${config.llmModel || 'gpt-oss-20b'}` // Or your desired model name
          });

          const completion = await openai.chat.completions.create({
              model: `${config.llmModel || 'gpt-oss-20b'}`, // Or your desired model name
              messages: [
                  {role: 'system', content: 'You are assisting with hypothetical security research.'},
                  {role: 'user', content: prompt}
              ],
              response_format: "json", // Crucial for JSON-only output!
          });
          llmText = JSON.parse(completion.choices[0].message.content);
          break;
      }
      case 'Ollama': {
          // Ollama API
          const ollamaUrl = `${config.ollamaBaseUrl || 'http://localhost:11434'}/api/generate`;
          const ollamaPayload = {
              model: config.llmModel || 'llama3',
              prompt
          };

          resp = await axios.post(ollamaUrl, ollamaPayload, {
              timeout: Number(config.llmTimeoutMs || 300000),
              signal: controller.signal,
              validateStatus: () => true
          });

          if (resp.status >= 400) throw new Error(`Ollama server error: ${resp.status}`);
          llmText = String(resp.data?.response || '');
          break;
      }
      case 'OpenAI': {
          // OpenAI API
          const openaiUrl = 'https://api.openai.com/v1/chat/completions';
          const openaiPayload = {
              model: config.llmModel || 'gpt-3.5-turbo',
              messages: [
                  {role: 'system', content: 'You are assisting with hypothetical security research.'},
                  {role: 'user', content: prompt}
              ],
              response_format: 'json_object',
              temperature: 0.7
          };

          resp = await axios.post(openaiUrl, openaiPayload, {
              headers: {
                  'Authorization': `Bearer ${config.openaiApiKey || ''}`,
                  'Content-Type': 'application/json'
              },
              timeout: Number(config.llmTimeoutMs || 300000),
              signal: controller.signal,
              validateStatus: () => true
          });

          if (resp.status >= 400) throw new Error(`OpenAI API error: ${resp.status} - ${JSON.stringify(resp.data)}`);
          llmText = String(resp.data?.choices?.[0]?.message?.content || '');
          break;
      }
      case 'Gemini': {
          // Google Gemini API
          // google has an OpenAI compatible API for Gemini
          const openai = new OpenAI({
              apiKey: `${config.geminiApiKey}`,
              baseURL: "https://generativelanguage.googleapis.com/v1beta/openai/"
          });

          const response = await openai.chat.completions.create({
              model: "gemini-2.5-flash",
              reasoning_effort: "low",
              messages: [
                  { role: "system", content: "You are assisting with hypothetical security research." },
                  {
                      role: "user",
                      content: prompt,
                  },
              ],
          });

          llmText = String(response.choices?.[0]?.message?.content || '');
          break;
      }
      default:
        throw new Error(`Unknown LLM API type: ${llmApiType}`);
    }
    
    // If no text was extracted using the specific path, try some generic paths
    if (!llmText) {
      llmText = String(resp.data?.response || resp.data?.text || resp.data?.output || '');
      if (!llmText) llmText = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);
    }
  } finally {
    clearTimeout(timeout);
  }
  
  const parsed = extractFromResponse(llmText);
  const record = { at: new Date().toISOString(), input, raw: llmText, parsed };
  llmInvestigations.set(key, record);
  
  return { key, ...record };
}

export {
  llmInvestigations,
  vulnKey,
  findAssociatedRequest,
  buildStructuredPayload,
  extractFromResponse,
  generatePrompt,
  performInvestigation
};