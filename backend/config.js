// config.js

import dotenv from 'dotenv';

try {
    dotenv.config(); // Load environment variables from .env file
    console.log("Dotenv loaded successfully!");  // Debugging output
    console.log("Loaded environment variables:", process.env);
} catch (error) {
    console.error("Error loading .env:", error); // Debugging output - critical!
}

const config = {
    // HTTP server port (for API and reverse proxy endpoint)
    port: Number(process.env.PORT) || 8081,

    // Whether the spider should be enabled automatically at server start (default: false)
    spiderEnabledAtStart: (process.env.SPIDER_ENABLED_AT_START ?? 'false').toLowerCase() === 'true',

    // Spidering depth (0 = disabled, 1 = follow links one level deep)
    spiderDepth: Number(process.env.SPIDER_DEPTH ?? 1),

    // Maximum pages to fetch per starting page (seed)
    spiderMaxPerSeed: Number(process.env.SPIDER_MAX_PER_SEED ?? 10),

    // If true, only follow links on the same origin as the seed URL
    spiderSameOriginOnly: (process.env.SPIDER_SAME_ORIGIN_ONLY ?? 'true').toLowerCase() !== 'false',

    // Timeout for spider fetches in milliseconds
    spiderTimeoutMs: Number(process.env.SPIDER_TIMEOUT_MS ?? 8000),

    // Throttle speed per unique domain (requests per second)
    spiderRequestsPerSec: Number(process.env.SPIDER_REQUESTS_PER_SEC ?? 1),

    // Whether to respect robots.txt (true by default)
    spiderRespectRobots: (process.env.SPIDER_RESPECT_ROBOTS ?? 'true').toLowerCase() !== 'false',

    // Optional: User-Agent to use for generated fuzz curl commands. If not provided,
    // the system will default to the original client's User-Agent captured for each request.
    fuzzUserAgent: process.env.FUZZ_USER_AGENT,

    // Whether to enable aggressive fingerprinting (false by default)
    aggressiveFingerprinting: (process.env.AGGRESSIVE_FINGERPRINTING ?? 'false').toLowerCase() !== 'false',

    // CVE lookup (NVD) configuration
    cveLookupEnabled: (process.env.CVE_LOOKUP_ENABLED ?? 'true').toLowerCase() !== 'false',
    nvdApiKey: process.env.NVD_API_KEY,
    nvdResultsPerTech: Number(process.env.NVD_RESULTS_PER_TECH ?? 5),

    // LLM integration configuration
    lmStudioHost: process.env.LLM_HOST || '127.0.0.1',
    lmStudioPort: Number(process.env.LLM_PORT ?? 1234),
    llmTimeoutMs: Number(process.env.LLM_TIMEOUT_MS ?? 300000), // default 5 minutes
    llmModel: process.env.LLM_MODEL,
    // LLM API type (LMStudio, Ollama, OpenAPI, Gemini)
    llmApiType: process.env.LLM_API_TYPE || 'LMStudio',
    // API keys for different LLM providers
    openaiApiKey: process.env.OPENAI_API_KEY,
    geminiApiKey: process.env.GEMINI_API_KEY,
    ollamaBaseUrl: process.env.OLLAMA_BASE_URL || 'http://localhost:11434',
};

export default config;
