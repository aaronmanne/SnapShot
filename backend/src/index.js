import express from 'express';
import http from 'http';
import cors from 'cors';
import morgan from 'morgan';
import {Server as SocketIOServer} from 'socket.io';
import httpProxy from 'http-proxy';
import config from '../config.js';

// Import utility modules
import ForwardProxy from './proxy/ForwardProxy.js';
import {startSpider, lastSpideredAt} from './utils/Spider.js';
import {detectOpenApiForHost} from './utils/OpenApiUtils.js';
import security, {
    identifyTechnologies,
    extractTechVersions,
    registerTechVersionsForHost,
    fetchCvesFor,
    queueCveLookup,
    getVulnerabilitiesAnalytics,
    detectRuntimeVulns,
    addRuntimeFindings,
    vulnsByTechVersion,
    techVersionHosts,
    runtimeFindings
} from './services/SecurityService.js';
import {llmInvestigations} from './services/LlmService.js';
import ProxyService from './services/ProxyService.js';
import AnalyticsService from './services/AnalyticsService.js';
import configureRoutes from './routes/ApiRoutes.js';

// Forward proxy port used by generated curl commands and forward proxy server
const FORWARD_PROXY_PORT = 8081;
const PORT = config.port;

// Express app setup
const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
    path: '/socket.io',
    cors: {origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']}
});

// Middleware
app.use(express.json({limit: '20mb'}));
app.use(express.urlencoded({extended: true}));
app.use(cors());
app.use(morgan('dev'));

// In-memory storage
const requests = [];
const uniqueHosts = new Set();
const uniquePaths = new Set();
const openApiDocs = new Map();

// Runtime feature flags/options (mutable via API)
const runtimeOptions = {
    aggressiveFingerprinting: config.aggressiveFingerprinting,
    llmEnabled: true,
    llmApiType: config.llmApiType || 'LMStudio',  // Default to LMStudio
};

// Create proxy server
const {createProxyServer} = httpProxy;
const proxy = createProxyServer({
    changeOrigin: true,
    secure: false,
});

// Initialize analytics service
const analyticsService = new AnalyticsService({
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
});

// Initialize proxy service
const proxyService = new ProxyService(config, {
    uniqueHosts,
    uniquePaths,
    requests,
    runtimeOptions,
    openApiDocs,
    emitRecord: params => analyticsService.emitRecord(params),
    detectOpenApiForHost,
    identifyTechnologies,
    detectRuntimeVulns,
    addRuntimeFindings,
    queueCveLookup,
    registerTechVersionsForHost,
    aggressiveFingerprint: (host, protocol) => analyticsService.aggressiveFingerprint(host, protocol),
    io
});

// Configure and use API routes
app.use(configureRoutes({
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
    proxy: proxyService.getProxy(),
    FORWARD_PROXY_PORT,
    runtimeOptions,
    analyticsService
}));

// Socket.io connection handler
io.on('connection', socket => {
    console.log('Client connected:', socket.id);
    socket.emit('hello', {message: 'Connected to SnapShot backend'});
});

// Start the server
server.listen(PORT, () => {
    console.log(`SnapShot backend listening on http://0.0.0.0:${PORT}`);
});

// Start Forward Proxy
new ForwardProxy({
    port: FORWARD_PROXY_PORT,
    config,
    emitRecord: params => analyticsService.emitRecord(params),
    startSpider,
    detectRuntimeVulns,
    addRuntimeFindings,
    lastSpideredAt
}).start();