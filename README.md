# SnapShot

A complete, Dockerized web dashboard for monitoring and analyzing proxied HTTP requests.

- Frontend: React SPA (Vite) served by Nginx, with a modern dashboard UI and live updates via Socket.IO.
- Backend: Node.js (Express) acting as an HTTP proxy and analytics API, pushing real-time events via Socket.IO.
- Orchestration: Docker Compose with two services: `frontend` and `backend` on a shared network.

## Quick Start

Prerequisites:
- Docker Desktop (or Docker Engine) and Docker Compose plugin
- .env file with API keys and other configurations

Run the stack:

```sh
# From the repository root
docker compose up --build
```

Then open:
- Frontend: http://localhost:3000
- Backend API: http://localhost:5000
- Default http proxy port listens on 8081

Port configuration:
- The backend port is configurable via the PORT environment variable and defaults to 8081 when not set.
- In this Docker Compose setup, the backend service sets PORT=5000 so the API is available at http://localhost:5000. You can change the mapping and/or PORT as needed.

The frontend is served via Nginx and internally reverse-proxies API/WebSocket traffic to the `backend` service by its service name, so real-time updates work out-of-the-box.

## Project Structure

```
/project_root
├── docker-compose.yml
├── /frontend
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── api.js
│       ├── styles.css
│       └── components/
│           ├── Header.jsx
│           ├── DataTable.jsx
│           └── AnalyticsPanels.jsx
└── /backend
    ├── Dockerfile
    ├── package.json
    └── src/
        └── index.js
```

## How It Works

- Proxy: Send any HTTP request to the backend proxy endpoint and it will forward the request, capture metadata, and broadcast the result over WebSocket to the dashboard.
- Real-time: The dashboard subscribes to `request` events over Socket.IO to display new requests instantly.
- Analytics: The backend aggregates simple analytics such as unique hostnames/paths, technology hints from headers, method and status distributions, and attempts to discover OpenAPI/Swagger documentation endpoints per host.
- Fuzzing: A button in the UI calls an API to generate fuzz-test curl commands based on recent traffic and downloads them as a text file.

## Using the Proxy

You can drive traffic through the proxy from any client. The backend accepts a `url` query parameter or `X-Target-URL` header indicating the full target URL.

Examples:

```sh
# Simple GET
curl "http://localhost:5000/proxy?url=https://httpbin.org/get"

# POST with body targeting an external API
curl -X POST \
  -H 'Content-Type: application/json' \
  --data '{"hello":"world"}' \
  "http://localhost:5000/proxy?url=https://httpbin.org/post"

# Using header instead of query param
curl -H 'X-Target-URL: https://example.com' http://localhost:5000/proxy
```

Every proxied response is analyzed and emitted to the dashboard.

## Spidering (Link Discovery)

When the proxy fetches an HTML page via the reverse-proxy endpoint (`/proxy`), the backend parses links on the page and, by default, spiders one level deep. In addition to standard anchor/image/script links (href/src), the spider also looks for common AJAX endpoints referenced in inline scripts, such as fetch(...), axios.get/post(...), $.ajax({ url: ... }), and XMLHttpRequest.open(...). Discovered links are fetched by the backend service and appear in the dashboard like any other request.

Configuration via environment variables:
- SPIDER_DEPTH: Depth to follow links. 0 disables spidering, 1 follows links one level deep (default 1).
- SPIDER_MAX_PER_SEED: Maximum pages to fetch per starting page (default 20).
- SPIDER_SAME_ORIGIN_ONLY: If true, only follow links on the same origin as the starting page (default true). Set to "false" to allow cross-origin links.
- SPIDER_TIMEOUT_MS: Timeout in ms for each spider fetch (default 8000).
- SPIDER_REQUESTS_PER_SEC: Throttle per-unique-domain spider speed in requests per second (default 5).
- SPIDER_RESPECT_ROBOTS: If true, the spider will respect robots.txt rules (default true). Set to "false" to ignore robots.txt.

Notes:
- Spidering is triggered for the reverse proxy path `/proxy` (and for forward proxy responses) when the content type is `text/html` and the response status is 200. It runs asynchronously in the background and does not delay the client response.
- The spider, including AJAX link discovery, uses the same User-Agent as the original requesting client that fetched the seed page.

## API Endpoints

- GET `/api/requests` — Returns recent requests (supports `q`, `method`, `status` filters)
- GET `/api/analytics` — Returns analytics (unique hostnames/paths, technologies, distributions, OpenAPI detections)
- POST `/api/fuzz/generate` — Returns a downloadable text file of curl commands for fuzzing

Socket.IO endpoint: `/socket.io` (proxied through the frontend when visiting http://localhost:3000)

## Notes

- The frontend uses Nginx to reverse proxy `/api` and `/socket.io` to the backend by Docker service name `backend`. When accessing the frontend via http://localhost:3000, the browser only contacts the frontend container, which proxies internally to the backend.
- The backend includes permissive CORS for convenience; when calling it directly on http://localhost:5000 this is helpful.
- OpenAPI detection checks common paths like `/openapi.json`, `/v3/api-docs`, `/swagger.json`, etc., per discovered hostname.

## Vulnerabilities Panel

The dashboard includes an Identified Vulnerabilities panel (above the Live Requests table).

What you’ll see:
- Known CVEs for detected technologies with version numbers (e.g., Server: nginx/1.18.0). The backend queries the NVD CVE API asynchronously and caches results per technology+version.
- Heuristic runtime indicators that a response may reflect exploitable behavior, including:
  - [SQLi] SQL error signatures suggesting possible SQL injection (e.g., MySQL/PostgreSQL/SQLServer/Oracle error strings)
  - [XSS] Likely client-side script execution indicators in HTML (e.g., inline <script>alert(...), onerror=alert(...), etc.)
  - [LFI] File inclusion/disclosure hints (e.g., /etc/passwd fragments, PHP include error messages)

Environment variables (backend):
- CVE_LOOKUP_ENABLED: Enable/disable CVE lookups (default: true)
- NVD_API_KEY: Optional NVD API key to increase rate limits (no key works but with stricter limits)
- NVD_RESULTS_PER_TECH: Max CVEs to show per technology+version (default: 5)

Notes:
- Runtime indicators are heuristic and may produce false positives. Treat them as leads to investigate rather than definitive findings.
- CVE data depends on the presence of versioned headers from targets (e.g., Server, X-Powered-By). Results update over time as more hosts are observed.

### LLM Investigation

You can click a vulnerability’s text (CVE ID or title) to open a closable side panel. The panel includes an "Investigate" button that sends a structured prompt to a configurable LLM service, including:
- Domain/Hostname
- URL Path
- HTTP Request Headers (User-Agent, Referer, etc.)
- Request Method
- Request Body (if applicable; body capture is not stored by default)
- CVE metadata

The prompt explicitly states the analysis is hypothetical and for security research only and requests Proof-of-Concept (PoC) code and mitigation advice. While waiting, the UI shows a loading indicator. If the request times out (backend-configurable, default 5 minutes) or fails, the panel displays the timeout/error. Responses are parsed to extract:
- Exploitation techniques
- Potential attack vectors
- PoC code (if present)
- Mitigation advice

Results are cached server-side for the vulnerability and reused when you re-open the panel.

Configuration (backend):
- LLM_HOST: Hostname of the LLM server (default: localhost)
- LLM_PORT: Port of the LLM server (default: 11434)
- LLM_MODEL: Model name for Ollama-compatible servers (default: llama3.1)
- LLM_TIMEOUT_MS: Request timeout in milliseconds (default: 300000)

API:
- POST `/api/llm/investigate` — Body: `{ vulnerability, requestId?, force? }`. Returns `{ key, at, input, raw, parsed }` or `{ cached: true, ... }` when available.

By default this targets an Ollama-compatible server: http://LLM_HOST:LLM_PORT/api/generate. Adjust env vars to point to your server.

## Development Tips

- Rebuild after code changes when running via Docker: `docker compose up --build`.
- For quick local frontend dev outside Docker, `cd frontend && npm install && npm run dev` (but ensure the backend is running on http://localhost:5000 or adjust Vite proxy accordingly if needed).

## License

MIT (add your copyright/owner information as appropriate).