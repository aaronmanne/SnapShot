# Frontend Dockerfile: build React app with Vite, then serve via Nginx and proxy API to backend

# Build stage
FROM node:18-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* .npmrc* ./
RUN npm i
COPY index.html ./
COPY vite.config.js ./
COPY src ./src
RUN npm run build

# Runtime stage
FROM nginx:1.27-alpine

# Copy built assets
COPY --from=build /app/dist /usr/share/nginx/html

# Add Nginx config with reverse proxy for /api and /socket.io to backend service
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
