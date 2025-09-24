# Backend Dockerfile
FROM node:18-alpine

# Create app directory
WORKDIR /app

# Install app dependencies
COPY package.json package-lock.json* .npmrc* ./
RUN npm i

# Bundle app source
COPY src ./src
COPY config.js ./config.js

ENV NODE_ENV=production
# Default port inside the image; can be overridden by environment
ENV PORT=8081

# Expose default port (informational)
EXPOSE 8081

CMD ["node", "src/index.js"]
