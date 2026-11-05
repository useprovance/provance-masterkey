FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY gateway/package.json gateway/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY gateway ./gateway
RUN npm run build && npm prune --omit=dev --ignore-scripts --no-audit --no-fund
FROM node:24-bookworm-slim
ENV NODE_ENV=production MASTERKEY_GATEWAY_HOST=0.0.0.0
WORKDIR /app
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist-gateway ./dist-gateway
COPY --chown=node:node gateway/providers.json ./gateway/providers.json
COPY --chown=node:node gateway/free-providers.json ./gateway/free-providers.json
COPY --chown=node:node gateway/certs ./gateway/certs
COPY --chown=node:node data/registry/index.json ./data/registry/index.json
COPY LICENSE ./LICENSE
USER node
EXPOSE 4010
CMD ["node","dist-gateway/main.js"]
