FROM node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:9eeb7f5887d0e239e78264b06f7f11d2e14be534050481803a9e4728fcdd278e
WORKDIR /app
COPY --from=dependencies /app/node_modules/ node_modules/
COPY shared/ shared/
COPY config/deploy.config.json config/deploy.config.json
COPY apps/control-portal/ apps/control-portal/
ARG DOJO_CODE_REVISION=unversioned
ENV NODE_ENV=production HOST=0.0.0.0 PORT=8080 DOJO_CODE_REVISION=${DOJO_CODE_REVISION}
EXPOSE 8080
CMD ["apps/control-portal/server.mjs"]