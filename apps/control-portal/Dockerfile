FROM node:24-bookworm-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY shared/ shared/
COPY config/deploy.config.json config/deploy.config.json
COPY apps/control-portal/ apps/control-portal/
USER node
ENV NODE_ENV=production HOST=0.0.0.0 PORT=8080
EXPOSE 8080
CMD ["node", "apps/control-portal/server.mjs"]