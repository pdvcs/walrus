FROM node:24-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:24-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=builder /app/dist ./dist
COPY src/db/migrations ./dist/db/migrations
COPY src/routes/api-docs.md ./dist/routes/api-docs.md
COPY packages ./packages
USER node
EXPOSE 8080
CMD ["node", "dist/main.js"]
