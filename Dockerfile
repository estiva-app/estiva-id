# Estiva ID — production image.
#
# Five stages so the runtime carries neither the toolchain nor dev dependencies.
# The migration runner ships too: `node dist/db/migrate.js` resolves migrations
# relative to its own location, so `migrations/` must be present in the image.

FROM node:22-bookworm-slim AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile


FROM deps AS build
WORKDIR /app
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN pnpm build


# The account UI (PEEK-68), built separately so a change to the page does not
# invalidate the service build's layer cache, or the other way round.
FROM deps AS build-web
WORKDIR /app
COPY vite.config.ts ./
COPY web ./web
RUN pnpm build:web


# Production dependencies only, resolved from the same lockfile.
FROM node:22-bookworm-slim AS prod-deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile --prod


FROM node:22-bookworm-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8787

COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build-web /app/dist-web ./dist-web
COPY migrations ./migrations
COPY package.json ./

# The base image ships an unprivileged `node` user. Nothing here writes to disk.
USER node

EXPOSE 8787

# Liveness only — never touches the database, so a Postgres outage does not get
# the container restarted underneath a working process.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8787/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/server.js"]
