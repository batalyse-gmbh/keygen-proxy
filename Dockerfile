FROM oven/bun:1.2.10 AS base
WORKDIR /app

COPY package.json ./
RUN bun install --frozen-lockfile --production || bun install --production

COPY src ./src

ENV NODE_ENV=production
EXPOSE 3000
CMD ["bun", "run", "start"]
