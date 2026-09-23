FROM node:22-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV PORT=3000 DB_PATH=/data/game.db
EXPOSE 3000
CMD ["node", "server.js"]
