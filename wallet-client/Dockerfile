FROM node:20-slim
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci || npm i --only=production
COPY src ./src
EXPOSE 4000
CMD ["node", "src/server.js"]


