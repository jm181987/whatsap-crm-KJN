FROM node:22-bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund --package-lock=false
COPY . .
RUN mkdir -p /app/session /app/public/audios /app/public/imagenes /app/public/archivos /app/public/videos
ENV PORT=3000 NODE_ENV=production
EXPOSE 3000
CMD ["npm", "start"]
