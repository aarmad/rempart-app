FROM node:22-alpine
WORKDIR /app

# Installer les dependances d'abord (meilleur cache)
COPY package*.json ./
RUN npm install --omit=dev

# Copier le reste du code
COPY . .

EXPOSE 8000
CMD ["node", "server.js"]
