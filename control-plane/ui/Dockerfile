FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
# Render nginx.conf at container startup via nginx:alpine's built-in envsubst.
# Templates in /etc/nginx/templates/*.template are processed before nginx starts.
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
# Default upstream — resolves correctly on ECS Fargate (shared network namespace).
# Docker Compose overrides this with the service DNS name via the environment.
ENV AGENTWALL_API_UPSTREAM=127.0.0.1:8400
# Restrict envsubst to AGENTWALL_* variables only so nginx's own runtime
# variables ($uri, $host, $remote_addr, etc.) are left untouched.
ENV NGINX_ENVSUBST_FILTER=AGENTWALL_
EXPOSE 80
