FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html

# Where the UI forwards /api/ requests. Defaults to the ECS Fargate layout,
# where all containers share one network namespace. Docker Compose overrides
# this with http://dashboard-api:8400 (see control-plane/docker-compose.yml).
ENV AGENTWALL_API_UPSTREAM=http://127.0.0.1:8400

# Restrict envsubst to AGENTWALL_* so nginx's own runtime variables ($uri,
# $host, $remote_addr, ...) are left intact when the template is rendered.
ENV NGINX_ENVSUBST_FILTER=AGENTWALL_

# Files under /etc/nginx/templates are rendered into /etc/nginx/conf.d by the
# nginx image entrypoint at container start.
COPY nginx.conf /etc/nginx/templates/default.conf.template
EXPOSE 80
