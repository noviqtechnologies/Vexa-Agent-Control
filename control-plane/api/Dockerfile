FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY . .
RUN CGO_ENABLED=0 go build -mod=vendor -o /dashboard-api .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /dashboard-api /usr/local/bin/dashboard-api
# Dedicated Single-Tenant Control Hub Administrator Configuration
# Pass administrator credentials and organization details via build args or runtime environment
ARG ADMIN_EMAIL=""
ARG ADMIN_PASSWORD=""
ARG ORGANIZATION_NAME="Primary Organization"
ARG ORGANIZATION_ID="00000000-0000-0000-0000-000000000001"

ENV ADMIN_EMAIL=${ADMIN_EMAIL} \
    ADMIN_PASSWORD=${ADMIN_PASSWORD} \
    ORGANIZATION_NAME=${ORGANIZATION_NAME} \
    ORGANIZATION_ID=${ORGANIZATION_ID} \
    TENANT_ADMIN_EMAIL=${ADMIN_EMAIL} \
    TENANT_ADMIN_PASSWORD=${ADMIN_PASSWORD} \
    TENANT_ADMIN_ORG_NAME=${ORGANIZATION_NAME} \
    CONTROL_HUB_ADMIN_EMAIL=${ADMIN_EMAIL} \
    CONTROL_HUB_ADMIN_PASSWORD=${ADMIN_PASSWORD}

EXPOSE 8081 8400
ENTRYPOINT ["dashboard-api"]
