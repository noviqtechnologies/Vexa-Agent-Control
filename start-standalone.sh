#!/bin/bash
set -e

# Initialize PostgreSQL data directory if empty
PGDATA="/var/lib/postgresql/data"

if [ -z "$(ls -A $PGDATA 2>/dev/null)" ]; then
    echo "Initializing PostgreSQL..."
    mkdir -p $PGDATA
    chown -R postgres:postgres $PGDATA
    su - postgres -c "/usr/lib/postgresql/15/bin/initdb -D $PGDATA"
    
    # Start Postgres temporarily to set up user and DB
    su - postgres -c "/usr/lib/postgresql/15/bin/pg_ctl -D $PGDATA -o '-c listen_addresses=localhost' -w start"
    
    su - postgres -c "psql -c \"CREATE USER agentwall WITH SUPERUSER PASSWORD 'agentwall';\""
    su - postgres -c "psql -c \"CREATE DATABASE agentwall OWNER agentwall;\""
    su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE agentwall TO agentwall;\""

    # Run migrations
    echo "Running migrations..."
    for f in /app/migrations/*.up.sql; do
        su - postgres -c "psql -d agentwall -f $f"
    done
    
    # Stop Postgres
    su - postgres -c "/usr/lib/postgresql/15/bin/pg_ctl -D $PGDATA -m fast -w stop"
fi

# Set default secrets if they aren't provided as environment variables
export GATEWAY_SECRET=${GATEWAY_SECRET:-"local-dev-shared-secret-change-me"}
export POLICY_READ_SECRET=${POLICY_READ_SECRET:-"local-dev-policy-read-secret"}

# Set up Supervisor configuration
cat > /etc/supervisor/conf.d/supervisord.conf <<EOF
[supervisord]
nodaemon=true
user=root

[program:postgresql]
command=su - postgres -c "/usr/lib/postgresql/15/bin/postgres -D $PGDATA"
priority=10
autorestart=true

[program:nginx]
command=nginx -g "daemon off;"
priority=20
autorestart=true

[program:dashboard-api]
command=/usr/local/bin/dashboard-api
environment=DATABASE_URL="%(ENV_DATABASE_URL)s",DASHBOARD_PORT="%(ENV_DASHBOARD_PORT)s",GATEWAY_SECRET="%(ENV_GATEWAY_SECRET)s",POLICY_READ_SECRET="%(ENV_POLICY_READ_SECRET)s",GATEWAY_URL="%(ENV_GATEWAY_URL)s"
priority=30
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

[program:agentwall]
command=/usr/local/bin/agentwall start --policy /app/policy.example.yaml
environment=AGENTWALL_LISTEN="%(ENV_AGENTWALL_LISTEN)s",AGENTWALL_LOG_PATH="%(ENV_AGENTWALL_LOG_PATH)s",AGENTWALL_SIEM_BACKEND="dashboard",AGENTWALL_SIEM_ENDPOINT="http://127.0.0.1:8400/api/v1/ingest/events"
priority=40
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
EOF

echo "Starting Supervisor to manage PostgreSQL, Nginx, Dashboard API, and AgentWall Gateway..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
