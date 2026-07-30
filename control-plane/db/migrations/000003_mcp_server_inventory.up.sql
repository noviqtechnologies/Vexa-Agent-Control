CREATE TABLE mcp_servers (
    agent_id      TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    ide_target    TEXT NOT NULL,
    server_name   TEXT NOT NULL,
    wrapped       BOOLEAN NOT NULL,
    path_verified BOOLEAN NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, ide_target, server_name)
);
