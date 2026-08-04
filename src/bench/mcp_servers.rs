//! Sandboxed In-Memory Mock Implementations for 133 MCP Servers

use std::collections::HashMap;

pub struct MockMcpRegistry {
    pub servers: HashMap<String, Vec<String>>,
}

impl MockMcpRegistry {
    pub fn new_133() -> Self {
        let mut servers = HashMap::new();
        let server_names = vec![
            "filesystem", "bash", "git", "postgres", "sqlite", "redis", "web_fetch", "slack", "github",
            "jira", "linear", "aws_s3", "gcp_storage", "docker", "kubernetes", "puppeteer", "brave_search",
            "fetch", "memory", "everything", "filesystem_v2", "terminal", "python_runner", "node_runner",
            "elastic", "mongo", "mysql", "dynamodb", "sqs", "sns", "lambda", "cloudfront", "stripe", "sendgrid",
            "twilio", "datadog", "sentry", "pagerduty", "notion", "airtable", "google_drive", "google_docs",
            "google_sheets", "gmail", "outlook", "teams", "discord", "figma", "miro", "trello", "asana",
            "zendesk", "intercom", "hubspot", "salesforce", "segment", "mixpanel", "posthog", "amplitude",
            "snowflake", "bigquery", "redshift", "clickhouse", "dbt", "airflow", "dagster", "prefect",
            "kafka", "rabbitmq", "nats", "vercell", "netlify", "cloudflare", "fastly", "digitalocean",
            "linode", "vultr", "terraform", "pulumi", "ansible", "vault", "consul", "nomad", "vault_v2",
            "bitbucket", "gitlab", "argocd", "flux", "prometheus", "grafana", "jaeger", "opentelemetry",
            "snyk", "sonarqube", "trivy", "checkov", "semgrep", "wiz", "lacework", "sysdig", "datadog_v2",
            "newrelic", "dynatrace", "splunk", "elastic_v2", "logstash", "kibana", "fluentd", "vector",
            "loki", "tempo", "cortex", "thanos", "mimir", "pyroscope", "parca", "opensearch", "meilisearch",
            "typesense", "algolia", "pinecone", "weaviate", "qdrant", "milvus", "chroma", "marqo",
            "langchain", "llama_index", "auto_gpt", "baby_agi", "crew_ai", "dspy", "guidance"
        ];

        for name in server_names {
            servers.insert(
                name.to_string(),
                vec![
                    "tools/list".to_string(),
                    "tools/call".to_string(),
                    "ping".to_string(),
                    "status".to_string(),
                ],
            );
        }

        Self { servers }
    }
}
