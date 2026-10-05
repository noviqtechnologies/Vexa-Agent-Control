//! OpenTelemetry (OTLP) HTTP/JSON Trace Exporter
//!
//! Maps internal Agent Control trace events and proxy spans into standard
//! OpenTelemetry Protocol (OTLP v1.0.0+) `resourceSpans` payloads according to
//! ADR-006, GenAI semantic conventions, and MCP tool attributes.

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtlpExportRequest {
    pub resource_spans: Vec<OtlpResourceSpan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtlpResourceSpan {
    pub resource: OtlpResource,
    pub scope_spans: Vec<OtlpScopeSpan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtlpResource {
    pub attributes: Vec<OtlpKeyValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtlpScopeSpan {
    pub scope: OtlpScope,
    pub spans: Vec<OtlpSpan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtlpScope {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtlpSpan {
    pub trace_id: String,
    pub span_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    pub name: String,
    pub kind: i32, // 1 = Internal, 2 = Server, 3 = Client
    pub start_time_unix_nano: u64,
    pub end_time_unix_nano: u64,
    pub attributes: Vec<OtlpKeyValue>,
    pub status: OtlpSpanStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtlpSpanStatus {
    /// 0 = Unset, 1 = Ok, 2 = Error
    pub code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OtlpKeyValue {
    pub key: String,
    pub value: OtlpAnyValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OtlpAnyValue {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub int_value: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bool_value: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub double_value: Option<f64>,
}

impl OtlpKeyValue {
    pub fn string(key: impl Into<String>, val: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: OtlpAnyValue {
                string_value: Some(val.into()),
                int_value: None,
                bool_value: None,
                double_value: None,
            },
        }
    }

    pub fn int(key: impl Into<String>, val: i64) -> Self {
        Self {
            key: key.into(),
            value: OtlpAnyValue {
                string_value: None,
                int_value: Some(val),
                bool_value: None,
                double_value: None,
            },
        }
    }

    pub fn bool(key: impl Into<String>, val: bool) -> Self {
        Self {
            key: key.into(),
            value: OtlpAnyValue {
                string_value: None,
                int_value: None,
                bool_value: Some(val),
                double_value: None,
            },
        }
    }
}

/// Builder and exporter for OpenTelemetry trace spans
pub struct OtlpExporter {
    client: reqwest::Client,
    service_name: String,
    service_version: String,
}

impl Default for OtlpExporter {
    fn default() -> Self {
        Self::new("agentcontrol", env!("CARGO_PKG_VERSION"))
    }
}

impl OtlpExporter {
    pub fn new(service_name: impl Into<String>, service_version: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            client,
            service_name: service_name.into(),
            service_version: service_version.into(),
        }
    }

    /// Build an OTLP ExportRequest from a list of OtlpSpans
    pub fn build_export_request(&self, spans: Vec<OtlpSpan>) -> OtlpExportRequest {
        OtlpExportRequest {
            resource_spans: vec![OtlpResourceSpan {
                resource: OtlpResource {
                    attributes: vec![
                        OtlpKeyValue::string("service.name", &self.service_name),
                        OtlpKeyValue::string("service.version", &self.service_version),
                        OtlpKeyValue::string("telemetry.sdk.name", "agentcontrol-rust"),
                    ],
                },
                scope_spans: vec![OtlpScopeSpan {
                    scope: OtlpScope {
                        name: "io.vexa.agentcontrol".to_string(),
                        version: Some(self.service_version.clone()),
                    },
                    spans,
                }],
            }],
        }
    }

    /// Convert high-level agent event parameters into an OtlpSpan
    pub fn create_span(
        &self,
        trace_id: &str,
        span_id: &str,
        parent_span_id: Option<&str>,
        tool_name: &str,
        verdict: &str,
        developer_id: Option<&str>,
        run_id: Option<&str>,
        duration_ms: u64,
        is_error: bool,
    ) -> OtlpSpan {
        let now_nano = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let start_time_nano = now_nano.saturating_sub(duration_ms * 1_000_000);

        let mut attributes = vec![
            OtlpKeyValue::string("gen_ai.system", "agentcontrol"),
            OtlpKeyValue::string("mcp.tool.name", tool_name),
            OtlpKeyValue::string("agentcontrol.verdict", verdict),
        ];

        if let Some(dev) = developer_id {
            attributes.push(OtlpKeyValue::string("agentcontrol.developer_id", dev));
        }
        if let Some(r_id) = run_id {
            attributes.push(OtlpKeyValue::string("agentcontrol.run_id", r_id));
        }

        let status = if is_error {
            OtlpSpanStatus {
                code: 2, // STATUS_CODE_ERROR
                message: Some(format!("Policy verdict blocked or error: {}", verdict)),
            }
        } else {
            OtlpSpanStatus {
                code: 1, // STATUS_CODE_OK
                message: None,
            }
        };

        OtlpSpan {
            trace_id: trace_id.to_string(),
            span_id: span_id.to_string(),
            parent_span_id: parent_span_id.map(|s| s.to_string()),
            name: format!("mcp.{}", tool_name),
            kind: 3, // SPAN_KIND_CLIENT
            start_time_unix_nano: start_time_nano,
            end_time_unix_nano: now_nano,
            attributes,
            status,
        }
    }

    /// Export spans to an external OTLP HTTP collector endpoint (e.g. http://localhost:4318/v1/traces)
    pub async fn export_to_collector(
        &self,
        endpoint: &str,
        spans: Vec<OtlpSpan>,
    ) -> Result<usize, String> {
        let span_count = spans.len();
        if span_count == 0 {
            return Ok(0);
        }

        let request = self.build_export_request(spans);
        let resp = self
            .client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("OTLP HTTP post failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("OTLP collector returned HTTP {}: {}", status, body));
        }

        Ok(span_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_otlp_json_serialization() {
        let exporter = OtlpExporter::default();
        let span = exporter.create_span(
            "4bf92f3577b34da6a3ce929d0e0e4736",
            "00f067aa0ba902b7",
            Some("5fb397be34d23b0f"),
            "read_file",
            "allow",
            Some("dev-alice"),
            Some("run-99"),
            45,
            false,
        );

        let req = exporter.build_export_request(vec![span]);
        let json_str = serde_json::to_string_pretty(&req).unwrap();

        assert!(json_str.contains("resourceSpans"));
        assert!(json_str.contains("service.name"));
        assert!(json_str.contains("agentcontrol"));
        assert!(json_str.contains("4bf92f3577b34da6a3ce929d0e0e4736"));
        assert!(json_str.contains("mcp.read_file"));
        assert!(json_str.contains("dev-alice"));
        assert!(json_str.contains("run-99"));
    }
}
