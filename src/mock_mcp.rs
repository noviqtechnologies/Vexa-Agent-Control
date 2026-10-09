//! In-memory mock MCP server for testing, CI smoke verification, and development.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub async fn run_mock_mcp_server(
    listen: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    println!("Mock MCP server listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(|req: Request<Incoming>| async move {
                        let path = req.uri().path();
                        if path == "/healthz" {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("Connection", "close")
                                    .body(Full::new(Bytes::from("OK")))
                                    .unwrap(),
                            );
                        }

                        if req.method() == Method::POST {
                            let bytes = match req.into_body().collect().await {
                                Ok(c) => c.to_bytes(),
                                Err(_) => Bytes::new(),
                            };
                            let body: serde_json::Value =
                                serde_json::from_slice(&bytes).unwrap_or(json!({}));
                            let id = body.get("id").cloned().unwrap_or(json!(1));
                            let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");

                            let resp_body = match method {
                                "tools/list" => json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": {
                                        "tools": [
                                            {
                                                "name": "read_file",
                                                "description": "Read file from disk"
                                            }
                                        ]
                                    }
                                }),
                                "tools/call" => {
                                    let params = body.get("params").cloned().unwrap_or(json!({}));
                                    let tool_name = params
                                        .get("name")
                                        .and_then(|n| n.as_str())
                                        .unwrap_or("unknown");
                                    json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "result": {
                                            "content": format!("Mock response from {}", tool_name)
                                        }
                                    })
                                }
                                _ => json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": {}
                                }),
                            };

                            return Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header("Content-Type", "application/json")
                                .header("Connection", "close")
                                .body(Full::new(Bytes::from(resp_body.to_string())))
                                .unwrap());
                        }

                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "text/plain")
                            .header("Connection", "close")
                            .body(Full::new(Bytes::from("Mock MCP Server Active")))
                            .unwrap())
                    }),
                )
                .await;
        });
    }
}
