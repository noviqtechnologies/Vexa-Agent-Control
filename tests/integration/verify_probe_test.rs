use agentcontrol::verify::run_verification_probe;
use hyper::service::service_fn;
use hyper::{body::Incoming, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde_json::json;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpListener;

async fn mock_gateway_handler(
    req: Request<Incoming>,
) -> Result<Response<http_body_util::Full<bytes::Bytes>>, Infallible> {
    let path = req.uri().path();
    let method = req.method();

    if path == "/healthz" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(http_body_util::Full::new(bytes::Bytes::from("OK")))
            .unwrap());
    }

    if method == Method::POST {
        use http_body_util::BodyExt;
        let bytes = req.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
        let id = body.get("id").cloned().unwrap_or(json!("1"));
        let params = body.get("params").cloned().unwrap_or(json!({}));
        let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let args_str = params.get("arguments").map(|a| a.to_string()).unwrap_or_default();

        if tool_name == "read_file" && args_str.contains("SYSTEM PROMPT OVERRIDE") {
            // Prompt injection block
            let resp_body = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "Policy violation: injection: Jailbreak Phrase: Ignore"
                }
            });
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json")
                .body(http_body_util::Full::new(bytes::Bytes::from(resp_body.to_string())))
                .unwrap());
        }

        if tool_name == "send_external_http" && args_str.contains("AKIAIOSFODNN7EXAMPLE") {
            // DLP Secret exfiltration block
            let resp_body = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "Policy violation: dlp: AWS Access Key ID"
                }
            });
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json")
                .body(http_body_util::Full::new(bytes::Bytes::from(resp_body.to_string())))
                .unwrap());
        }

        // Safe tool allow
        let resp_body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": "README file content"
            }
        });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from(resp_body.to_string())))
            .unwrap());
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .unwrap())
}

#[tokio::test]
async fn test_verification_probe_suite_all_pass() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let gateway_url = format!("http://127.0.0.1:{}", addr.port());

    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service_fn(mock_gateway_handler))
                        .await;
                });
            }
        }
    });

    let exit_code = run_verification_probe(&gateway_url, true).await;
    assert_eq!(exit_code, 0, "Expected verify suite to pass 3/3 on compliant gateway");
}

#[tokio::test]
async fn test_verification_probe_suite_injection_failure_honest_fail() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let gateway_url = format!("http://127.0.0.1:{}", addr.port());

    // Mock buggy/unprotected gateway that allows injection and returns upstream connection error (HTTP 200)
    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service_fn(|req: Request<Incoming>| async move {
                            if req.uri().path() == "/healthz" {
                                return Ok::<_, Infallible>(Response::builder()
                                    .status(StatusCode::OK)
                                    .body(http_body_util::Full::new(bytes::Bytes::from("OK")))
                                    .unwrap());
                            }
                            use http_body_util::BodyExt;
                            let bytes = req.into_body().collect().await.unwrap().to_bytes();
                            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
                            let id = body.get("id").cloned().unwrap_or(json!("1"));
                            let params = body.get("params").cloned().unwrap_or(json!({}));
                            let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");

                            if tool_name == "send_external_http" {
                                let resp_body = json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": { "code": -32001, "message": "Policy violation: dlp: AWS Key" }
                                });
                                return Ok(Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .body(http_body_util::Full::new(bytes::Bytes::from(resp_body.to_string())))
                                    .unwrap());
                            }

                            // Buggy gateway returns HTTP 200 with upstream error for injection!
                            let resp_body = json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": { "code": -32603, "message": "Upstream error: Network error: error sending request for url (http://127.0.0.1:3000/)" }
                            });
                            Ok(Response::builder()
                                .status(StatusCode::OK)
                                .body(http_body_util::Full::new(bytes::Bytes::from(resp_body.to_string())))
                                .unwrap())
                        }))
                        .await;
                });
            }
        }
    });

    let exit_code = run_verification_probe(&gateway_url, true).await;
    assert_eq!(exit_code, 1, "Expected verify suite to fail (exit 1) when injection is forwarded upstream instead of blocked");
}
