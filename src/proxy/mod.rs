//! Proxy server, TLS interception, JSON-RPC forwarding, STDIO transport, and egress tracking subsystem.

pub mod adaptive_timeout;
pub mod broker_client;
pub mod codec;
pub mod db;
pub mod egress;
pub mod embedding_batcher;
pub mod forward;
pub mod handler;
pub mod key_invalidation;
pub mod llm_proxy;
pub mod local_key_cache;
pub mod mitm;
pub mod pipeline;
pub mod prompt_cache;
pub mod provider_key_client;
pub mod provider_router;
pub mod replay_guard;
pub mod request_coalescer;
pub mod server;
pub mod session;
pub mod stdio;
pub mod tls;
pub mod transformer;
pub mod tunnel;
