//! Standalone local identity management
//!
//! Provides local key generation and device identification for standalone mode.

pub struct StandaloneIdentity {
    pub device_id: String,
}

impl StandaloneIdentity {
    pub fn new() -> Self {
        Self {
            device_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}
