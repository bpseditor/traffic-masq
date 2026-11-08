//! HTTP API and models for the daemon-client control protocol.

use std::time::Duration;

/// Cover candidate convergence and compensation before terminating a request.
pub(crate) const HTTP_CONNECTION_TIMEOUT: Duration = crate::core::transaction::CONVERGENCE_DEADLINE
    .saturating_mul(2)
    .saturating_add(Duration::from_secs(5));
pub mod client;
pub mod control;
pub mod model;
pub mod server;

pub(crate) mod operations;
