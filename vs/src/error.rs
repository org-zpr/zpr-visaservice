use libeval::actor;
use libeval::eval::EvalError;
use std::net::SocketAddr;
use thiserror::Error;

use zpr::vsapi_types::{ApiResponseError, ErrorCode, VsapiTypeError};

#[derive(Debug, Error)]
pub enum VSError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("configuration error: {0}")]
    Config(#[from] toml::de::Error),

    #[error("parameter error: {0}")]
    ParamError(String),

    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("internal error: {0}")]
    InternalError(String),

    #[error("timed out: {0}")]
    Timeout(String),

    #[error("evaluation error: {0}")]
    EvalErr(#[from] EvalError),

    #[error("policy error: {0}")]
    PolicyError(#[from] libeval::policy::PolicyError),

    #[error("visa denied: {0}")]
    VisaDenied(String),

    #[error("UTF8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("Capn Proto not in schema: {0}")]
    CpnpNotInSchema(#[from] capnp::NotInSchema),

    #[error("attribute error: {0}")]
    AttributeError(#[from] actor::AttributeError),

    #[error("database error: {0}")]
    DBError(#[from] DBError),
}

#[derive(Debug, Error)]
pub enum DBError {
    #[error("redis error: {0}")]
    RedisError(#[from] redis::RedisError),

    #[error("policy missing required details: {0}")]
    MissingRequired(String),

    #[error("invalid data: {0}")]
    InvalidData(String),

    #[error("openssl error: {0}")]
    OpenSslError(#[from] openssl::error::ErrorStack),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("serialization/deserialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("attribute error: {0}")]
    AttributeError(#[from] actor::AttributeError),

    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("vsapi error: {0}")]
    VsapiError(#[from] VsapiTypeError),
}

#[derive(Debug, Error)]
pub enum VSSError {
    #[error("internal error: {0}")]
    InternalError(String),

    #[error("queue full: {0}")]
    QueueFull(String),

    #[error("vss connection closed")]
    ConnClosed,

    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("vsapi error: {0}")]
    VsapiError(#[from] VsapiTypeError),

    #[error("api response error: {0:?} ({1}, retry {2})")]
    ApiResponseError(ErrorCode, String, u32),

    #[error("duplicate vss worker for {0}")]
    DuplicateWorker(SocketAddr),
}

impl From<ApiResponseError> for VSSError {
    fn from(err: ApiResponseError) -> Self {
        VSSError::ApiResponseError(err.code, err.message, err.retry_in)
    }
}
