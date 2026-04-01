use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("empty policy")]
    EmptyPolicy,

    #[error("attribute missing: {0}")]
    AttributeMissing(String),

    #[error("no match")]
    NoMatch,

    #[error("invalid claim: {0}")]
    InvalidClaim(String),

    #[error("claim missing: {0}")]
    ClaimMissing(String),
}
