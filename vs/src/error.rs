use thiserror::Error;

#[derive(Debug, Error)]
pub enum VSError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("configuration error: {0}")]
    Config(#[from] toml::de::Error),

    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("internal error: {0}")]
    InternalError(String),
}
