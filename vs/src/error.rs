use thiserror::Error;

#[derive(Debug, Error)]
pub enum VSError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Configuration error: {0}")]
    Config(#[from] toml::de::Error),
}
