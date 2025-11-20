use thiserror::Error;

#[derive(Debug, Error)]
pub enum DTError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),
}
