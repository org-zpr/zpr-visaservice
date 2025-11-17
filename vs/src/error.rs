use thiserror::Error;

use libeval::eval::EvalError;

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

    #[error("evaluation error: {0}")]
    EvalErr(#[from] EvalError),

    #[error("policy error: {0}")]
    PolicyError(#[from] libeval::policy::PolicyError),

    #[error("UTF8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("Capn Proto not in schema: {0}")]
    CpnpNotInSchema(#[from] capnp::NotInSchema),
}
