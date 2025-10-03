use libeval::zpr_policy::ZprPolicyError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MachineError {
    #[error("Execution error: {0}")]
    ExecutionError(String),
    #[error("Pio error: {0}")]
    Pio(#[from] PioError),
}

#[derive(Debug, Error)]
pub enum PioError {
    #[error("Invalid policy format: {0}")]
    InvalidFormat(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),
    #[error("ZPR policy error: {0}")]
    ZprPolicy(#[from] ZprPolicyError),
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Unknown instruction")]
    UnknownInstruction,
    #[error("Unexpected end of input")]
    UnexpectedEof,
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}

#[derive(Debug, Error)]
pub enum ZptError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),
    #[error("ZPR policy error: {0}")]
    ZprPolicy(#[from] ZprPolicyError),
    #[error("Machine error: {0}")]
    Machine(#[from] MachineError),
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
}
