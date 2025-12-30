use libeval::actor::AttributeError;
use libeval::policy::PolicyError;
use rustyline::error::ReadlineError;
use thiserror::Error;
use zpr::vsapi_types::VsapiTypeError;

#[derive(Debug, Error)]
pub enum MachineError {
    #[error("Execution error: {0}")]
    ExecutionError(String),
    #[error("Pio error: {0}")]
    Pio(#[from] PioError),
    #[error("attribute error: {0}")]
    Attribute(#[from] AttributeError),
    #[error("vsapi type error: {0}")]
    VsapiTypeError(#[from] VsapiTypeError),
}

#[derive(Debug, Error)]
pub enum PioError {
    #[error("Invalid policy format: {0}")]
    InvalidFormat(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),
    #[error("Policy error: {0}")]
    Policy(#[from] PolicyError),
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
    #[error("Policy error: {0}")]
    ZprPolicy(#[from] PolicyError),
    #[error("Machine error: {0}")]
    Machine(#[from] MachineError),
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
    #[error("REPL error: {0}")]
    Repl(#[from] ReadlineError),
}
