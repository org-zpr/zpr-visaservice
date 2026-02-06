use thiserror::Error;

#[derive(Error, Debug)]
pub enum VsaError {
    #[error("HTTP request failed: {0}")]
    HttpRequest(#[from] reqwest::Error),

    #[error("Failed to parse JSON response: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("HTTP error with status code: {0}")]
    HttpError(reqwest::StatusCode),

    #[error("URL parsing error: {0}")]
    UrlParseError(#[from] url::ParseError),
}
