use thiserror::Error;

pub type Result<T> = std::result::Result<T, OcfgError>;

#[derive(Error, Debug)]
pub enum OcfgError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Template error: {0}")]
    Template(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("OpenWrt integration error: {0}")]
    OpenWrt(String),

    #[error("User cancelled operation")]
    Cancelled,

    #[error("Missing required configuration: {0}")]
    MissingRequired(String),

    #[error("Invalid value: {0}")]
    InvalidValue(String),

    #[error("Dialoguer error: {0}")]
    Dialoguer(#[from] dialoguer::Error),

    #[error("Anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
}
