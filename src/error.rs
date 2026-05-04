use thiserror::Error;

pub type Result<T> = std::result::Result<T, OcfgError>;

/// Macro for creating OcfgError instances with automatic variant prefixing
/// and debug location tracking using the dbg_here! proc-macro
///
/// # Examples
///
/// ```rust
/// use ocfg::err;
/// use ocfg::error::OcfgError;
///
/// // Simple message
/// let error = err!(Config, "Configuration file not found");
///
/// // With formatting
/// let error = err!(Config, "Failed to parse {}: {}", "config.toml", "invalid syntax");
///
/// // The macro automatically expands to:
/// // OcfgError::Config("Configuration file not found".to_string())
/// // And prints debug location information via dbg_here!
/// ```
#[macro_export]
macro_rules! err {
    ($variant:ident, $msg:expr) => {
        {
            $crate::error::OcfgError::$variant(format!("Error created: {} - {}", stringify!($variant), $msg))
        }
    };
    // Other variants with formatted message
    ($variant:ident, $fmt:expr, $($arg:tt)*) => {
        {
            $crate::error::OcfgError::$variant(format!("Error created: {} - {}", stringify!($variant), format!($fmt, $($arg)*)))
        }
    };
}

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

    #[error("User cancelled operation: {0}")]
    Cancelled(String),

    #[error("Missing required configuration: {0}")]
    MissingRequired(String),

    #[error("Invalid value: {0}")]
    InvalidValue(String),

    #[error("Dialoguer error: {0}")]
    Dialoguer(#[from] dialoguer::Error),

    #[error("Network error: {0}")]
    Network(String),
}

impl OcfgError {
    /// Create a new Config error
    pub fn config(msg: impl Into<String>) -> Self {
        OcfgError::Config(msg.into())
    }

    /// Create a new IO error
    pub fn io(err: std::io::Error) -> Self {
        OcfgError::Io(err)
    }

    /// Create a new Serialization error
    pub fn serialization(msg: impl Into<String>) -> Self {
        OcfgError::Serialization(msg.into())
    }

    /// Create a new Crypto error
    pub fn crypto(msg: impl Into<String>) -> Self {
        OcfgError::Crypto(msg.into())
    }

    /// Create a new Template error
    pub fn template(msg: impl Into<String>) -> Self {
        OcfgError::Template(msg.into())
    }

    /// Create a new Validation error
    pub fn validation(msg: impl Into<String>) -> Self {
        OcfgError::Validation(msg.into())
    }

    /// Create a new OpenWrt error
    pub fn openwrt(msg: impl Into<String>) -> Self {
        OcfgError::OpenWrt(msg.into())
    }

    /// Create a new Cancelled error
    pub fn cancelled(msg: impl Into<String>) -> Self {
        OcfgError::Cancelled(msg.into())
    }

    /// Create a new MissingRequired error
    pub fn missing_required(msg: impl Into<String>) -> Self {
        OcfgError::MissingRequired(msg.into())
    }

    /// Create a new InvalidValue error
    pub fn invalid_value(msg: impl Into<String>) -> Self {
        OcfgError::InvalidValue(msg.into())
    }

    /// Create a new Network error
    pub fn network(msg: impl Into<String>) -> Self {
        OcfgError::Network(msg.into())
    }
}
