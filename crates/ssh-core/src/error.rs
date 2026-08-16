use thiserror::Error;

#[derive(Error, Debug)]
pub enum SshError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Key exchange failed: {0}")]
    KexFailed(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Channel error: {0}")]
    Channel(String),

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Timeout")]
    Timeout,

    #[error("Host key verification failed")]
    HostKeyVerificationFailed,

    #[error("Known hosts error: {0}")]
    KnownHosts(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Subprocess error: {0}")]
    Subprocess(String),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Buffer overflow")]
    BufferOverflow,

    #[error("Compression error: {0}")]
    Compression(String),
}

pub type Result<T> = std::result::Result<T, SshError>;
