use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EnstowError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[allow(dead_code)]
    #[error("Decryption failed for {path}: {message}")]
    Decryption { path: PathBuf, message: String },

    #[error("Target path already exists (collision): {path}")]
    Collision { path: PathBuf },

    #[error("Invalid path or configuration: {0}")]
    Config(String),
}
