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

    #[error("Hook execution failed ({hook_type}): command '{command}' exited with {status}")]
    Hook {
        hook_type: String,
        command: String,
        status: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let io_err = EnstowError::Io {
            path: PathBuf::from("/test/path"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"),
        };
        assert!(format!("{io_err}").contains("I/O error at /test/path"));

        let dec_err = EnstowError::Decryption {
            path: PathBuf::from("/secret.age"),
            message: "invalid key".to_string(),
        };
        assert_eq!(
            format!("{dec_err}"),
            "Decryption failed for /secret.age: invalid key"
        );

        let col_err = EnstowError::Collision {
            path: PathBuf::from("/dotfile"),
        };
        assert_eq!(
            format!("{col_err}"),
            "Target path already exists (collision): /dotfile"
        );

        let cfg_err = EnstowError::Config("bad value".to_string());
        assert_eq!(
            format!("{cfg_err}"),
            "Invalid path or configuration: bad value"
        );

        let hook_err = EnstowError::Hook {
            hook_type: "pre_apply".to_string(),
            command: "exit 1".to_string(),
            status: "failed".to_string(),
        };
        assert_eq!(
            format!("{hook_err}"),
            "Hook execution failed (pre_apply): command 'exit 1' exited with failed"
        );
    }
}
