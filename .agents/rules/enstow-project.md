# enstow Project Rules

- Rust CLI tool: Secret-aware dotfile manager combining GNU `stow` symlinking with `sops` and `age` decryption.
- Plaintext secrets must NEVER be written to disk in git-tracked paths or committed to git.
- Decrypted target files must have strict file permissions (`0600` on unix).
- Follow Ponytail minimal design & Caveman concise responses.
- Use `thiserror` for internal errors and `anyhow` in CLI entry points.
- Verify changes with `cargo test`, `cargo clippy -- -D warnings`, and `cargo fmt -- --check`.
