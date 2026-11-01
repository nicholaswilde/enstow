# enstow Project Rules

- Rust CLI tool: Secret-aware dotfile manager combining GNU `stow` symlinking with `sops` and `age` decryption.
- Plaintext secrets must NEVER be written to disk in git-tracked paths or committed to git.
- Decrypted target files must have strict file permissions (`0600` on unix).
- Follow Ponytail minimal design & Caveman concise responses.
- **Development Workflow (TDD)**: Test-Driven Development is strictly required. For any new feature or bug fix:
  1. Write failing unit/integration tests defining expected behavior (Red).
  2. Implement minimum code to satisfy tests (Green).
  3. Refactor while maintaining green tests.
- Use `thiserror` for internal errors and `anyhow` in CLI entry points.
- Verify changes with `cargo test`, `cargo clippy -- -D warnings`, and `cargo fmt -- --check`.
