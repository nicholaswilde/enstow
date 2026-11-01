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
- **Cross-Platform Filesystem & Symlinks**:
  - **Symlink Comparisons**: Never compare symlinks using raw path equality (`dest == source`). macOS resolves `/var` to `/private/var`, and Windows uses 8.3 aliases (`RUNNER~1` vs `runneradmin`).
  - **Symlink Target Resolution**: Always use `is_symlink_to` (or resolve relative links against `target.parent()` and compare `canonicalize()` outputs).
  - **Path Construction**: Never hardcode `/` inside path string joins (e.g. `path.join("a/b")`). Always chain components (`path.join("a").join("b")`) to ensure correct platform separators on Windows.
  - **Path Assertions in Tests**: Compare canonical paths via `fs::canonicalize()` or `is_symlink_to` instead of raw `assert_eq!(read_link(target), source)`.
  - **Symlink Creation in Tests**: Never write `#[cfg(unix)] std::os::unix::fs::symlink(...)` alone in test fixtures. Always pair with `#[cfg(windows)] std::os::windows::fs::symlink_file(...)` so fixtures are created across all CI matrix platforms.
