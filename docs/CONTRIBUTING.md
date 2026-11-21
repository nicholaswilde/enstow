# Contributing Guide

`enstow` accepts change requests using [GitHub pull requests][1]. This document outlines the process so you know what to expect.

## :test_tube: Development & Quality Gates

Use [`task`](https://taskfile.dev/) as the primary command runner:

```bash
task check        # Type check code
task test         # Run formatting, clippy lints, and unit tests
task test:ci      # Run full suite using CI profile
task lint         # Run clippy with -D warnings
task fmt          # Auto-format with rustfmt
task lint:md      # Lint Markdown files with rumdl
task completions  # Generate shell completion scripts
task man          # Generate UNIX roff man page
task coverage     # Run tests and output coverage summary
task build        # Build all multi-arch Linux targets via cross
task serve        # Serve local Zensical documentation site
task docs:build   # Build static Zensical documentation site
```

All pull requests should satisfy:

- `cargo fmt -- --check` (formatting via `rustfmt`)
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test` (unit and integration tests)
- `rumdl check .` (Markdown linting)

## :microscope: TDD & Cross-Platform Symlink Testing

`enstow` follows Test-Driven Development (write a failing test first, implement the minimal fix, then refactor) and runs CI across Linux, macOS, Windows, and ARM cross-compilation targets:

- **Canonical Symlink Comparisons:** Never compare symlinks using raw path equality (`dest == source`). Resolve relative links against `target.parent()` and compare canonicalized paths via `is_symlink_to` (macOS resolves `/var` to `/private/var`, and Windows uses 8.3 aliases like `RUNNER~1`).
- **Windows Verbatim Prefixes:** Strip verbatim prefixes (`\\?\`, `\\?\UNC\`, `\??\`) via `normalize_path` before checking ancestry (`starts_with`) or equality.
- **Path Joins:** Chain `.join("dir").join("file")` instead of hardcoding forward slashes inside path strings.
- **Deletion Assertions:** Never use `assert!(!path.exists())` to verify symlink removal because dangling symlinks return `false`; always assert `assert!(fs::symlink_metadata(path).is_err())`.
- **Cross-Platform Symlink Fixtures:** Pair `#[cfg(unix)] std::os::unix::fs::symlink(...)` with `#[cfg(windows)] std::os::windows::fs::symlink_file(...)` in test helpers so fixtures work across every OS matrix job.

## Developer Certificate of Origin

`enstow` uses a [Developer Certificate of Origin (DCO)][2] to sign-off that you have the right to contribute the code being contributed. The full text of the DCO reads:

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
1 Letterman Drive
Suite D4700
San Francisco, CA, 94129

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Every commit needs to have signoff added to it with a message like:

```shell
Signed-off-by: Joe Smith <joe.smith@example.com>
```

If you set your `user.name` and `user.email` in your git configuration, you can sign your commit automatically with `git commit -s` or `git commit --signoff`.

## Issues

Feature requests, bug reports, and support requests all occur through GitHub issues. If you would like to file an issue, view existing issues, or comment on an issue please engage with issues at <https://github.com/nicholaswilde/enstow/issues>.

## Pull Requests

All changes to the source code are made through GitHub [pull requests][1]. If you would like to make a change to the source, docs, or other component in the repository please open a pull request with the change.

If you are unsure if the change will be welcome you may want to file an issue first. The issue can detail the change and you can get feedback from the maintainers prior to starting to make the change.

You can find existing pull requests at <https://github.com/nicholaswilde/enstow/pulls>.

## Versioning

Versioning is done per [Semantic Versioning 2.0.0 (semver)][3] principles.

[1]: https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests
[2]: https://developercertificate.org/
[3]: https://semver.org/spec/v2.0.0.html
