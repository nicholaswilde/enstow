# AGENTS.md

Conventions and architecture for AI agents working on `enstow`.

---

<!-- rtk-begin -->
## RTK Command Guidelines

- **Git Operations**: Prefix `git` commands with `rtk` (e.g., `rtk git status`, `rtk git diff`, `rtk git log`, `rtk git commit`, `rtk git push`).
- **GitHub CLI**: Prefix `gh` commands with `rtk` and pipe to `cat` (e.g., `rtk gh issue list | cat`, `rtk gh pr status | cat`). Always pipe to bypass interactive pagers.
- **File & Directory Inspection**: Use `rtk ls`, `rtk tree`, `rtk find`, or `rtk read` when listing or reading files for token-optimized output.
- **Searching**: Use `rtk rg` or `rg` (ripgrep) for line search pattern matching to save tokens.
- **Spellchecking**: Run `rtk typos --format brief`; `--format brief` strips visual code context blocks to conserve tokens.
- **Link Checking**: Run `rtk lychee --no-progress [optional: --offline] <target>`; always pass `--no-progress` to suppress terminal escape sequences, and `--offline` when validating local file links.
- **TOML Operations**: Prefix `taplo` commands with `rtk` (e.g., `rtk taplo fmt`, `rtk taplo lint`, `rtk taplo check`).
- **Markdown Operations**: Prefix `rumdl` commands with `rtk` (e.g., `rtk rumdl check .`, `rtk rumdl fmt .`).
- **Ripwire Operations**: Prefix `ripwire` commands with `rtk` (e.g., `rtk ripwire <dir> --for="<task>"`). Always invoke via CLI, never register or use MCP.
- **Build & Test Outputs**: Use `rtk err` or `rtk test` when running build/test commands to filter output to errors/failures only (e.g., `rtk test cargo test`).
- **Python & UV Operations**: Prefix Python scripts and commands with `uv run`, and prefix `uv` commands with `rtk` (e.g., `rtk uv run <script.py>`, `rtk uv run <command>`, `rtk uv add`, `rtk uv sync`). Never run bare `python` or bare `uv`.
- **Exceptions**: Inside `ctx_execute` / `ctx_batch_execute` sandbox code, skip `rtk` (only printed output enters context). Drop `rtk` when exact raw bytes or patch required (`git diff` patch).
<!-- rtk-end -->

<!-- context-mode-begin -->
## Context-Mode Routing Guidelines

- **Derive, Do Not Dump**: Do NOT use `ctx_execute_file` or `ctx_execute` to dump whole file or full config. Print only specific value, matches, count, or known line range needed.
- **Tool Call Surface**: When using MCP wrappers, call `call_mcp_tool` with `ServerName: "context-mode_context-mode"` (or `"context-mode"`) and `ToolName: "ctx_execute"`, `"ctx_execute_file"`, `"ctx_batch_execute"`, `"ctx_fetch_and_index"`, `"ctx_search"`, or `"ctx_index"`.
- **Mandatory Routing**:
  - For analyze/count/filter/compare/search/parse/transform tasks, write code with `ctx_execute` and print only final answer.
  - For analyzing/exploring inside file, use `ctx_execute_file`. Use native `read_file` only when editing requires exact bytes or small known range.
  - Use `ctx_batch_execute` for multi-command repository reconnaissance.
  - Use `ctx_execute` for shell commands whose output may exceed short fixed answer.
  - Use `ctx_fetch_and_index` for web content, then `ctx_search` to query it.
  - Return only derived answers, concise summaries, selected snippets, or file paths.
<!-- context-mode-end -->

<!-- ponytail-begin -->
## Ponytail (Lazy Senior Dev Mode) Guidelines

- **Stop at first rung that holds**:
  1. Need to build at all? (YAGNI)
  2. Already in codebase? Reuse existing helpers/utils/patterns.
  3. Stdlib does it? Use it.
  4. Native platform feature covers it? Use it.
  5. Installed dependency solves it? Use it.
  6. Can be one line? One line.
  7. Only then: write minimum working code.
- **Bug fix = root cause, not symptom**: Fix shared function/path rather than individual callers.
- **Rules**:
  - No unrequested abstractions, boilerplate, or avoidable dependencies.
  - Deletion over addition. Boring over clever. Fewest files possible.
  - Shortest working diff wins once problem understood.
  - Mark deliberate simplifications cutting real corner with `ponytail:` comment naming ceiling and upgrade path.
  - Ensure logic leaves behind ONE runnable check (assert-based demo/self-check or small test file). Trivial one-liners need none.
<!-- ponytail-end -->

<!-- caveman-begin -->
## Caveman Guidelines

Respond terse like smart caveman. All technical substance stay. Only fluff die.

Rules:

- Drop: articles (a/an/the), filler (just/really/basically), pleasantries, hedging.
- Fragments OK. Short synonyms. Technical terms exact. Code unchanged.
- Pattern: [thing] [action] [reason]. [next step].
- Not: "Sure! I'd be happy to help you with that."
- Yes: "Bug in auth middleware. Fix:"

Switch level: /caveman lite|full|ultra|wenyan
Stop: "stop caveman" or "normal mode"

Auto-Clarity: drop caveman for security warnings, irreversible actions, user confused. Resume after.

Boundaries: code/commits/PRs written normal.
<!-- caveman-end -->

<!-- codegraph-begin -->
## CodeGraph

In repositories indexed by CodeGraph (`.codegraph/` directory exists at repo root), reach for it BEFORE grep/find or reading files when exploring code:

- **MCP tool**: `codegraph_explore` answers source + call path + blast radius in one call. Dynamic-dispatch hops included. Name file or symbol in query to read current line-numbered source.
- **Shell**: `codegraph explore "<symbol names or question>"`.

If no `.codegraph/` directory exists, skip CodeGraph entirely.
<!-- codegraph-end -->

<!-- serena-begin -->
## Serena Semantic Navigation & LSP Integration

Use Serena (`serena`) MCP tools for semantic navigation, AST symbol inspection, LSP diagnostics, and project memories:

1. **Map first**: Call `get_symbols_overview` on target file instead of reading entire file.
2. **Read target symbol only**: Call `find_symbol` with `include_body: true` for target function/class/method.
3. **Check callers**: Call `find_referencing_symbols` or `find_implementations` before signature or behavior changes.
4. **Edit by symbol**: Use `replace_symbol_body`, `insert_after_symbol`, `insert_before_symbol`, or `rename_symbol`. Use standard edit for small tweaks or non-code files.
5. **Verify diagnostics**: Call `get_diagnostics_for_file` after edits to catch LSP errors before full test run.
<!-- serena-end -->

<!-- headroom-begin -->
## Headroom MCP (Context Window Compression)

Use Headroom (`headroom`) MCP tools to manage context window consumption on large payloads:

- `headroom_compress`: Shrink large tool outputs or raw data.
- `headroom_retrieve`: Retrieve original content by hash if specific details needed.
- `headroom_stats`: Monitor headroom cache usage.
<!-- headroom-end -->

<!-- ripwire-begin -->
## Ripwire CLI Guidelines

Use `ripwire` CLI (prefixed with `rtk ripwire`) for AST codebase mapping, call graphs, blast radius, and structural queries:

- **CLI First**: Always invoke `rtk ripwire <dir> [flags]` via CLI; do NOT use MCP server.
- **Task Orientation**: `rtk ripwire <dir> --for="<task>"` for ranked signatures and bodies.
- **Task Bundle**: `rtk ripwire <dir> --pack-task="<task>" --legend=compact`.
- **Stack Trace / Error**: `rtk ripwire <dir> --from-trace=FILE --legend=compact` (`-` for stdin).
- **Call Graph**: `rtk ripwire <dir> --callers=SYM`, `--callees=SYM`, `--uses=SYM`.
- **Blast Radius**: `rtk ripwire <dir> --impact=SYM --legend=compact` before changing shared code.
- **Quality Delta & Gate**: `rtk ripwire <dir> --quality-delta --legend=compact` and `--test-gate --legend=compact`.
- **Atomic Edits**: `rtk ripwire <dir> --replace-symbol-body=SYM --edit-payload=FILE` without whole-file re-reading.
<!-- ripwire-end -->

<!-- ripgrep-guidelines-begin -->
## Ripgrep Guidelines

- **Pattern Searching**: Always use `rg` (ripgrep) or `rtk rg` instead of standard `grep` to search text inside files quickly and save token output.
- **Scope**: Use `-t rust` for Rust files, `-l` for file listing, keep context small (`-C 1`).
<!-- ripgrep-guidelines-end -->

<!-- taplo-rules-begin -->
## Taplo TOML Rules

- **Prefix with RTK**: Always prefix `taplo` commands with `rtk` in interactive shells (e.g., `rtk taplo fmt`, `rtk taplo lint`).
- **Format**: Run `rtk taplo fmt` to format TOML files in-place (`Cargo.toml`).
- **Validation**: Run `rtk taplo lint` to validate TOML syntax and schema.
<!-- taplo-rules-end -->

<!-- issue-management-begin -->
## GitHub Issue Management

When creating or updating GitHub issues, adhere to naming and labeling scheme:

- **Features**: Prefix title with `[feat]:` and apply `enhancement` label.
- **Bugs**: Prefix title with `[bug]:` and apply `bug` label.
- **Commit Closing**: GitHub issues only close automatically when commits containing `Fixes #<number>` are pushed to remote repository.
<!-- issue-management-end -->

<!-- sensitive-information-protection-begin -->
## Sensitive Information Protection

NEVER commit or stage sensitive personal, financial, or security data to repository:

1. **Secrets & Credentials**: Never commit `.env` files, API keys, bearer tokens, passwords, or private encryption keys.
2. **Decrypted Files**: Never commit decrypted secret files. Ensure plaintext files are excluded in `.gitignore` or written outside version-controlled dotfiles directory.
3. **Strict Permissions**: Decrypted secret target files must always be created with strict permissions (`0600` on unix).
4. **Explicit Staging**: Never use `git add .` when untracked secret files exist; stage explicitly by name.
<!-- sensitive-information-protection-end -->

---

## 1. Project Overview & Architecture

**`enstow`**: Rust CLI secret-aware dotfile manager. Combines symlinking (`stow`) with seamless decryption (`sops` and `age`).

### Core Goals

- **Security First:** Never store or write decrypted secrets into version-controlled files. Write plaintext target files with strict permissions (`0600`).
- **Simplicity & Speed:** Fast execution, minimal overhead, clear dry-run previews.
- **Portability:** Static single binary across common platforms (Linux, macOS, Windows).
- **Ponytail Discipline:** Minimum code solving problem. No speculative abstractions.

### Key Capabilities

- Scan dotfile directories and compute target destination paths.
- Symlink regular files and directories to target directory.
- Decrypt encrypted files (`.sops.yaml`, `.age`, etc.) in memory and deploy to destination securely.
- Full `dry-run` support to preview link creations and secret injections.

---

## 2. Technology Stack

- **Language & Edition:** Rust (Edition 2021)
- **CLI Parsing:** `clap` (with `derive`, `env` features)
- **Error Handling:** `anyhow` (CLI top-level) / `thiserror` (internal domain errors)
- **Observability:** `tracing`, `tracing-subscriber`
- **File Traversal:** `walkdir`
- **Serialization:** `serde`, `serde_json`, `serde_yaml_ng`
- **Decryption:** `age` crate and/or external `sops` CLI invocation
- **Automation:** `task` (`Taskfile.yml`)

---

## 3. Development Principles & Code Style

- **Build Discipline (Ponytail):** Minimum code solving problem. Reuse stdlib; no speculative abstractions.
- **Development Workflow (TDD):** Test-Driven Development is mandatory. Write failing test first (Red), implement minimal solution (Green), verify and refactor.
- **Surgical Changes:** Modify only requested code. Keep edits focused and verifiable.
- **Response Style (Caveman):** Terse, technical, zero fluff.
- **Verification:** Run tests and linters via `task test` or `cargo test && cargo clippy -- -D warnings`.
- **Cross-Platform Filesystem & Symlinks:**
  - Never compare symlinks using raw equality (`dest == source`). Always resolve relative links against `target.parent()` and compare canonicalized paths via `is_symlink_to`.
  - Normalize Windows verbatim prefixes (`\\?\`, `\\?\UNC\`, `\??\`) before checking ancestry (`starts_with`) or equality; `canonicalize()` emits `\\?\` while `read_link()` returns paths without it, causing prefix component mismatches.
  - Avoid hardcoded forward slashes in path joins (`path.join("dir/file")`); use `.join("dir").join("file")` for Windows compatibility.
  - In integration/unit tests, compare canonical paths (`fs::canonicalize()`) to prevent failures from short paths (`RUNNER~1`) or macOS symlinked root paths (`/var` vs `/private/var`).
  - When asserting symlink removal/pruning in tests, never use `assert!(!path.exists())` because dangling symlinks return `false`; always assert `assert!(fs::symlink_metadata(path).is_err())`.
  - When creating test symlink fixtures, never use `#[cfg(unix)]` alone; always pair with `#[cfg(windows)] std::os::windows::fs::symlink_file(...)` to prevent silent missing-file failures on Windows runners.
