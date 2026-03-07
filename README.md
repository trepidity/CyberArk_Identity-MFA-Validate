# Seahorse - BSWH MFA Validate

A Rust TUI application that validates OATH MFA codes against CyberArk Identity and displays SAML responses. Replaces the legacy .NET Epic GenAuth Test Host.

## Features

- **Two authentication flows:**
  - **Browser Flow** — Opens a native webview for CyberArk login, captures the SAML response via a localhost ACS listener
  - **REST API Flow** — Terminal-only authentication using CyberArk's StartAuthentication/AdvanceAuthentication endpoints (supports multi-challenge)
- **SAML validation** — Parses SAML responses, validates RSA-SHA256 signatures, and checks time conditions
- **Certificate handling** — Loads PFX certificates for SAML AuthnRequest signing and displays certificate expiry
- **TUI interface** — Interactive terminal UI built with Ratatui for environment selection, flow choice, authentication, and result display
- **Cross-platform** — Builds for Windows, macOS (ARM + Intel), and Linux

## Project Structure

```
seahorse/src/
  main.rs           # Entry point
  lib.rs            # Library root
  config.rs         # Config loading (JSON + PFX)
  crypto.rs         # Certificate and crypto operations
  auth/
    mod.rs           # Auth module
    browser_flow.rs  # Webview-based browser flow
    rest_flow.rs     # REST API flow
  saml/
    mod.rs           # SAML module
    builder.rs       # AuthnRequest XML builder
    parser.rs        # SAML response parser
    validator.rs     # Signature and time validation
  tui/
    mod.rs           # TUI module
    app.rs           # Application state
    ui.rs            # UI rendering
    input.rs         # Keyboard input handling
config/
  PROD/config.json   # Production environment config
  TST/config.json    # Test environment config
```

## Building

```sh
cd seahorse
cargo build --release
```

The binary is output to `seahorse/target/release/seahorse`.

## Usage

```sh
./seahorse
```

The TUI will guide you through selecting an environment (PROD/TST), authentication flow, and display the SAML response details.

## CI/CD

- **CI** — Runs `cargo check`, `cargo test`, `cargo clippy`, and `cargo fmt --check` on every push/PR to `main`
- **Release** — Pushing a `v*` tag triggers cross-platform builds and creates a GitHub Release with artifacts:
  - `seahorse-linux-amd64.tar.gz`
  - `seahorse-windows-amd64.zip`
  - `seahorse-macos-arm64.tar.gz`
  - `seahorse-macos-amd64.tar.gz`
