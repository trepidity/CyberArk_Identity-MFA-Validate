# Tauri UI Rewrite Design Spec

**Date:** 2026-03-16
**Status:** Draft
**Scope:** Replace the ratatui TUI with a Tauri desktop app using HTML/CSS/JS frontend and the existing Rust backend.

## Background

The current ratatui TUI has fundamental conflicts with GUI operations on macOS. The wry webview (browser flow) pollutes the process with NSApplication, causing a spinning beach ball after the webview closes. File dialogs require platform-specific workarounds (osascript on macOS, rfd elsewhere). These problems are architectural — the TUI and GUI paradigms can't coexist cleanly in one process.

Tauri solves this by making the app a proper GUI app from the start. The webview IS the UI, so there's no conflict between rendering and native dialogs/windows.

## Goals

1. Replace the TUI with a Tauri desktop app — HTML/CSS/JS frontend, Rust backend
2. Preserve all existing backend logic unchanged (saml/, crypto, config, auth)
3. Native file dialogs, clipboard, and window management via Tauri plugins
4. Cross-platform: macOS and Windows (Linux nice-to-have)
5. Minimal effort — vanilla HTML/CSS/JS, no React/Vue/npm build step
6. No spinning beach ball

## Non-Goals

- Web deployment (Tauri is desktop-only)
- Mobile support
- Redesigning the SAML validation pipeline
- Adding new validation features (scope is UI only)

---

## Design

### 1. Architecture

The app has two layers connected by Tauri IPC:

**Frontend (HTML/CSS/JS):** A single-page app rendered in the OS webview (WebKit on macOS, WebView2 on Windows). Vanilla JS — no framework, no build step. Calls Rust backend via `window.__TAURI__.invoke("command_name", {args})`.

**Backend (Rust):** The existing saml/, crypto, config, and auth modules exposed as `#[tauri::command]` functions. These are thin wrappers (~5-10 lines each) that call existing functions and return serializable results.

### 2. Tauri Commands (the bridge)

Six commands expose the backend to the frontend:

```rust
#[tauri::command]
fn load_config(env: String) -> Result<ConfigInfo, String>
// Calls config::load_config, returns tenant URL, appkey, etc.

#[tauri::command]
async fn run_rest_flow(env: String, username: String, password: String, otp: String, signed: bool) -> Result<FlowResult, String>
// Calls auth::rest_flow + saml::builder + saml::validator
// Returns assertion XML + ValidationReport + assertion details

#[tauri::command]
fn decode_saml(input: String) -> Result<DecodedSaml, String>
// Calls saml::decoder::decode_saml_input + parser + validator
// Returns parsed details, attributes, validation report, pretty XML

#[tauri::command]
fn validate_assertion(xml: String, idp_cert_path: Option<String>) -> Result<ValidationInfo, String>
// Calls saml::validator::validate_assertion with optional trust store

#[tauri::command]
fn load_idp_cert(path: String) -> Result<CertInfo, String>
// Calls saml::trust::load_idp_certificates, returns CN, chain count, path

#[tauri::command]
fn get_cert_info(path: String) -> Result<CertInfo, String>
// Returns certificate details for display
```

All commands return `Result<T, String>` where T is a serde-serializable struct. Errors are returned as user-friendly strings.

### 3. Frontend Screens

**Screen 1: Home**
- PROD and TST environment buttons
- "View SAML Assertion" button
- Simple centered layout

**Screen 2: Authentication**
- Tab-style selector: Browser Flow / REST API Flow
- Credential inputs: Username, Password (REST only), OTP (REST only)
- Signed/Unsigned radio toggle
- Authenticate button
- Loading spinner during auth

**Screen 3: Validation Result**
- Split layout: left panel (details + validation), right panel (XML)
- Assertion details: Issuer, Subject, Audience, ID, timestamps
- Validation panel with color-coded checks (green checkmark, red cross, gray dash)
- Summary line: Trusted/Valid/Partial/Failed/Unsigned
- Metadata: Algorithm, Signer CN, Expiry, IDP Cert status
- Syntax-highlighted XML viewer with scroll
- Action buttons: Copy, Save Raw XML, Load IDP Cert

**Screen 4: SAML Viewer**
- Open File button (native file dialog via Tauri)
- Paste from Clipboard button
- Text area for manual paste
- Load IDP Cert button
- Decode & Validate button
- After decode: shows same result layout as Screen 3

### 4. Native Features via Tauri Plugins

- **dialog** — file open/save dialogs (replaces osascript/rfd)
- **clipboard-manager** — copy to clipboard (replaces arboard)
- **shell** — open external browser for browser flow
- **window** — window management

### 5. Browser Flow

The browser flow currently uses wry to embed a webview. With Tauri, two options:

**Option A (recommended):** Open the system browser via `tauri-plugin-shell::open()` and listen on a localhost HTTP server for the callback. This is the cleanest separation — the browser handles auth, Seahorse receives the SAMLResponse via HTTP redirect.

**Option B:** Open a second Tauri window for the webview login. More integrated but more complex.

The existing `auth::browser_flow` module already supports the HTTP listener pattern — it just needs the URL opened in the external browser instead of an embedded webview.

### 6. Project Structure

```
seahorse/
├── src-tauri/
│   ├── src/
│   │   ├── main.rs        — Tauri app setup, window config
│   │   ├── commands.rs     — #[tauri::command] bridge functions
│   │   ├── lib.rs          — re-exports existing modules
│   │   ├── saml/           — EXISTING, no changes
│   │   ├── crypto.rs       — EXISTING, no changes
│   │   ├── config.rs       — EXISTING, no changes
│   │   └── auth/           — EXISTING, no changes
│   ├── Cargo.toml          — tauri + existing deps (minus TUI deps)
│   ├── tauri.conf.json     — app metadata, window size, permissions
│   └── capabilities/       — Tauri v2 permission config
│
├── src/                    — Frontend (served by Tauri webview)
│   ├── index.html          — single page, all screens
│   ├── styles.css          — layout, colors, validation panel styling
│   └── app.js              — screen navigation, Tauri IPC calls, DOM updates
│
├── tests/                  — EXISTING, no changes
├── config/                 — EXISTING, no changes
└── sample_files/           — EXISTING, no changes
```

### 7. Dependencies

**Removed:** ratatui, crossterm, rfd, arboard, wry (direct), tao (direct)

**Added:** tauri (v2), tauri-plugin-dialog, tauri-plugin-clipboard-manager, tauri-plugin-shell, serde (already present), serde_json (already present)

**Kept:** openssl (vendored), quick-xml, base64, chrono, reqwest, tokio, uuid, flate2, urlencoding, anyhow, tracing

### 8. Migration Path

1. Create the Tauri project structure alongside existing code
2. Move existing Rust modules into src-tauri/src/
3. Write commands.rs (thin bridge layer)
4. Build the frontend (index.html + styles.css + app.js)
5. Wire up Tauri commands in app.js
6. Delete old TUI code (tui/ directory)
7. Update Cargo.toml (remove TUI deps, add Tauri)
8. Test on macOS and Windows

The backend tests continue to pass throughout because the modules are unchanged.
