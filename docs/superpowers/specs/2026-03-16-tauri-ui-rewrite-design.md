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

**Frontend (HTML/CSS/JS):** A single-page app rendered in the OS webview (WebKit on macOS, WebView2 on Windows). Vanilla JS — no framework, no build step. Uses `window.__TAURI__` global API (requires `app.withGlobalTauri = true` in `tauri.conf.json` since we have no JS bundler).

**Backend (Rust):** The existing saml/, crypto, config, and auth modules exposed as `#[tauri::command]` functions. These are thin wrappers (~5-10 lines each) that call existing functions and return serializable DTOs.

**Serialization requirement:** Existing backend types (`ValidationReport`, `AssertionDetails`, `DecodeResult`, etc.) currently derive only `Debug, Clone`. They need `#[derive(Serialize)]` added. This is additive and non-breaking — the only "change" to backend modules. Types containing non-serializable fields (e.g., `IdpTrustStore` with `openssl::X509`) get purpose-built DTOs in `commands.rs` that extract displayable fields (CN, fingerprint, expiry).

### 2. State Management

Shared mutable state is held via `tauri::State<Mutex<T>>`:

```rust
struct AppState {
    config: Option<Config>,
    config_dir: Option<PathBuf>,
    idp_trust_store: Option<IdpTrustStore>,
    last_raw_xml: Option<String>, // for Save Raw XML
}
```

Commands receive `state: tauri::State<'_, Mutex<AppState>>` and lock as needed. This mirrors the current `App` struct's role as a state container.

**Config resolution:** The app locates the `config/` directory relative to the executable at startup (same `find_config_base_path()` logic). On macOS/Windows bundles, Tauri's `app.path().resource_dir()` can be used as a fallback. The resolved base path is stored in `AppState.config_dir`.

### 3. Tauri Commands (the bridge)

```rust
#[tauri::command]
fn load_config(state: State<Mutex<AppState>>, env: String) -> Result<ConfigInfo, String>
// Calls config::load_config, stores Config in state
// Returns ConfigInfo (subset excluding certkey and certificate filename)

#[tauri::command]
async fn run_rest_flow(state: State<'_, Mutex<AppState>>, username: String, password: String, otp: String, signed: bool) -> Result<FlowResult, String>
// Orchestrates the full REST auth flow (6 steps)
// Emits "auth-progress" events for step-by-step status updates
// Returns assertion XML + validation report + assertion details
// Stores raw XML in state for Save

#[tauri::command]
fn decode_saml(state: State<Mutex<AppState>>, input: String) -> Result<DecodedSaml, String>
// Calls saml::decoder + parser + validator
// Returns a tagged enum by document type (see below)

#[tauri::command]
fn validate_assertion(state: State<Mutex<AppState>>, xml: String) -> Result<ValidationReportDto, String>
// Uses trust store from state if loaded
// Returns serializable validation report

#[tauri::command]
fn load_idp_cert(state: State<Mutex<AppState>>, path: String) -> Result<CertInfoDto, String>
// Loads PEM, stores IdpTrustStore in state
// Returns CN, chain count, path, expiry
```

**ConfigInfo DTO** (excludes sensitive fields):
```rust
#[derive(Serialize)]
struct ConfigInfo {
    url: String,      // tenant URL
    timeout: u64,
    check_user: bool,
    use_bypass: bool,
    browser: String,
    has_idp_cert: bool, // whether idp_certificate is configured
}
```

**DecodedSaml return type** (tagged enum for frontend branching):
```rust
#[derive(Serialize)]
#[serde(tag = "type")]
enum DecodedSaml {
    AuthnRequest { details: AuthnRequestDetailsDto, pretty_xml: String },
    Response { response: ResponseDetailsDto, assertion: Option<AssertionDetailsDto>, attributes: Vec<SamlAttributeDto>, validation: Option<ValidationReportDto>, pretty_xml: String },
    Assertion { details: AssertionDetailsDto, attributes: Vec<SamlAttributeDto>, validation: ValidationReportDto, pretty_xml: String },
}
```

**Progress events** during REST flow:
```rust
app.emit("auth-progress", json!({"step": "password", "message": "Authenticating with password..."}));
```
Frontend listens with `window.__TAURI__.event.listen("auth-progress", callback)`.

### 4. Frontend Screens

**Screen 1: Home**
- PROD and TST environment buttons
- "View SAML Assertion" button
- Simple centered layout

**Screen 2: Authentication**
- Tab-style selector: Browser Flow / REST API Flow
- Credential inputs: Username, Password (REST only), OTP (REST only)
- Signed/Unsigned radio toggle
- Authenticate button
- Progress indicator showing current step ("Authenticating with password...", "Validating OTP...")

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

**Error handling:** Errors from commands are displayed as a dismissible banner/toast at the top of the current screen with the error message and a "Retry" or "Dismiss" button. Critical errors (config not found) redirect to an error screen with a "Back to Home" option. No separate error screen needed for transient failures.

### 5. Browser Flow

The existing browser flow uses an embedded wry webview with JavaScript injection to intercept `HTMLFormElement.prototype.submit()` and capture the SAMLResponse. This approach is necessary because the CyberArk SAML POST is sent to `/security/whoami`, not a configurable callback URL.

**Tauri approach:** Open a second Tauri `WebviewWindow` with the same JavaScript injection strategy. This works because Tauri's webview supports initialization scripts (`webview.eval()` or `initialization_scripts` in window config). The second window captures the SAMLResponse via Tauri's IPC, emits an event to the main window, then closes itself.

This is functionally identical to the current wry approach but within Tauri's proper event loop — no beach ball.

### 6. Native Features via Tauri Plugins

- **dialog** — file open/save dialogs (replaces osascript/rfd)
- **clipboard-manager** — copy to clipboard (replaces arboard)
- **shell** — open URLs in system browser (if needed)

**Required Tauri v2 capability permissions** (in `capabilities/default.json`):
```json
{
  "permissions": [
    "core:default",
    "dialog:allow-open",
    "dialog:allow-save",
    "clipboard-manager:allow-write-text",
    "clipboard-manager:allow-read-text",
    "shell:allow-open"
  ]
}
```

### 7. Project Structure

```
seahorse/
├── src-tauri/
│   ├── src/
│   │   ├── main.rs        — Tauri app setup, window config, state init
│   │   ├── commands.rs     — #[tauri::command] bridge functions + DTOs
│   │   └── lib.rs          — re-exports existing modules
│   ├── Cargo.toml          — depends on seahorse lib crate via path
│   ├── tauri.conf.json     — app name, window 800x700, withGlobalTauri
│   └── capabilities/       — Tauri v2 permission config
│
├── src/                    — Frontend (served by Tauri webview)
│   ├── index.html          — single page, all screens
│   ├── styles.css          — layout, colors, validation panel styling
│   └── app.js              — screen navigation, Tauri IPC calls, DOM updates
│
├── src/                    — Existing library crate (unchanged)
│   ├── lib.rs
│   ├── saml/               — c14n, validator, parser, trust, builder, decoder
│   ├── crypto.rs
│   ├── config.rs
│   └── auth/
│
├── tests/                  — EXISTING, no changes
├── config/                 — EXISTING, no changes
└── sample_files/           — EXISTING, no changes
```

**Key:** `src-tauri/Cargo.toml` depends on the `seahorse` library crate via path dependency (`seahorse = { path = ".." }`). This avoids physically moving files and keeps existing tests working. The `seahorse` lib crate gets `Serialize` derives added to its public types.

### 8. Dependencies

**Removed from lib:** ratatui, crossterm, rfd, arboard, wry (direct), tao (direct), objc

**Added to src-tauri:** tauri (v2), tauri-plugin-dialog, tauri-plugin-clipboard-manager, tauri-plugin-shell

**Kept in lib:** openssl (vendored), quick-xml, base64, chrono, reqwest, tokio, uuid, flate2, urlencoding, anyhow, tracing, serde, serde_json

### 9. Window Configuration

In `tauri.conf.json`:
```json
{
  "app": {
    "withGlobalTauri": true,
    "windows": [{
      "title": "Seahorse — SAML Validation Tool",
      "width": 800,
      "height": 700,
      "resizable": true,
      "minWidth": 600,
      "minHeight": 500
    }]
  }
}
```

### 10. Logging

Use `tauri-plugin-log` to write logs to the platform-appropriate location (`app_data_dir`). Falls back to `tracing` output in dev mode.

### 11. Migration Path

1. Add `#[derive(Serialize)]` to existing backend types (~10 structs)
2. Create `src-tauri/` with Cargo.toml depending on seahorse lib crate
3. Write `commands.rs` (thin bridge layer + DTOs)
4. Write `main.rs` (Tauri app setup, state init)
5. Build the frontend (`index.html` + `styles.css` + `app.js`)
6. Wire up Tauri commands in `app.js`
7. Adapt browser flow to use second Tauri window
8. Configure `tauri.conf.json` and capabilities
9. Delete old TUI code (`tui/` directory, old `main.rs`)
10. Test on macOS and Windows

The backend tests continue to pass throughout because the lib crate modules are unchanged (only Serialize derives added).
