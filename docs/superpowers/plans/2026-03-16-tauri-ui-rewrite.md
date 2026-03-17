# Tauri UI Rewrite Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the ratatui TUI with a Tauri v2 desktop app using HTML/CSS/JS frontend while preserving all existing Rust backend logic.

**Architecture:** Tauri v2 app with `src-tauri/` containing Rust commands that call the existing `seahorse` library crate via path dependency. Frontend is vanilla HTML/CSS/JS in `seahorse/src/` (Tauri's default frontend dir). The `seahorse` lib crate gets `Serialize` derives added to ~10 types. A thin `commands.rs` bridges frontend and backend via DTOs.

**Tech Stack:** Tauri v2, vanilla HTML/CSS/JS (no framework), existing Rust backend (openssl, quick-xml, reqwest, tokio)

**Spec:** `docs/superpowers/specs/2026-03-16-tauri-ui-rewrite-design.md`

---

## Chunk 1: Serialize Derives + Tauri Project Scaffold

### Task 1: Add Serialize Derives to Backend Types

**Files:**
- Modify: `seahorse/src/saml/validator.rs`
- Modify: `seahorse/src/saml/parser.rs`
- Modify: `seahorse/src/saml/decoder.rs`
- Modify: `seahorse/src/config.rs`

Add `#[derive(serde::Serialize)]` to all public types that will cross the IPC boundary. This is additive and non-breaking — existing tests must still pass.

- [ ] **Step 1: Add Serialize to validator types**

In `seahorse/src/saml/validator.rs`, update derives:
```rust
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum ValidationSummary { ... }

#[derive(Debug, Clone, serde::Serialize)]
pub struct ValidationCheck { ... }

#[derive(Debug, Clone, serde::Serialize)]
pub struct ValidationReport { ... }
```

- [ ] **Step 2: Add Serialize to parser types**

In `seahorse/src/saml/parser.rs`, update derives on:
- `AssertionDetails`
- `AuthnRequestDetails`
- `ResponseDetails`
- `SamlAttribute`
- `SamlParseResult`

- [ ] **Step 3: Add Serialize to decoder types**

In `seahorse/src/saml/decoder.rs`, update derives on:
- `SamlDocumentType`
- `DecodeResult`

- [ ] **Step 4: Add Serialize to config types**

In `seahorse/src/config.rs`, update derives on:
- `Config`
- `Environment`

- [ ] **Step 5: Verify all tests pass**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test`
Expected: All 67+ tests PASS

- [ ] **Step 6: Commit**

```bash
git add seahorse/src/saml/validator.rs seahorse/src/saml/parser.rs seahorse/src/saml/decoder.rs seahorse/src/config.rs
git commit -m "feat: add Serialize derives to backend types for Tauri IPC"
```

---

### Task 2: Initialize Tauri Project Structure

**Files:**
- Create: `seahorse/src-tauri/Cargo.toml`
- Create: `seahorse/src-tauri/src/main.rs`
- Create: `seahorse/src-tauri/src/lib.rs`
- Create: `seahorse/src-tauri/tauri.conf.json`
- Create: `seahorse/src-tauri/capabilities/default.json`
- Create: `seahorse/src-tauri/build.rs`
- Modify: `seahorse/Cargo.toml` (ensure lib target exists alongside bin)

This task scaffolds the Tauri project that depends on the seahorse library crate.

- [ ] **Step 1: Ensure seahorse has a lib target**

The existing `seahorse/Cargo.toml` has `[[bin]]` for the TUI binary. Ensure it also has a `[lib]` section (it should — check `src/lib.rs` exists).

- [ ] **Step 2: Remove TUI-only deps from lib crate**

In `seahorse/Cargo.toml`, the TUI deps (`ratatui`, `crossterm`, `rfd`, `arboard`, `objc`, `wry`, `tao`) should stay for now (the old binary still references them). They'll be removed in the final cleanup task. For now, just ensure the lib crate compiles cleanly.

- [ ] **Step 3: Create src-tauri/Cargo.toml**

```toml
[package]
name = "seahorse-tauri"
version = "1.0.0"
edition = "2021"
description = "Seahorse SAML Validation Tool - Desktop App"

[lib]
name = "seahorse_tauri_lib"
crate-type = ["staticlib", "cdylib", "rlib"]

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
seahorse = { path = ".." }
tauri = { version = "2", features = [] }
tauri-plugin-dialog = "2"
tauri-plugin-clipboard-manager = "2"
tauri-plugin-shell = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
anyhow = "1"
tracing = "0.1"
```

- [ ] **Step 4: Create src-tauri/build.rs**

```rust
fn main() {
    tauri_build::build()
}
```

- [ ] **Step 5: Create src-tauri/tauri.conf.json**

```json
{
  "$schema": "https://raw.githubusercontent.com/nicedoc/tauri-schema/main/v2.json",
  "productName": "Seahorse",
  "version": "1.0.0",
  "identifier": "org.bswh.seahorse",
  "build": {
    "frontendDist": "../src",
    "devUrl": "http://localhost:1420"
  },
  "app": {
    "withGlobalTauri": true,
    "windows": [
      {
        "title": "Seahorse — SAML Validation Tool",
        "width": 900,
        "height": 700,
        "resizable": true,
        "minWidth": 600,
        "minHeight": 500
      }
    ],
    "security": {
      "csp": null
    }
  },
  "bundle": {
    "active": true,
    "targets": "all",
    "icon": []
  }
}
```

- [ ] **Step 6: Create src-tauri/capabilities/default.json**

```json
{
  "identifier": "default",
  "description": "Default capabilities for Seahorse",
  "windows": ["main"],
  "permissions": [
    "core:default",
    "dialog:default",
    "clipboard-manager:allow-write-text",
    "clipboard-manager:allow-read-text",
    "shell:allow-open"
  ]
}
```

- [ ] **Step 7: Create minimal src-tauri/src/lib.rs**

```rust
use tauri::Manager;

mod commands;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            commands::load_config,
            commands::decode_saml,
            commands::validate_assertion,
            commands::load_idp_cert,
        ])
        .setup(|app| {
            // Initialize app state
            app.manage(std::sync::Mutex::new(commands::AppState::default()));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

- [ ] **Step 8: Create minimal src-tauri/src/main.rs**

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    seahorse_tauri_lib::run();
}
```

- [ ] **Step 9: Create stub src-tauri/src/commands.rs**

```rust
use std::path::PathBuf;
use std::sync::Mutex;
use serde::Serialize;
use tauri::State;

#[derive(Default)]
pub struct AppState {
    pub config: Option<seahorse::config::Config>,
    pub config_dir: Option<PathBuf>,
    pub idp_trust_store: Option<seahorse::saml::trust::IdpTrustStore>,
    pub last_raw_xml: Option<String>,
}

#[tauri::command]
pub fn load_config(state: State<Mutex<AppState>>, env: String) -> Result<String, String> {
    Ok(format!("Config loaded for {}", env))
}

#[tauri::command]
pub fn decode_saml(state: State<Mutex<AppState>>, input: String) -> Result<String, String> {
    Ok("Stub".to_string())
}

#[tauri::command]
pub fn validate_assertion(state: State<Mutex<AppState>>, xml: String) -> Result<String, String> {
    Ok("Stub".to_string())
}

#[tauri::command]
pub fn load_idp_cert(state: State<Mutex<AppState>>, path: String) -> Result<String, String> {
    Ok("Stub".to_string())
}
```

- [ ] **Step 10: Create minimal frontend placeholder**

Create `seahorse/src/index.html`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Seahorse</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div id="app">
    <h1>Seahorse</h1>
    <p>SAML Validation Tool</p>
    <p id="status">Loading...</p>
  </div>
  <script src="app.js"></script>
</body>
</html>
```

Create `seahorse/src/styles.css`:
```css
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; }
#app { padding: 24px; }
h1 { color: #60a5fa; }
```

Create `seahorse/src/app.js`:
```javascript
document.getElementById('status').textContent = 'Tauri app loaded!';
```

NOTE: These frontend files go in `seahorse/src/` which conflicts with the existing Rust `src/` directory. Tauri's `frontendDist` points here. The Rust lib crate sources are also in `src/`. This is fine — Tauri only serves `.html`, `.css`, `.js` files from the frontend dist directory. But to avoid confusion, we may need to put frontend files in a separate directory like `seahorse/ui/` and update `frontendDist` accordingly.

**Actually — use `seahorse/ui/` for frontend files:**

Update `tauri.conf.json` `frontendDist` to `"../ui"` and create:
- `seahorse/ui/index.html`
- `seahorse/ui/styles.css`
- `seahorse/ui/app.js`

- [ ] **Step 11: Verify Tauri project builds**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse/src-tauri && cargo build`
Expected: Compiles (may take a while first time for Tauri deps)

- [ ] **Step 12: Verify existing tests still pass**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test`
Expected: All tests PASS (lib crate unchanged)

- [ ] **Step 13: Commit**

```bash
git add seahorse/src-tauri/ seahorse/ui/
git commit -m "feat: scaffold Tauri v2 project with stub commands and placeholder frontend"
```

---

## Chunk 2: Commands Layer (DTOs + Real Implementations)

### Task 3: Implement load_config Command

**Files:**
- Modify: `seahorse/src-tauri/src/commands.rs`

- [ ] **Step 1: Implement ConfigInfo DTO and load_config**

```rust
#[derive(Serialize)]
pub struct ConfigInfo {
    pub url: String,
    pub timeout: u64,
    pub check_user: bool,
    pub use_bypass: bool,
    pub browser: String,
    pub has_idp_cert: bool,
}

#[tauri::command]
pub fn load_config(state: State<Mutex<AppState>>, env: String) -> Result<ConfigInfo, String> {
    let environment = match env.as_str() {
        "PROD" => seahorse::config::Environment::Prod,
        "TST" => seahorse::config::Environment::Tst,
        _ => return Err(format!("Unknown environment: {}", env)),
    };

    // Find config base path
    let base = find_config_base_path()
        .ok_or_else(|| "Could not find config/ directory".to_string())?;
    let config_dir = seahorse::config::get_config_dir(&base, environment);
    let config = seahorse::config::load_config(&config_dir)
        .map_err(|e| format!("Failed to load config: {}", e))?;

    let has_idp_cert = config.idp_certificate.is_some();

    // Load IDP cert from config if specified
    if let Some(ref idp_cert_file) = config.idp_certificate {
        let idp_cert_path = config_dir.join(idp_cert_file);
        if let Ok(store) = seahorse::saml::trust::load_idp_certificates(&idp_cert_path) {
            let mut state = state.lock().unwrap();
            state.idp_trust_store = Some(store);
        }
    }

    let info = ConfigInfo {
        url: config.url.clone(),
        timeout: config.timeout,
        check_user: config.check_user,
        use_bypass: config.use_bypass,
        browser: config.browser.clone(),
        has_idp_cert,
    };

    let mut state = state.lock().unwrap();
    state.config = Some(config);
    state.config_dir = Some(config_dir);

    Ok(info)
}

fn find_config_base_path() -> Option<std::path::PathBuf> {
    // Same logic as existing main.rs find_config_base_path
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("config").is_dir() { return Some(cwd); }
        if let Some(parent) = cwd.parent() {
            if parent.join("config").is_dir() { return Some(parent.to_path_buf()); }
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            if exe_dir.join("config").is_dir() { return Some(exe_dir.to_path_buf()); }
            if let Some(parent) = exe_dir.parent() {
                if parent.join("config").is_dir() { return Some(parent.to_path_buf()); }
            }
        }
    }
    None
}
```

- [ ] **Step 2: Verify build**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse/src-tauri && cargo check`

- [ ] **Step 3: Commit**

```bash
git add seahorse/src-tauri/src/commands.rs
git commit -m "feat: implement load_config Tauri command with ConfigInfo DTO"
```

---

### Task 4: Implement decode_saml and validate_assertion Commands

**Files:**
- Modify: `seahorse/src-tauri/src/commands.rs`

- [ ] **Step 1: Add validation and decode DTOs**

These DTOs wrap existing types that already have Serialize. For types that ARE already Serialize (like `ValidationReport`), we can return them directly. For types with non-serializable fields, create thin DTOs.

```rust
#[derive(Serialize)]
pub struct CertInfoDto {
    pub cn: String,
    pub chain_count: usize,
    pub source_path: String,
}

#[derive(Serialize)]
#[serde(tag = "type")]
pub enum DecodedSaml {
    AuthnRequest {
        details: seahorse::saml::parser::AuthnRequestDetails,
        pretty_xml: String,
    },
    Response {
        response: seahorse::saml::parser::ResponseDetails,
        assertion: Option<seahorse::saml::parser::AssertionDetails>,
        attributes: Vec<seahorse::saml::parser::SamlAttribute>,
        validation: Option<seahorse::saml::validator::ValidationReport>,
        pretty_xml: String,
        raw_xml: String,
    },
    Assertion {
        details: seahorse::saml::parser::AssertionDetails,
        attributes: Vec<seahorse::saml::parser::SamlAttribute>,
        validation: seahorse::saml::validator::ValidationReport,
        pretty_xml: String,
        raw_xml: String,
    },
}
```

- [ ] **Step 2: Implement decode_saml**

```rust
#[tauri::command]
pub fn decode_saml(state: State<Mutex<AppState>>, input: String) -> Result<DecodedSaml, String> {
    let result = seahorse::saml::decoder::decode_saml_input(&input)
        .map_err(|e| format!("Failed to decode SAML: {}", e))?;

    let pretty_xml = seahorse::saml::parser::pretty_print_xml(&result.xml);

    let trust_store = {
        let state = state.lock().unwrap();
        // We can't pass a reference out of the lock, so check if loaded
        state.idp_trust_store.is_some()
    };

    match result.document_type {
        seahorse::saml::decoder::SamlDocumentType::AuthnRequest => {
            let details = seahorse::saml::parser::extract_authn_request_details(&result.xml)
                .map_err(|e| format!("Failed to parse AuthnRequest: {}", e))?;
            Ok(DecodedSaml::AuthnRequest { details, pretty_xml })
        }
        seahorse::saml::decoder::SamlDocumentType::Response => {
            let response = seahorse::saml::parser::extract_response_details(&result.xml).ok();
            let (assertion, attributes, validation, raw_assertion) =
                if let Ok(assertion_xml) = seahorse::saml::parser::extract_assertion_from_response(&result.xml) {
                    let details = seahorse::saml::parser::extract_assertion_details(&assertion_xml).ok();
                    let attrs = seahorse::saml::parser::extract_attributes(&assertion_xml).unwrap_or_default();
                    let state_guard = state.lock().unwrap();
                    let report = seahorse::saml::validator::validate_assertion(
                        &assertion_xml,
                        state_guard.idp_trust_store.as_ref(),
                    );
                    (details, attrs, Some(report), assertion_xml)
                } else {
                    (None, vec![], None, String::new())
                };
            // Store raw XML for saving
            {
                let mut state_guard = state.lock().unwrap();
                state_guard.last_raw_xml = Some(raw_assertion.clone());
            }
            Ok(DecodedSaml::Response {
                response: response.unwrap_or_else(|| seahorse::saml::parser::ResponseDetails {
                    id: String::new(), issue_instant: String::new(), issuer: String::new(),
                    destination: None, in_response_to: None, status: String::new(),
                }),
                assertion, attributes, validation, pretty_xml,
                raw_xml: raw_assertion,
            })
        }
        seahorse::saml::decoder::SamlDocumentType::Assertion => {
            let details = seahorse::saml::parser::extract_assertion_details(&result.xml)
                .map_err(|e| format!("Failed to parse assertion: {}", e))?;
            let attributes = seahorse::saml::parser::extract_attributes(&result.xml).unwrap_or_default();
            let state_guard = state.lock().unwrap();
            let validation = seahorse::saml::validator::validate_assertion(
                &result.xml,
                state_guard.idp_trust_store.as_ref(),
            );
            drop(state_guard);
            // Store raw XML
            {
                let mut state_guard = state.lock().unwrap();
                state_guard.last_raw_xml = Some(result.xml.clone());
            }
            Ok(DecodedSaml::Assertion {
                details, attributes, validation, pretty_xml,
                raw_xml: result.xml,
            })
        }
    }
}
```

- [ ] **Step 3: Implement validate_assertion and load_idp_cert**

```rust
#[tauri::command]
pub fn validate_assertion(state: State<Mutex<AppState>>, xml: String) -> Result<seahorse::saml::validator::ValidationReport, String> {
    let state_guard = state.lock().unwrap();
    let report = seahorse::saml::validator::validate_assertion(
        &xml,
        state_guard.idp_trust_store.as_ref(),
    );
    Ok(report)
}

#[tauri::command]
pub fn load_idp_cert(state: State<Mutex<AppState>>, path: String) -> Result<CertInfoDto, String> {
    let store = seahorse::saml::trust::load_idp_certificates(std::path::Path::new(&path))
        .map_err(|e| format!("Failed to load IDP certificate: {}", e))?;

    let info = CertInfoDto {
        cn: seahorse::saml::trust::cert_cn(&store.leaf_cert),
        chain_count: store.chain_certs.len(),
        source_path: path,
    };

    let mut state_guard = state.lock().unwrap();
    state_guard.idp_trust_store = Some(store);

    Ok(info)
}
```

- [ ] **Step 4: Verify Tauri build**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse/src-tauri && cargo check`

- [ ] **Step 5: Verify lib tests still pass**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test`

- [ ] **Step 6: Commit**

```bash
git add seahorse/src-tauri/src/commands.rs
git commit -m "feat: implement decode_saml, validate_assertion, load_idp_cert Tauri commands"
```

---

## Chunk 3: Frontend — HTML/CSS/JS

### Task 5: Build the Frontend — HTML Structure

**Files:**
- Create: `seahorse/ui/index.html` (replace placeholder)

The single HTML file contains all 4 screens as `<section>` elements, shown/hidden by JS. No routing library needed.

- [ ] **Step 1: Write index.html with all screen sections**

The HTML should include:
- `<section id="screen-home">` — PROD/TST buttons + View SAML button
- `<section id="screen-auth">` — flow selector tabs, credential form, authenticate button, progress area
- `<section id="screen-result">` — split layout with details/validation left, XML right, action buttons
- `<section id="screen-viewer">` — open file/paste buttons, textarea, decode button
- `<div id="error-toast">` — dismissible error banner (hidden by default)

Each section has `display: none` by default. JS shows the active one.

- [ ] **Step 2: Commit**

```bash
git add seahorse/ui/index.html
git commit -m "feat: add HTML structure for all 4 Tauri frontend screens"
```

---

### Task 6: Build the Frontend — CSS Styling

**Files:**
- Create: `seahorse/ui/styles.css` (replace placeholder)

Dark theme matching the wireframe mockups. Responsive layout with CSS grid/flexbox.

- [ ] **Step 1: Write styles.css**

Key styles needed:
- Dark background (#0f172a), light text (#e2e8f0)
- Card/panel styling with borders and rounded corners
- Split layout for result screen (flex with gap)
- Validation check colors: green (#22c55e), red (#ef4444), gray (#64748b)
- Form inputs with dark theme
- Button styles (primary blue #1e40af, secondary gray)
- XML viewer with monospace font and syntax highlighting colors
- Toast/banner styles for errors
- Loading spinner

- [ ] **Step 2: Commit**

```bash
git add seahorse/ui/styles.css
git commit -m "feat: add dark-theme CSS for Tauri frontend"
```

---

### Task 7: Build the Frontend — JavaScript Application Logic

**Files:**
- Create: `seahorse/ui/app.js` (replace placeholder)

Vanilla JS — no framework. Screen navigation, Tauri IPC calls, DOM manipulation.

- [ ] **Step 1: Write app.js with screen navigation and Tauri IPC**

Key functions:
```javascript
// Screen navigation
function showScreen(screenId) { /* hide all sections, show target */ }

// Tauri command wrappers
async function loadConfig(env) { return window.__TAURI__.core.invoke('load_config', { env }); }
async function decodeSaml(input) { return window.__TAURI__.core.invoke('decode_saml', { input }); }
async function validateAssertion(xml) { return window.__TAURI__.core.invoke('validate_assertion', { xml }); }
async function loadIdpCert(path) { return window.__TAURI__.core.invoke('load_idp_cert', { path }); }

// Native dialog wrappers
async function openFileDialog(filters) { return window.__TAURI__.dialog.open({ filters }); }
async function saveFileDialog(defaultName) { return window.__TAURI__.dialog.save({ defaultPath: defaultName }); }
async function copyToClipboard(text) { return window.__TAURI__.clipboardManager.writeText(text); }

// Screen handlers
async function onSelectEnv(env) { /* loadConfig, showScreen('auth') */ }
async function onAuthenticate() { /* collect form, run_rest_flow, render result */ }
async function onDecodeViewer() { /* get textarea content, decodeSaml, render result */ }
async function onOpenFile() { /* openFileDialog, read file, decodeSaml */ }
async function onLoadIdpCert() { /* openFileDialog for PEM, loadIdpCert, re-validate */ }
async function onSaveRawXml() { /* saveFileDialog, write via Tauri fs */ }
async function onCopyXml() { /* copyToClipboard */ }

// Rendering
function renderValidationReport(report, containerId) { /* build colored check HTML */ }
function renderAssertionDetails(details, containerId) { /* build detail rows */ }
function renderXml(prettyXml, containerId) { /* syntax highlight and display */ }
function showError(message) { /* show toast */ }
function hideError() { /* hide toast */ }
```

- [ ] **Step 2: Wire up event listeners**

```javascript
// Home screen
document.getElementById('btn-prod').addEventListener('click', () => onSelectEnv('PROD'));
document.getElementById('btn-tst').addEventListener('click', () => onSelectEnv('TST'));
document.getElementById('btn-viewer').addEventListener('click', () => showScreen('screen-viewer'));

// Auth screen
document.getElementById('btn-authenticate').addEventListener('click', onAuthenticate);

// Viewer screen
document.getElementById('btn-open-file').addEventListener('click', onOpenFile);
document.getElementById('btn-decode').addEventListener('click', onDecodeViewer);

// Result screen actions
document.getElementById('btn-copy').addEventListener('click', onCopyXml);
document.getElementById('btn-save').addEventListener('click', onSaveRawXml);
document.getElementById('btn-load-cert').addEventListener('click', onLoadIdpCert);
```

- [ ] **Step 3: Implement renderValidationReport**

Build colored HTML for the validation checks:
```javascript
function renderValidationReport(report, containerId) {
    const container = document.getElementById(containerId);
    const summaryColors = {
        Trusted: '#22c55e', Valid: '#22c55e',
        Partial: '#eab308', Unsigned: '#64748b', Failed: '#ef4444'
    };
    let html = `<div class="validation-summary" style="color: ${summaryColors[report.summary]}">
        ${report.summary === 'Trusted' || report.summary === 'Valid' ? '✓' : report.summary === 'Failed' ? '✗' : '—'}
        ${report.summary}</div>`;
    for (const check of report.checks) {
        const icon = check.passed ? '✓' : '✗';
        const color = check.passed ? '#22c55e' : '#ef4444';
        html += `<div class="validation-check">
            <span style="color:${color}">${icon}</span>
            <span class="check-name">${check.name}:</span>
            <span>${check.detail}</span>
        </div>`;
        if (check.diagnostic) {
            html += `<div class="check-diagnostic">${check.diagnostic}</div>`;
        }
    }
    container.innerHTML = html;
}
```

- [ ] **Step 4: Implement XML syntax highlighting**

Simple regex-based colorizer:
```javascript
function highlightXml(xml) {
    return xml
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/&lt;(\/?)([\w:]+)/g, '&lt;$1<span class="xml-tag">$2</span>')
        .replace(/([\w:]+)=(".*?")/g, '<span class="xml-attr">$1</span>=<span class="xml-value">$2</span>');
}
```

- [ ] **Step 5: Verify the full app runs**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse/src-tauri && cargo tauri dev`
Expected: Window opens, Home screen shows, clicking PROD/TST loads config

- [ ] **Step 6: Commit**

```bash
git add seahorse/ui/app.js
git commit -m "feat: implement frontend JavaScript with screen navigation and Tauri IPC"
```

---

## Chunk 4: REST Flow + Browser Flow Integration

### Task 8: Implement REST Flow Command

**Files:**
- Modify: `seahorse/src-tauri/src/commands.rs`
- Modify: `seahorse/src-tauri/src/lib.rs`

- [ ] **Step 1: Add run_rest_flow command**

This is the most complex command — it orchestrates the 6-step REST auth flow and emits progress events.

```rust
#[tauri::command]
pub async fn run_rest_flow(
    app: tauri::AppHandle,
    state: State<'_, Mutex<AppState>>,
    username: String,
    password: String,
    otp: String,
    signed: bool,
) -> Result<DecodedSaml, String> {
    // Extract config from state
    let (config, config_dir) = {
        let s = state.lock().unwrap();
        let config = s.config.clone().ok_or("No config loaded")?;
        let config_dir = s.config_dir.clone().ok_or("No config dir")?;
        (config, config_dir)
    };

    // Progress helper
    let emit_progress = |step: &str, msg: &str| {
        let _ = app.emit("auth-progress", serde_json::json!({
            "step": step, "message": msg
        }));
    };

    // Run the REST flow steps (same logic as current main.rs run_rest_flow)
    // ... (call seahorse::auth::rest_flow functions)
    // ... emit progress at each step
    // ... build assertion, validate, return DecodedSaml::Assertion
    todo!("Implement full REST flow orchestration")
}
```

The full implementation should mirror `main.rs` lines 189-472 but as an async function that emits progress events and returns a `DecodedSaml`.

- [ ] **Step 2: Register the command in lib.rs**

Add `commands::run_rest_flow` to the `invoke_handler` in `lib.rs`.

- [ ] **Step 3: Wire up frontend progress listener**

In `app.js`, add:
```javascript
window.__TAURI__.event.listen('auth-progress', (event) => {
    document.getElementById('auth-progress').textContent = event.payload.message;
});
```

- [ ] **Step 4: Verify REST flow works end-to-end**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse/src-tauri && cargo tauri dev`
Test: Select TST → REST Flow → enter credentials → Authenticate
Expected: Progress updates appear, validation result displays

- [ ] **Step 5: Commit**

```bash
git add seahorse/src-tauri/src/commands.rs seahorse/src-tauri/src/lib.rs seahorse/ui/app.js
git commit -m "feat: implement REST flow Tauri command with progress events"
```

---

### Task 9: Implement Browser Flow via Second Tauri Window

**Files:**
- Modify: `seahorse/src-tauri/src/commands.rs`
- Modify: `seahorse/src-tauri/src/lib.rs`

- [ ] **Step 1: Add run_browser_flow command**

Opens a second Tauri WebviewWindow with the CyberArk login URL and JavaScript injection to capture SAMLResponse:

```rust
#[tauri::command]
pub async fn run_browser_flow(
    app: tauri::AppHandle,
    state: State<'_, Mutex<AppState>>,
    username: String,
) -> Result<DecodedSaml, String> {
    let config = {
        let s = state.lock().unwrap();
        s.config.clone().ok_or("No config loaded")?
    };

    let login_url = seahorse::auth::browser_flow::build_login_url(
        &config.url, &username, &config.appkey
    );

    // Create a second webview window for CyberArk login
    let window = tauri::WebviewWindowBuilder::new(
        &app,
        "auth-browser",
        tauri::WebviewUrl::External(login_url.parse().unwrap()),
    )
    .title("CyberArk Identity Login")
    .inner_size(800.0, 700.0)
    .build()
    .map_err(|e| format!("Failed to open browser window: {}", e))?;

    // Inject JavaScript to intercept form submission and capture SAMLResponse
    // (same injection logic as current browser_flow.rs)
    let js = r#"
        // ... intercept HTMLFormElement.prototype.submit
        // ... capture SAMLResponse from form data
        // ... post back via window.__TAURI__.event.emit
    "#;
    window.eval(js).map_err(|e| format!("JS injection failed: {}", e))?;

    // Listen for the SAMLResponse event from the auth window
    // Process and return as DecodedSaml
    todo!("Implement browser flow capture via second window events")
}
```

- [ ] **Step 2: Register command and test**

- [ ] **Step 3: Commit**

```bash
git commit -m "feat: implement browser flow via second Tauri window with JS injection"
```

---

## Chunk 5: Final Integration and Cleanup

### Task 10: Save Raw XML via Tauri Dialog

**Files:**
- Modify: `seahorse/src-tauri/src/commands.rs`
- Modify: `seahorse/ui/app.js`

- [ ] **Step 1: Add save_raw_xml command**

```rust
#[tauri::command]
pub fn save_raw_xml(state: State<Mutex<AppState>>, path: String) -> Result<(), String> {
    let xml = {
        let s = state.lock().unwrap();
        s.last_raw_xml.clone().ok_or("No SAML data to save")?
    };
    std::fs::write(&path, &xml).map_err(|e| format!("Failed to save: {}", e))
}
```

- [ ] **Step 2: Wire up frontend save button**

```javascript
async function onSaveRawXml() {
    const path = await window.__TAURI__.dialog.save({
        defaultPath: 'assertion.xml',
        filters: [{ name: 'XML', extensions: ['xml'] }]
    });
    if (path) {
        await window.__TAURI__.core.invoke('save_raw_xml', { path });
        showToast('Saved to ' + path);
    }
}
```

- [ ] **Step 3: Commit**

```bash
git commit -m "feat: add save raw XML via native file dialog"
```

---

### Task 11: Polish and Cleanup

**Files:**
- Various UI polish
- Remove old TUI references from lib crate if desired

- [ ] **Step 1: Test all screens end-to-end**

- Home → PROD/TST → loads config
- REST flow → authenticate → validation result
- Viewer → paste XML → decode → validation
- Viewer → Open File → decode → validation
- Load IDP Cert → re-validate
- Copy to clipboard
- Save raw XML

- [ ] **Step 2: Remove old TUI binary (optional — keep for now since it's a branch)**

The old `main.rs` binary still references TUI code. Since this is on an isolated branch, we can keep it or remove it. Removing it allows cleaning up TUI-only deps from the lib crate's Cargo.toml.

- [ ] **Step 3: Run cargo clippy and fmt**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse/src-tauri && cargo clippy && cargo fmt`

- [ ] **Step 4: Final commit**

```bash
git commit -m "chore: polish and cleanup Tauri frontend"
```
