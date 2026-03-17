use crossterm::event::{self, Event, KeyCode, KeyModifiers};

use super::app::{App, SamlInputMode, Screen};
use crate::saml;

pub fn handle_input(app: &mut App) -> std::io::Result<bool> {
    if event::poll(std::time::Duration::from_millis(100))? {
        let ev = event::read()?;

        // Handle bracketed paste events (for SamlInput paste mode)
        if let Event::Paste(ref text) = ev {
            if app.screen == Screen::SamlInput && app.saml_input_mode == SamlInputMode::Paste {
                app.saml_paste_buffer.push_str(text);
            }
            return Ok(false);
        }

        // Handle IDP cert input mode (intercepts all key events)
        if app.idp_cert_input_active {
            if let Event::Key(key) = ev {
                match key.code {
                    KeyCode::Enter => {
                        let path = expand_tilde(&app.idp_cert_input);
                        match saml::trust::load_idp_certificates(std::path::Path::new(&path)) {
                            Ok(store) => {
                                let cn = saml::trust::cert_cn(&store.leaf_cert);
                                let chain_count = store.chain_certs.len();
                                app.status_message = format!(
                                    "Loaded IDP cert: CN={} (+ {} chain cert{})",
                                    cn,
                                    chain_count,
                                    if chain_count == 1 { "" } else { "s" }
                                );
                                app.idp_trust_store = Some(store);
                                // Re-run validation on current assertion
                                revalidate_current(app);
                            }
                            Err(e) => {
                                app.status_message = format!("Failed to load IDP cert: {}", e);
                            }
                        }
                        app.idp_cert_input_active = false;
                    }
                    KeyCode::Esc => {
                        app.idp_cert_input_active = false;
                        app.idp_cert_input.clear();
                    }
                    KeyCode::Backspace => {
                        app.idp_cert_input.pop();
                    }
                    KeyCode::Char(c) => {
                        app.idp_cert_input.push(c);
                    }
                    _ => {}
                }
            }
            return Ok(false);
        }

        if let Event::Key(key) = ev {
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                if app.screen == Screen::Result || app.screen == Screen::SamlView {
                    copy_to_clipboard(app);
                    return Ok(false);
                }
                app.running = false;
                return Ok(true);
            }
            match app.screen {
                Screen::EnvSelect => handle_env_select(app, key.code),
                Screen::FlowSelect => handle_flow_select(app, key.code),
                Screen::AuthInput => handle_auth_input(app, key.code),
                Screen::Waiting => handle_waiting(app, key.code),
                Screen::Result => handle_result(app, key.code),
                Screen::Error => handle_error(app, key.code),
                Screen::SamlInput => handle_saml_input(app, key.code),
                Screen::SamlView => handle_saml_view(app, key.code),
                Screen::CompareInput | Screen::CompareView => {}
            }
        }
    }
    Ok(false)
}

fn copy_to_clipboard(app: &mut App) {
    let xml = if app.screen == Screen::SamlView {
        &app.viewer_pretty_xml
    } else {
        &app.raw_xml
    };
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => match clipboard.set_text(xml) {
            Ok(_) => {
                let status = Some("Copied to clipboard!".to_string());
                if app.screen == Screen::SamlView {
                    app.viewer_copy_status = status;
                } else {
                    app.copy_status = status;
                }
            }
            Err(e) => {
                let status = Some(format!("Copy failed: {}", e));
                if app.screen == Screen::SamlView {
                    app.viewer_copy_status = status;
                } else {
                    app.copy_status = status;
                }
            }
        },
        Err(e) => {
            let status = Some(format!("Clipboard unavailable: {}", e));
            if app.screen == Screen::SamlView {
                app.viewer_copy_status = status;
            } else {
                app.copy_status = status;
            }
        }
    }
}

fn handle_env_select(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up => {
            if app.env_selection > 0 {
                app.env_selection -= 1;
            }
        }
        KeyCode::Down => {
            if app.env_selection < 2 {
                app.env_selection += 1;
            }
        }
        KeyCode::Enter => {
            if app.env_selection == 2 {
                app.screen = Screen::SamlInput;
            } else {
                app.environment = Some(app.get_selected_env());
                app.screen = Screen::FlowSelect;
            }
        }
        KeyCode::Char('q') => app.running = false,
        _ => {}
    }
}

fn handle_flow_select(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up => {
            if app.flow_selection > 0 {
                app.flow_selection -= 1;
            }
        }
        KeyCode::Down => {
            if app.flow_selection < 1 {
                app.flow_selection += 1;
            }
        }
        KeyCode::Tab => {
            app.signing_selection = if app.signing_selection == 0 { 1 } else { 0 };
        }
        KeyCode::Enter => {
            app.flow_mode = Some(app.get_selected_flow());
            app.signing_mode = app.get_selected_signing();
            app.screen = Screen::AuthInput;
        }
        KeyCode::Esc => app.screen = Screen::EnvSelect,
        KeyCode::Char('q') => app.running = false,
        _ => {}
    }
}

fn handle_auth_input(app: &mut App, key: KeyCode) {
    let is_browser = app.flow_mode == Some(super::app::FlowMode::Browser);
    let max_field = if is_browser { 0 } else { 2 };
    match key {
        KeyCode::Tab if !is_browser => {
            app.active_field = (app.active_field + 1) % (max_field + 1);
        }
        KeyCode::BackTab if !is_browser => {
            app.active_field = if app.active_field == 0 {
                max_field
            } else {
                app.active_field - 1
            };
        }
        KeyCode::Backspace => match app.active_field {
            0 => {
                app.username.pop();
            }
            1 if !is_browser => {
                app.password.pop();
            }
            2 if !is_browser => {
                app.otp_code.pop();
            }
            _ => {}
        },
        KeyCode::Char(c) => match app.active_field {
            0 => app.username.push(c),
            1 if !is_browser => app.password.push(c),
            2 if !is_browser => app.otp_code.push(c),
            _ => {}
        },
        KeyCode::Enter => {
            if !app.username.is_empty() {
                app.screen = Screen::Waiting;
                app.status_message = "Starting authentication...".to_string();
            }
        }
        KeyCode::Esc => {
            app.screen = Screen::FlowSelect;
            app.username.clear();
            app.password.clear();
            app.otp_code.clear();
            app.active_field = 0;
        }
        _ => {}
    }
}

fn handle_waiting(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc => {
            app.screen = Screen::AuthInput;
            app.status_message.clear();
        }
        KeyCode::Char('q') => app.running = false,
        _ => {}
    }
}

fn handle_result(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char('q') => app.running = false,
        KeyCode::Char('c') => copy_to_clipboard(app),
        KeyCode::Char('s') => save_raw_saml(app),
        KeyCode::Char('i') => open_idp_cert_dialog(app),
        KeyCode::Char('I') => {
            if !app.idp_cert_input_active {
                app.idp_cert_input_active = true;
                app.idp_cert_input.clear();
            }
        }
        KeyCode::Char('r') => {
            app.screen = Screen::AuthInput;
            app.password.clear();
            app.otp_code.clear();
            app.active_field = 0;
            app.assertion_details = None;
            app.signature_validation = None;
            app.raw_xml.clear();
            app.raw_xml_original.clear();
            app.scroll_offset = 0;
            app.copy_status = None;
        }
        KeyCode::Up => {
            if app.scroll_offset > 0 {
                app.scroll_offset -= 1;
            }
        }
        KeyCode::Down => {
            app.scroll_offset += 1;
        }
        KeyCode::Esc => {
            app.screen = Screen::FlowSelect;
            app.copy_status = None;
        }
        _ => {}
    }
}

fn handle_error(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char('q') => app.running = false,
        KeyCode::Char('r') => {
            let go_to_saml = app.flow_mode.is_none() && app.environment.is_none();
            if go_to_saml {
                app.screen = Screen::SamlInput;
            } else {
                app.screen = Screen::AuthInput;
                app.password.clear();
                app.otp_code.clear();
                app.active_field = 0;
            }
            app.error_message.clear();
        }
        KeyCode::Esc => {
            let go_to_saml = app.flow_mode.is_none() && app.environment.is_none();
            if go_to_saml {
                app.screen = Screen::SamlInput;
            } else {
                app.screen = Screen::FlowSelect;
            }
            app.error_message.clear();
        }
        _ => {}
    }
}

fn handle_saml_input(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Tab => {
            app.saml_input_mode = match app.saml_input_mode {
                SamlInputMode::Paste => SamlInputMode::File,
                SamlInputMode::File => SamlInputMode::Paste,
            };
        }
        KeyCode::F(3) => {
            // Browse for file using OS dialog
            browse_and_load_saml(app);
        }
        KeyCode::F(5) => {
            submit_saml_input(app);
        }
        KeyCode::Backspace => match app.saml_input_mode {
            SamlInputMode::Paste => {
                app.saml_paste_buffer.pop();
            }
            SamlInputMode::File => {
                app.saml_file_path.pop();
            }
        },
        KeyCode::Enter => match app.saml_input_mode {
            SamlInputMode::Paste => {
                app.saml_paste_buffer.push('\n');
            }
            SamlInputMode::File => {
                submit_saml_input(app);
            }
        },
        KeyCode::Char(c) => match app.saml_input_mode {
            SamlInputMode::Paste => app.saml_paste_buffer.push(c),
            SamlInputMode::File => app.saml_file_path.push(c),
        },
        KeyCode::Esc => {
            app.screen = Screen::EnvSelect;
            app.saml_paste_buffer.clear();
            app.saml_file_path.clear();
        }
        _ => {}
    }
}

fn submit_saml_input(app: &mut App) {
    let input = match app.saml_input_mode {
        SamlInputMode::Paste => app.saml_paste_buffer.clone(),
        SamlInputMode::File => {
            let path = expand_tilde(&app.saml_file_path);
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    if content.len() > 1_048_576 {
                        app.error_message = "File exceeds 1MB size limit".to_string();
                        app.screen = Screen::Error;
                        return;
                    }
                    content
                }
                Err(e) => {
                    app.error_message = format!("Failed to read file: {}", e);
                    app.screen = Screen::Error;
                    return;
                }
            }
        }
    };
    if input.trim().is_empty() {
        return;
    }
    if input.len() > 1_048_576 {
        app.error_message = "Input exceeds 1MB size limit".to_string();
        app.screen = Screen::Error;
        return;
    }
    // Store input in status_message temporarily for processing in main loop
    app.status_message = input;
    app.screen = Screen::Waiting;
}

/// Open an OS file dialog to browse for a SAML assertion file, then load and decode it.
fn browse_and_load_saml(app: &mut App) {
    let file = pick_open_xml_dialog();
    if let Some(path) = file {
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                if content.len() > 1_048_576 {
                    app.error_message = "File exceeds 1MB size limit".to_string();
                    app.screen = Screen::Error;
                    return;
                }
                app.status_message = content;
                app.screen = Screen::Waiting;
            }
            Err(e) => {
                app.error_message = format!("Failed to read file: {}", e);
                app.screen = Screen::Error;
            }
        }
    }
}

/// macOS: use osascript to open a file dialog for XML/SAML files.
#[cfg(target_os = "macos")]
fn pick_open_xml_dialog() -> Option<std::path::PathBuf> {
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
    let _ = disable_raw_mode();
    let result = std::process::Command::new("osascript")
        .args([
            "-e",
            r#"set theFile to choose file with prompt "Open SAML Assertion" of type {"xml", "txt", "public.xml"}"#,
            "-e",
            r#"POSIX path of theFile"#,
        ])
        .output();
    let _ = enable_raw_mode();
    match result {
        Ok(output) if output.status.success() => {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if path_str.is_empty() { None } else { Some(std::path::PathBuf::from(path_str)) }
        }
        _ => None,
    }
}

/// Non-macOS: use rfd for native file dialog.
#[cfg(not(target_os = "macos"))]
fn pick_open_xml_dialog() -> Option<std::path::PathBuf> {
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
    let _ = disable_raw_mode();
    let file = rfd::FileDialog::new()
        .set_title("Open SAML Assertion")
        .add_filter("XML", &["xml"])
        .add_filter("All Files", &["*"])
        .pick_file();
    let _ = enable_raw_mode();
    file
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with('~') {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return path.replacen('~', &home.to_string_lossy(), 1);
        }
    }
    path.to_string()
}

/// Re-run validation on the currently displayed assertion after IDP cert change.
/// Uses the original (pre-pretty-print) XML to preserve the exact bytes for digest verification.
fn revalidate_current(app: &mut App) {
    match app.screen {
        Screen::Result => {
            if !app.raw_xml_original.is_empty() {
                let report = saml::validator::validate_assertion(
                    &app.raw_xml_original,
                    app.idp_trust_store.as_ref(),
                );
                app.signature_validation = Some(report);
            }
        }
        Screen::SamlView => {
            if !app.viewer_pretty_xml.is_empty() {
                let report = saml::validator::validate_assertion(
                    &app.viewer_pretty_xml,
                    app.idp_trust_store.as_ref(),
                );
                app.viewer_signature = Some(report);
            }
        }
        _ => {}
    }
}

/// Save the raw SAML assertion XML to a file via OS save dialog.
/// Saves the original (pre-pretty-print) XML to preserve exact bytes for signature verification.
fn save_raw_saml(app: &mut App) {
    let xml = match app.screen {
        Screen::Result => &app.raw_xml_original,
        Screen::SamlView => &app.viewer_pretty_xml, // viewer doesn't have a separate original
        _ => return,
    };

    if xml.is_empty() {
        app.status_message = "No SAML data to save".to_string();
        return;
    }

    let path = pick_save_dialog();

    if let Some(path) = path {
        match std::fs::write(&path, xml) {
            Ok(_) => {
                app.status_message = format!("Saved raw SAML to {}", path.display());
            }
            Err(e) => {
                app.status_message = format!("Failed to save: {}", e);
            }
        }
    }
}

/// macOS: use osascript to open a save dialog in a separate process.
#[cfg(target_os = "macos")]
fn pick_save_dialog() -> Option<std::path::PathBuf> {
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

    let _ = disable_raw_mode();

    let result = std::process::Command::new("osascript")
        .args([
            "-e",
            r#"set savePath to choose file name with prompt "Save Raw SAML Assertion" default name "assertion.xml""#,
            "-e",
            r#"POSIX path of savePath"#,
        ])
        .output();

    let _ = enable_raw_mode();

    match result {
        Ok(output) if output.status.success() => {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if path_str.is_empty() {
                None
            } else {
                Some(std::path::PathBuf::from(path_str))
            }
        }
        _ => None,
    }
}

/// Non-macOS: use rfd for native save dialog.
#[cfg(not(target_os = "macos"))]
fn pick_save_dialog() -> Option<std::path::PathBuf> {
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

    let _ = disable_raw_mode();

    let file = rfd::FileDialog::new()
        .set_title("Save Raw SAML Assertion")
        .set_file_name("assertion.xml")
        .add_filter("XML", &["xml"])
        .add_filter("All Files", &["*"])
        .save_file();

    let _ = enable_raw_mode();

    file
}

/// Open a native file dialog to browse for an IDP certificate PEM file.
///
/// On macOS, uses `osascript` to run the file dialog in a separate process.
/// This avoids the NSApplication event loop issue that causes terminal apps
/// to hang with a spinning ball after the dialog closes.
///
/// On other platforms, uses `rfd` (Rusty File Dialogs) directly.
fn open_idp_cert_dialog(app: &mut App) {
    let file = pick_file_dialog();

    if let Some(path) = file {
        match saml::trust::load_idp_certificates(&path) {
            Ok(store) => {
                let cn = saml::trust::cert_cn(&store.leaf_cert);
                let chain_count = store.chain_certs.len();
                app.status_message = format!(
                    "Loaded IDP cert: CN={} (+ {} chain cert{})",
                    cn,
                    chain_count,
                    if chain_count == 1 { "" } else { "s" }
                );
                app.idp_trust_store = Some(store);
                revalidate_current(app);
            }
            Err(e) => {
                app.status_message = format!("Failed to load IDP cert: {}", e);
            }
        }
    }
}

/// macOS: use osascript to open a file dialog in a separate process.
/// This avoids the spinning ball caused by NSApplication event loop issues
/// in terminal apps.
#[cfg(target_os = "macos")]
fn pick_file_dialog() -> Option<std::path::PathBuf> {
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

    let _ = disable_raw_mode();

    let result = std::process::Command::new("osascript")
        .args([
            "-e",
            r#"set theFile to choose file with prompt "Select IDP Certificate (PEM)" of type {"pem", "crt", "cer", "public.x509-certificate"}"#,
            "-e",
            r#"POSIX path of theFile"#,
        ])
        .output();

    let _ = enable_raw_mode();

    match result {
        Ok(output) if output.status.success() => {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if path_str.is_empty() {
                None
            } else {
                Some(std::path::PathBuf::from(path_str))
            }
        }
        _ => None, // User cancelled or osascript failed
    }
}

/// Non-macOS: use rfd for native file dialog.
#[cfg(not(target_os = "macos"))]
fn pick_file_dialog() -> Option<std::path::PathBuf> {
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

    let _ = disable_raw_mode();

    let file = rfd::FileDialog::new()
        .set_title("Select IDP Certificate (PEM)")
        .add_filter("PEM Certificate", &["pem", "crt", "cer"])
        .add_filter("All Files", &["*"])
        .pick_file();

    let _ = enable_raw_mode();

    file
}

fn handle_saml_view(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char('q') => app.running = false,
        KeyCode::Char('c') => copy_to_clipboard(app),
        KeyCode::Char('s') => save_raw_saml(app),
        KeyCode::Char('i') => open_idp_cert_dialog(app),
        KeyCode::Char('I') => {
            if !app.idp_cert_input_active {
                app.idp_cert_input_active = true;
                app.idp_cert_input.clear();
            }
        }
        KeyCode::Char('r') => {
            app.screen = Screen::SamlInput;
            app.saml_paste_buffer.clear();
            app.saml_file_path.clear();
            app.decoded_saml = None;
            app.viewer_authn_request = None;
            app.viewer_response = None;
            app.viewer_assertion = None;
            app.viewer_attributes.clear();
            app.viewer_signature = None;
            app.viewer_pretty_xml.clear();
            app.viewer_scroll_offset = 0;
            app.viewer_copy_status = None;
        }
        KeyCode::Up => {
            if app.viewer_scroll_offset > 0 {
                app.viewer_scroll_offset -= 1;
            }
        }
        KeyCode::Down => {
            app.viewer_scroll_offset += 1;
        }
        KeyCode::Esc => {
            app.screen = Screen::EnvSelect;
            app.viewer_copy_status = None;
        }
        _ => {}
    }
}
