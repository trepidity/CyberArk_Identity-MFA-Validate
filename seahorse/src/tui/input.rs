use crossterm::event::{self, Event, KeyCode, KeyModifiers};

use super::app::{App, Screen};

pub fn handle_input(app: &mut App) -> std::io::Result<bool> {
    if event::poll(std::time::Duration::from_millis(100))? {
        if let Event::Key(key) = event::read()? {
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                // On the Result screen, Ctrl+C copies SAML to clipboard
                if app.screen == Screen::Result {
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
            }
        }
    }
    Ok(false)
}

fn copy_to_clipboard(app: &mut App) {
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => match clipboard.set_text(&app.raw_xml) {
            Ok(_) => {
                app.copy_status = Some("Copied to clipboard!".to_string());
            }
            Err(e) => {
                app.copy_status = Some(format!("Copy failed: {}", e));
            }
        },
        Err(e) => {
            app.copy_status = Some(format!("Clipboard unavailable: {}", e));
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
            if app.env_selection < 1 {
                app.env_selection += 1;
            }
        }
        KeyCode::Enter => {
            app.environment = Some(app.get_selected_env());
            app.screen = Screen::FlowSelect;
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
        KeyCode::Char('r') => {
            app.screen = Screen::AuthInput;
            app.password.clear();
            app.otp_code.clear();
            app.active_field = 0;
            app.assertion_details = None;
            app.signature_validation = None;
            app.raw_xml.clear();
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
            app.screen = Screen::AuthInput;
            app.password.clear();
            app.otp_code.clear();
            app.active_field = 0;
            app.error_message.clear();
        }
        KeyCode::Esc => {
            app.screen = Screen::FlowSelect;
            app.error_message.clear();
        }
        _ => {}
    }
}
