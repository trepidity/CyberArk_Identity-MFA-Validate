use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::app::{App, CompareMode, SamlInputMode, Screen};

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub fn render_compare_input(frame: &mut Frame, app: &App) {
    let area = frame.area();

    let outer_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(1)])
        .split(area);

    let pane_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(outer_chunks[0]);

    for (idx, pane_area) in pane_chunks.iter().enumerate() {
        let pane = &app.compare_panes[idx];
        let is_active = idx == app.compare_active_pane;

        let border_style = if is_active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let title = format!(" Pane {} ", idx + 1);
        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style);

        // Mode indicator
        let mode_label = match pane.input_mode {
            SamlInputMode::Paste => "[Paste Mode]",
            SamlInputMode::File => "[File Mode]",
        };

        // Content preview
        let content_line = match pane.input_mode {
            SamlInputMode::Paste => {
                if pane.paste_buffer.is_empty() {
                    "  (paste SAML data here)".to_string()
                } else {
                    let chars = pane.paste_buffer.len();
                    let lines = pane.paste_buffer.lines().count().max(1);
                    format!("  {} chars, {} lines", chars, lines)
                }
            }
            SamlInputMode::File => {
                if pane.file_path.is_empty() {
                    "  (type or browse for file path)".to_string()
                } else {
                    format!("  {}", pane.file_path)
                }
            }
        };

        // Decode status
        let decode_line = match &pane.decode_status {
            Some(s) => format!("  Status: {}", s),
            None => "  (not decoded)".to_string(),
        };

        let mode_color = if is_active {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let content_color = if pane.decoded_xml.is_some() {
            Color::Green
        } else {
            Color::White
        };

        let decode_color = match &pane.decode_status {
            Some(s) if s.starts_with("Error") || s.starts_with("error") => Color::Red,
            Some(_) => Color::Green,
            None => Color::DarkGray,
        };

        let text = vec![
            Line::from(Span::styled(mode_label, Style::default().fg(mode_color))),
            Line::from(Span::styled(content_line, Style::default().fg(content_color))),
            Line::from(Span::styled(decode_line, Style::default().fg(decode_color))),
        ];

        let inner = block.inner(*pane_area);
        frame.render_widget(block, *pane_area);
        let paragraph = Paragraph::new(text);
        frame.render_widget(paragraph, inner);
    }

    // Status bar
    let both_decoded = app.compare_panes[0].decoded_xml.is_some()
        && app.compare_panes[1].decoded_xml.is_some();

    let hint = if both_decoded {
        "Tab: Switch Pane | m: Mode | F3: Browse | Enter: Decode | F5: Compare | Esc: Back | q: Quit"
    } else {
        "Tab: Switch Pane | m: Mode | F3: Browse | Enter: Decode | Esc: Back | q: Quit"
    };

    let status_bar = Paragraph::new(hint).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(status_bar, outer_chunks[1]);
}

pub fn render_compare_view(frame: &mut Frame, _app: &App) {
    let area = frame.area();
    let block = Block::default()
        .title(" Compare View (TODO) ")
        .borders(Borders::ALL);
    frame.render_widget(block, area);
}

// ---------------------------------------------------------------------------
// Input handling
// ---------------------------------------------------------------------------

pub fn handle_compare_input(app: &mut App, key_code: KeyCode) {
    match key_code {
        KeyCode::Tab => {
            app.compare_active_pane = 1 - app.compare_active_pane;
        }
        KeyCode::Char('m') => {
            let pane = &mut app.compare_panes[app.compare_active_pane];
            pane.input_mode = match pane.input_mode {
                SamlInputMode::Paste => SamlInputMode::File,
                SamlInputMode::File => SamlInputMode::Paste,
            };
        }
        KeyCode::Char('q') => {
            app.running = false;
        }
        KeyCode::Esc => {
            app.screen = Screen::EnvSelect;
            app.compare_panes[0] = super::app::ComparePane::default();
            app.compare_panes[1] = super::app::ComparePane::default();
            app.compare_active_pane = 0;
            app.compare_diff_result = None;
            app.compare_byte_diff = None;
            app.compare_c14n_diff = None;
            app.compare_validation = None;
        }
        KeyCode::F(3) => {
            if let Some(path) = crate::tui::input::pick_open_xml_dialog() {
                let pane = &mut app.compare_panes[app.compare_active_pane];
                pane.file_path = path.to_string_lossy().to_string();
                pane.input_mode = SamlInputMode::File;
            }
        }
        KeyCode::Enter => {
            decode_active_pane(app);
        }
        KeyCode::F(5) => {
            let both_decoded = app.compare_panes[0].decoded_xml.is_some()
                && app.compare_panes[1].decoded_xml.is_some();
            if both_decoded {
                compute_comparison(app);
                app.screen = Screen::CompareView;
            }
        }
        KeyCode::Backspace => {
            let pane = &mut app.compare_panes[app.compare_active_pane];
            match pane.input_mode {
                SamlInputMode::Paste => {
                    pane.paste_buffer.pop();
                }
                SamlInputMode::File => {
                    pane.file_path.pop();
                }
            }
        }
        KeyCode::Char(c) => {
            let pane = &mut app.compare_panes[app.compare_active_pane];
            match pane.input_mode {
                SamlInputMode::Paste => {
                    pane.paste_buffer.push(c);
                }
                SamlInputMode::File => {
                    pane.file_path.push(c);
                }
            }
        }
        _ => {}
    }
}

pub fn handle_compare_view(app: &mut App, _key_code: KeyCode) {
    let _ = app;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn decode_active_pane(app: &mut App) {
    let idx = app.compare_active_pane;
    let pane = &app.compare_panes[idx];

    let input = match pane.input_mode {
        SamlInputMode::Paste => pane.paste_buffer.clone(),
        SamlInputMode::File => {
            let expanded = crate::tui::input::expand_tilde(&pane.file_path);
            match std::fs::read_to_string(&expanded) {
                Ok(content) => content,
                Err(e) => {
                    app.compare_panes[idx].decode_status =
                        Some(format!("Error reading file: {}", e));
                    return;
                }
            }
        }
    };

    if input.trim().is_empty() {
        app.compare_panes[idx].decode_status = Some("Error: input is empty".to_string());
        return;
    }

    match crate::saml::decoder::decode_saml_input(&input) {
        Ok(result) => {
            let raw_bytes = result.xml.as_bytes().to_vec();
            app.compare_panes[idx].decode_status = Some("Decoded OK".to_string());
            app.compare_panes[idx].decoded_xml = Some(result.xml);
            app.compare_panes[idx].raw_bytes = Some(raw_bytes);
        }
        Err(e) => {
            app.compare_panes[idx].decode_status = Some(format!("Error: {}", e));
            app.compare_panes[idx].decoded_xml = None;
            app.compare_panes[idx].raw_bytes = None;
        }
    }
}

pub fn compute_comparison(app: &mut App) {
    // Reset scroll/mode state
    app.compare_scroll_offset = 0;
    app.compare_h_scroll_offset = 0;
    app.compare_mode = CompareMode::Xml;
    app.compare_diff_only = false;

    let left_xml = app.compare_panes[0].decoded_xml.clone().unwrap_or_default();
    let right_xml = app.compare_panes[1].decoded_xml.clone().unwrap_or_default();

    // Mode 1: XML pretty-print diff
    let left_pretty = crate::saml::parser::pretty_print_xml(&left_xml);
    let right_pretty = crate::saml::parser::pretty_print_xml(&right_xml);
    app.compare_diff_result = Some(crate::saml::diff::diff_lines(&left_pretty, &right_pretty));

    // Mode 2: byte diff on raw bytes
    let left_bytes = app.compare_panes[0]
        .raw_bytes
        .clone()
        .unwrap_or_default();
    let right_bytes = app.compare_panes[1]
        .raw_bytes
        .clone()
        .unwrap_or_default();
    app.compare_byte_diff = Some(crate::saml::diff::diff_bytes(&left_bytes, &right_bytes));

    // Mode 4: validate both assertions
    let left_report =
        crate::saml::validator::validate_assertion(&left_xml, app.idp_trust_store.as_ref());
    let right_report =
        crate::saml::validator::validate_assertion(&right_xml, app.idp_trust_store.as_ref());
    app.compare_validation = Some((left_report, right_report));

    // Mode 3 (C14N diff) - leave as None for now; CompareView will handle
    app.compare_c14n_diff = None;
}
