use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::saml::diff::{filter_byte_diff, filter_diff_lines, ByteDiffRow, DiffResult};
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

pub fn render_compare_view(frame: &mut Frame, app: &App) {
    let area = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // mode bar
            Constraint::Min(5),    // content
            Constraint::Length(1), // status bar
        ])
        .split(area);

    render_mode_bar(frame, app, chunks[0]);

    match app.compare_mode {
        CompareMode::Xml => render_xml_diff(frame, app, chunks[1]),
        CompareMode::Hex => render_hex_diff(frame, app, chunks[1]),
        CompareMode::C14n => render_c14n_diff(frame, app, chunks[1]),
        CompareMode::Validation => render_validation_diff(frame, app, chunks[1]),
    }

    // Diff count
    let diff_count = match app.compare_mode {
        CompareMode::Xml => app
            .compare_diff_result
            .as_ref()
            .map(|d| d.diff_count)
            .unwrap_or(0),
        CompareMode::C14n => app
            .compare_c14n_diff
            .as_ref()
            .map(|d| d.diff_count)
            .unwrap_or(0),
        CompareMode::Hex => app
            .compare_byte_diff
            .as_ref()
            .map(|rows| rows.iter().filter(|r| !r.diffs.is_empty()).count())
            .unwrap_or(0),
        CompareMode::Validation => 0,
    };

    let filter_label = if app.compare_diff_only {
        "diff-only"
    } else {
        "all"
    };
    let status = format!(
        "Diffs: {}  Filter: {}  | 1-4: Mode | d: Toggle Filter | Up/Down: Scroll | Left/Right: H-Scroll | Esc: Back",
        diff_count, filter_label
    );
    let status_bar = Paragraph::new(status).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(status_bar, chunks[2]);
}

fn render_mode_bar(frame: &mut Frame, app: &App, area: Rect) {
    let modes: &[(&str, CompareMode)] = &[
        ("1:XML", CompareMode::Xml),
        ("2:Hex", CompareMode::Hex),
        ("3:C14N", CompareMode::C14n),
        ("4:Valid", CompareMode::Validation),
    ];

    let spans: Vec<Span> = modes
        .iter()
        .enumerate()
        .flat_map(|(i, (label, mode))| {
            let style = if *mode == app.compare_mode {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
                    .add_modifier(Modifier::UNDERLINED)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            let mut spans = vec![Span::styled(label.to_string(), style)];
            if i < modes.len() - 1 {
                spans.push(Span::styled("  ", Style::default()));
            }
            spans
        })
        .collect();

    let bar = Paragraph::new(Line::from(spans));
    frame.render_widget(bar, area);
}

fn render_xml_diff(frame: &mut Frame, app: &App, area: Rect) {
    if let Some(diff) = &app.compare_diff_result {
        render_line_diff(frame, app, area, diff, "Assertion A (XML)", "Assertion B (XML)");
    } else {
        let block = Block::default()
            .title(" XML Diff (no data) ")
            .borders(Borders::ALL);
        frame.render_widget(block, area);
    }
}

fn render_c14n_diff(frame: &mut Frame, app: &App, area: Rect) {
    // Will be implemented in Task 8
    if let Some(diff) = &app.compare_c14n_diff {
        render_line_diff(frame, app, area, diff, "Assertion A (c14n)", "Assertion B (c14n)");
    } else {
        let block = Block::default()
            .title(" C14N Diff (not computed) ")
            .borders(Borders::ALL);
        frame.render_widget(block, area);
    }
}

fn render_validation_diff(frame: &mut Frame, _app: &App, area: Rect) {
    let block = Block::default()
        .title(" Validation (TODO) ")
        .borders(Borders::ALL);
    frame.render_widget(block, area);
}

/// Shared line-diff renderer used for XML (Mode 1) and C14N (Mode 3).
fn render_line_diff(
    frame: &mut Frame,
    app: &App,
    area: Rect,
    diff: &DiffResult,
    left_title: &str,
    right_title: &str,
) {
    let pane_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let left_block = Block::default()
        .title(format!(" {} ", left_title))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let right_block = Block::default()
        .title(format!(" {} ", right_title))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let left_inner = left_block.inner(pane_chunks[0]);
    let right_inner = right_block.inner(pane_chunks[1]);

    frame.render_widget(left_block, pane_chunks[0]);
    frame.render_widget(right_block, pane_chunks[1]);

    let mut left_lines: Vec<Line<'static>> = Vec::new();
    let mut right_lines: Vec<Line<'static>> = Vec::new();

    let mut left_num: usize = 0;
    let mut right_num: usize = 0;

    // Collect the lines to render, respecting diff-only filter
    let indexed: Vec<(usize, &crate::saml::diff::DiffLine)> = if app.compare_diff_only {
        filter_diff_lines(diff, 2)
    } else {
        diff.lines.iter().enumerate().collect()
    };

    for (_idx, line) in indexed {
        use crate::saml::diff::DiffLine;
        match line {
            DiffLine::Same(text) => {
                left_num += 1;
                right_num += 1;
                let num_left = left_num;
                let num_right = right_num;
                let t = text.clone();
                left_lines.push(Line::from(vec![
                    Span::styled(
                        format!("{:4} ", num_left),
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::DIM),
                    ),
                    Span::styled(
                        t.clone(),
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::DIM),
                    ),
                ]));
                right_lines.push(Line::from(vec![
                    Span::styled(
                        format!("{:4} ", num_right),
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::DIM),
                    ),
                    Span::styled(
                        t,
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::DIM),
                    ),
                ]));
            }
            DiffLine::Removed(text) => {
                left_num += 1;
                let num = left_num;
                left_lines.push(Line::from(vec![
                    Span::styled(
                        format!("{:4} ", num),
                        Style::default().fg(Color::Red),
                    ),
                    Span::styled(text.clone(), Style::default().fg(Color::Red)),
                ]));
                right_lines.push(Line::from(Span::raw("")));
            }
            DiffLine::Added(text) => {
                right_num += 1;
                let num = right_num;
                left_lines.push(Line::from(Span::raw("")));
                right_lines.push(Line::from(vec![
                    Span::styled(
                        format!("{:4} ", num),
                        Style::default().fg(Color::Green),
                    ),
                    Span::styled(text.clone(), Style::default().fg(Color::Green)),
                ]));
            }
            DiffLine::Changed {
                left,
                right,
                left_spans,
                right_spans,
            } => {
                left_num += 1;
                right_num += 1;
                left_lines.push(build_highlighted_line(
                    left_num,
                    left.clone(),
                    left_spans.clone(),
                    Color::Red,
                ));
                right_lines.push(build_highlighted_line(
                    right_num,
                    right.clone(),
                    right_spans.clone(),
                    Color::Yellow,
                ));
            }
        }
    }

    let left_para = Paragraph::new(left_lines)
        .scroll((app.compare_scroll_offset, app.compare_h_scroll_offset));
    let right_para = Paragraph::new(right_lines)
        .scroll((app.compare_scroll_offset, app.compare_h_scroll_offset));

    frame.render_widget(left_para, left_inner);
    frame.render_widget(right_para, right_inner);
}

/// Build a ratatui Line with character-level diff highlights.
/// `spans` is a list of `(start, end)` character-index ranges that differ.
/// Characters in those ranges get `highlight_color` background, others are plain white.
fn build_highlighted_line(
    line_num: usize,
    text: String,
    spans: Vec<(usize, usize)>,
    highlight_color: Color,
) -> Line<'static> {
    let chars: Vec<char> = text.chars().collect();
    let mut result: Vec<Span<'static>> = Vec::new();

    // Line number prefix
    result.push(Span::styled(
        format!("{:4} ", line_num),
        Style::default().fg(highlight_color),
    ));

    if spans.is_empty() {
        // No highlights — just render the whole text in the highlight color
        result.push(Span::styled(
            text,
            Style::default().fg(highlight_color),
        ));
        return Line::from(result);
    }

    let mut cursor = 0usize;
    for (start, end) in &spans {
        let start = *start;
        let end = (*end).min(chars.len());

        // Normal text before span
        if cursor < start {
            let segment: String = chars[cursor..start].iter().collect();
            result.push(Span::styled(segment, Style::default().fg(Color::White)));
        }

        // Highlighted span
        if start < end {
            let segment: String = chars[start..end].iter().collect();
            result.push(Span::styled(
                segment,
                Style::default()
                    .fg(Color::Black)
                    .bg(highlight_color),
            ));
        }

        cursor = end;
    }

    // Remaining text after last span
    if cursor < chars.len() {
        let segment: String = chars[cursor..].iter().collect();
        result.push(Span::styled(segment, Style::default().fg(Color::White)));
    }

    Line::from(result)
}

fn render_hex_diff(frame: &mut Frame, app: &App, area: Rect) {
    let pane_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let left_block = Block::default()
        .title(" Assertion A (Hex) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let right_block = Block::default()
        .title(" Assertion B (Hex) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let left_inner = left_block.inner(pane_chunks[0]);
    let right_inner = right_block.inner(pane_chunks[1]);

    frame.render_widget(left_block, pane_chunks[0]);
    frame.render_widget(right_block, pane_chunks[1]);

    let byte_diff = match &app.compare_byte_diff {
        Some(d) => d,
        None => {
            return;
        }
    };

    let indexed: Vec<(usize, &ByteDiffRow)> = if app.compare_diff_only {
        filter_byte_diff(byte_diff)
    } else {
        byte_diff.iter().enumerate().collect()
    };

    let mut left_lines: Vec<Line<'static>> = Vec::new();
    let mut right_lines: Vec<Line<'static>> = Vec::new();

    for (_row_idx, row) in &indexed {
        left_lines.push(build_hex_line(row.offset, &row.left_bytes, &row.diffs));
        right_lines.push(build_hex_line(row.offset, &row.right_bytes, &row.diffs));
    }

    let left_para = Paragraph::new(left_lines)
        .scroll((app.compare_scroll_offset, app.compare_h_scroll_offset));
    let right_para = Paragraph::new(right_lines)
        .scroll((app.compare_scroll_offset, app.compare_h_scroll_offset));

    frame.render_widget(left_para, left_inner);
    frame.render_widget(right_para, right_inner);
}

/// Build one hex-dump line for 16 bytes starting at `offset`.
/// `diffs` is the set of byte positions (0-15) within this row that differ.
fn build_hex_line(offset: usize, bytes: &[u8], diffs: &[usize]) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();

    // Offset column
    spans.push(Span::styled(
        format!("{:08x}  ", offset),
        Style::default().fg(Color::DarkGray),
    ));

    // Hex bytes (16 per row, space after byte 8)
    for i in 0..16usize {
        if i == 8 {
            spans.push(Span::raw(" "));
        }
        let is_diff = diffs.contains(&i);
        if let Some(&b) = bytes.get(i) {
            let text = format!("{:02x} ", b);
            if is_diff {
                spans.push(Span::styled(
                    text,
                    Style::default().fg(Color::Black).bg(Color::Yellow),
                ));
            } else {
                spans.push(Span::styled(text, Style::default().fg(Color::White)));
            }
        } else {
            spans.push(Span::raw("   "));
        }
    }

    // ASCII column
    spans.push(Span::styled("|", Style::default().fg(Color::DarkGray)));
    for i in 0..16usize {
        let is_diff = diffs.contains(&i);
        if let Some(&b) = bytes.get(i) {
            let ch = if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            };
            let text = ch.to_string();
            if is_diff {
                spans.push(Span::styled(
                    text,
                    Style::default().fg(Color::Black).bg(Color::Yellow),
                ));
            } else {
                spans.push(Span::styled(text, Style::default().fg(Color::White)));
            }
        } else {
            spans.push(Span::raw(" "));
        }
    }
    spans.push(Span::styled("|", Style::default().fg(Color::DarkGray)));

    Line::from(spans)
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

pub fn handle_compare_view(app: &mut App, key_code: KeyCode) {
    match key_code {
        KeyCode::Char('q') => {
            app.running = false;
        }
        KeyCode::Esc => {
            app.screen = Screen::CompareInput;
            app.compare_scroll_offset = 0;
            app.compare_h_scroll_offset = 0;
        }
        KeyCode::Char('1') => {
            app.compare_mode = CompareMode::Xml;
            app.compare_scroll_offset = 0;
            app.compare_h_scroll_offset = 0;
        }
        KeyCode::Char('2') => {
            app.compare_mode = CompareMode::Hex;
            app.compare_scroll_offset = 0;
            app.compare_h_scroll_offset = 0;
        }
        KeyCode::Char('3') => {
            app.compare_mode = CompareMode::C14n;
            app.compare_scroll_offset = 0;
            app.compare_h_scroll_offset = 0;
        }
        KeyCode::Char('4') => {
            app.compare_mode = CompareMode::Validation;
            app.compare_scroll_offset = 0;
            app.compare_h_scroll_offset = 0;
        }
        KeyCode::Char('d') => {
            app.compare_diff_only = !app.compare_diff_only;
            app.compare_scroll_offset = 0;
        }
        KeyCode::Up => {
            app.compare_scroll_offset = app.compare_scroll_offset.saturating_sub(1);
        }
        KeyCode::Down => {
            app.compare_scroll_offset = app.compare_scroll_offset.saturating_add(1);
        }
        KeyCode::Left => {
            app.compare_h_scroll_offset = app.compare_h_scroll_offset.saturating_sub(4);
        }
        KeyCode::Right => {
            app.compare_h_scroll_offset = app.compare_h_scroll_offset.saturating_add(4);
        }
        KeyCode::PageUp => {
            app.compare_scroll_offset = app.compare_scroll_offset.saturating_sub(20);
        }
        KeyCode::PageDown => {
            app.compare_scroll_offset = app.compare_scroll_offset.saturating_add(20);
        }
        KeyCode::Home => {
            app.compare_scroll_offset = 0;
            app.compare_h_scroll_offset = 0;
        }
        _ => {}
    }
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
