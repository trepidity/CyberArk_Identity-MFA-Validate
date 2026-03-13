use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use super::app::{App, SamlDocType, SamlInputMode, Screen, SigningMode};

pub fn render(frame: &mut Frame, app: &App) {
    match app.screen {
        Screen::EnvSelect => render_env_select(frame, app),
        Screen::FlowSelect => render_flow_select(frame, app),
        Screen::AuthInput => render_auth_input(frame, app),
        Screen::Waiting => render_waiting(frame, app),
        Screen::Result => render_result(frame, app),
        Screen::Error => render_error(frame, app),
        Screen::SamlInput => render_saml_input(frame, app),
        Screen::SamlView => render_saml_view(frame, app),
    }
}

fn render_env_select(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let title = Paragraph::new("Seahorse - SAML Validation Tool")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let menu_items = ["PROD", "TST", "View SAML Assertion"];
    let items: Vec<ListItem> = menu_items
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let style = if i == app.env_selection {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let prefix = if i == app.env_selection { "> " } else { "  " };
            ListItem::new(format!("{}{}", prefix, label)).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title("Seahorse - Main Menu")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, chunks[1]);

    let help = Paragraph::new("Up/Down: Navigate | Enter: Select | q: Quit")
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}

fn render_flow_select(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let env_name = app.environment.map(|e| e.to_string()).unwrap_or_default();
    let title = Paragraph::new(format!("Seahorse - Environment: {}", env_name))
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let flows = ["Browser Flow", "REST API Flow"];
    let items: Vec<ListItem> = flows
        .iter()
        .enumerate()
        .map(|(i, flow)| {
            let style = if i == app.flow_selection {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let prefix = if i == app.flow_selection { "> " } else { "  " };
            ListItem::new(format!("{}{}", prefix, flow)).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title("Seahorse - Select Auth Flow")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, chunks[1]);

    let signing_label = match app.get_selected_signing() {
        SigningMode::Signed => "Signed",
        SigningMode::Unsigned => "Unsigned",
    };
    let signing = Paragraph::new(format!("Assertion Mode: [{}]", signing_label))
        .style(Style::default().fg(Color::Green))
        .block(Block::default().borders(Borders::ALL).title("Signing"));
    frame.render_widget(signing, chunks[2]);

    let help =
        Paragraph::new("Up/Down: Flow | Tab: Toggle Signing | Enter: Select | Esc: Back | q: Quit")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[3]);
}

fn render_auth_input(frame: &mut Frame, app: &App) {
    let is_browser = app.flow_mode == Some(super::app::FlowMode::Browser);

    let constraints = if is_browser {
        vec![
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(3),
        ]
    } else {
        vec![
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(3),
        ]
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(frame.area());

    let flow_name = app.flow_mode.map(|f| f.to_string()).unwrap_or_default();
    let title = Paragraph::new(format!("Seahorse - {} Authentication", flow_name))
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let username_style = if app.active_field == 0 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    let username = Paragraph::new(app.username.as_str())
        .style(username_style)
        .block(
            Block::default()
                .title("Username")
                .borders(Borders::ALL)
                .border_style(if app.active_field == 0 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                }),
        );
    frame.render_widget(username, chunks[1]);

    if is_browser {
        let help = Paragraph::new("Enter: Submit | Esc: Back")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(help, chunks[3]);
    } else {
        // Password field (masked)
        let pw_style = if app.active_field == 1 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };
        let masked: String = "*".repeat(app.password.len());
        let password = Paragraph::new(masked).style(pw_style).block(
            Block::default()
                .title("Password")
                .borders(Borders::ALL)
                .border_style(if app.active_field == 1 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                }),
        );
        frame.render_widget(password, chunks[2]);

        // OTP field
        let otp_style = if app.active_field == 2 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };
        let otp = Paragraph::new(app.otp_code.as_str())
            .style(otp_style)
            .block(
                Block::default()
                    .title("OTP Code")
                    .borders(Borders::ALL)
                    .border_style(if app.active_field == 2 {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default()
                    }),
            );
        frame.render_widget(otp, chunks[3]);

        let help = Paragraph::new("Tab: Switch Field | Enter: Submit | Esc: Back")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(help, chunks[5]);
    }
}

fn render_waiting(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let title = Paragraph::new("Seahorse - Authenticating")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let status = Paragraph::new(app.status_message.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().title("Status").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(status, chunks[1]);

    let help = Paragraph::new("Esc: Cancel | q: Quit")
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}

fn render_result(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(10),
            Constraint::Length(7),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let title = Paragraph::new("Seahorse - SAML Assertion Result")
        .style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    // Assertion details
    let details_text = if let Some(ref details) = app.assertion_details {
        vec![
            Line::from(vec![
                Span::styled("Issuer:    ", Style::default().fg(Color::Cyan)),
                Span::raw(&details.issuer),
            ]),
            Line::from(vec![
                Span::styled("Subject:   ", Style::default().fg(Color::Cyan)),
                Span::raw(&details.subject),
            ]),
            Line::from(vec![
                Span::styled("Audience:  ", Style::default().fg(Color::Cyan)),
                Span::raw(&details.audience),
            ]),
            Line::from(vec![
                Span::styled("ID:        ", Style::default().fg(Color::Cyan)),
                Span::raw(&details.assertion_id),
            ]),
            Line::from(vec![
                Span::styled("Issued:    ", Style::default().fg(Color::Cyan)),
                Span::raw(&details.issue_instant),
            ]),
            Line::from(vec![
                Span::styled("NotBefore: ", Style::default().fg(Color::Cyan)),
                Span::raw(details.not_before.as_deref().unwrap_or("N/A")),
            ]),
            Line::from(vec![
                Span::styled("NotAfter:  ", Style::default().fg(Color::Cyan)),
                Span::raw(details.not_after.as_deref().unwrap_or("N/A")),
            ]),
            Line::from(vec![
                Span::styled("Signed:    ", Style::default().fg(Color::Cyan)),
                Span::raw(if details.has_signature { "Yes" } else { "No" }),
            ]),
        ]
    } else {
        vec![Line::from("No assertion details available")]
    };

    let details = Paragraph::new(details_text)
        .block(
            Block::default()
                .title("Assertion Details")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(details, chunks[1]);

    // Signature info
    let sig_text = if let Some(ref sig) = app.signature_validation {
        let valid_color = if sig.signature_valid {
            Color::Green
        } else {
            Color::Red
        };
        vec![
            Line::from(vec![
                Span::styled("Present:     ", Style::default().fg(Color::Cyan)),
                Span::raw(if sig.signature_present { "Yes" } else { "No" }),
            ]),
            Line::from(vec![
                Span::styled("Valid:       ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    if sig.signature_valid { "Yes" } else { "No" },
                    Style::default().fg(valid_color),
                ),
            ]),
            Line::from(vec![
                Span::styled("Algorithm:   ", Style::default().fg(Color::Cyan)),
                Span::raw(&sig.algorithm),
            ]),
            Line::from(vec![
                Span::styled("Certificate: ", Style::default().fg(Color::Cyan)),
                Span::raw(&sig.certificate_subject),
            ]),
            Line::from(vec![
                Span::styled("Cert Expiry: ", Style::default().fg(Color::Cyan)),
                Span::raw(sig.certificate_not_after.as_deref().unwrap_or("N/A")),
            ]),
        ]
    } else {
        vec![Line::from("No signature validation performed")]
    };

    let sig_widget = Paragraph::new(sig_text)
        .block(
            Block::default()
                .title("Signature Info")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(sig_widget, chunks[2]);

    // Raw XML (scrollable, pretty-printed)
    let xml_paragraph = Paragraph::new(app.raw_xml.as_str())
        .block(
            Block::default()
                .title("SAML Response (formatted)")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.scroll_offset, 0));
    frame.render_widget(xml_paragraph, chunks[3]);

    let copy_indicator = match &app.copy_status {
        Some(msg) => format!(" | {}", msg),
        None => String::new(),
    };
    let help = Paragraph::new(format!(
        "Up/Down: Scroll | c/Ctrl+C: Copy SAML | r: Retry | Esc: Back | q: Quit{}",
        copy_indicator
    ))
    .style(Style::default().fg(Color::DarkGray))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[4]);
}

fn render_error(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let title = Paragraph::new("Seahorse - Error")
        .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let error = Paragraph::new(app.error_message.as_str())
        .style(Style::default().fg(Color::Red))
        .block(
            Block::default()
                .title("Error Details")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(error, chunks[1]);

    let help = Paragraph::new("r: Retry | Esc: Back | q: Quit")
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}

fn render_saml_input(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let title = Paragraph::new("Seahorse - View SAML Assertion")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let mode_label = match app.saml_input_mode {
        SamlInputMode::Paste => "[Paste]  File ",
        SamlInputMode::File => " Paste  [File]",
    };
    let mode = Paragraph::new(format!("Input Mode: {}", mode_label))
        .style(Style::default().fg(Color::Green))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Mode (Tab to switch)"),
        );
    frame.render_widget(mode, chunks[1]);

    match app.saml_input_mode {
        SamlInputMode::Paste => {
            let display = if app.saml_paste_buffer.is_empty() {
                "Paste SAML data here (XML, base64, URL-encoded, or full URL)...".to_string()
            } else {
                let chars = app.saml_paste_buffer.len();
                let lines = app.saml_paste_buffer.lines().count().max(1);
                format!(
                    "{}\n\n--- {} chars, {} lines ---",
                    &app.saml_paste_buffer, chars, lines
                )
            };
            let style = if app.saml_paste_buffer.is_empty() {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            let input = Paragraph::new(display)
                .style(style)
                .block(
                    Block::default()
                        .title("SAML Data")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Yellow)),
                )
                .wrap(Wrap { trim: false });
            frame.render_widget(input, chunks[2]);
        }
        SamlInputMode::File => {
            let display = if app.saml_file_path.is_empty() {
                "Enter file path...".to_string()
            } else {
                app.saml_file_path.clone()
            };
            let style = if app.saml_file_path.is_empty() {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            let input = Paragraph::new(display).style(style).block(
                Block::default()
                    .title("File Path")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            );
            frame.render_widget(input, chunks[2]);
        }
    }

    let help_text = match app.saml_input_mode {
        SamlInputMode::Paste => "Tab: Switch Mode | F5: Decode | Esc: Back | q: Quit",
        SamlInputMode::File => "Tab: Switch Mode | Enter: Load & Decode | Esc: Back | q: Quit",
    };
    let help = Paragraph::new(help_text)
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[3]);
}

fn render_saml_view(frame: &mut Frame, app: &App) {
    let has_attrs = !app.viewer_attributes.is_empty();
    let has_sig = app.viewer_signature.is_some();

    // Calculate details height based on content
    let details_height = {
        let mut lines = 0u16;
        if app.viewer_authn_request.is_some() {
            lines += 9; // max AuthnRequest fields
        }
        if app.viewer_response.is_some() {
            lines += 6;
        }
        if app.viewer_assertion.is_some() {
            lines += 9; // separator + 8 fields
        }
        lines.max(3) + 2 // +2 for borders
    };

    let attr_height = if has_attrs {
        (app.viewer_attributes.len() as u16 + 2).min(10)
    } else {
        0
    };
    let sig_height: u16 = if has_sig { 7 } else { 0 };

    let mut constraints = vec![
        Constraint::Length(3),              // title
        Constraint::Length(details_height), // details
    ];
    if has_attrs {
        constraints.push(Constraint::Length(attr_height));
    }
    if has_sig {
        constraints.push(Constraint::Length(sig_height));
    }
    constraints.push(Constraint::Min(5)); // XML
    constraints.push(Constraint::Length(3)); // help

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(frame.area());

    let mut chunk_idx = 0;

    // Title
    let doc_type_label = match &app.decoded_saml {
        Some(d) => match d.document_type {
            SamlDocType::AuthnRequest => "SAML AuthnRequest",
            SamlDocType::Response => "SAML Response",
            SamlDocType::Assertion => "SAML Assertion",
        },
        None => "SAML Document",
    };
    let title = Paragraph::new(format!("Seahorse - {}", doc_type_label))
        .style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[chunk_idx]);
    chunk_idx += 1;

    // Details panel
    let details_text = build_viewer_details(app);
    let details = Paragraph::new(details_text)
        .block(Block::default().title("Details").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(details, chunks[chunk_idx]);
    chunk_idx += 1;

    // Attributes panel
    if has_attrs {
        let attr_lines: Vec<Line> = app
            .viewer_attributes
            .iter()
            .map(|a| {
                let val = a.values.join(", ");
                Line::from(vec![
                    Span::styled(format!("{}: ", a.name), Style::default().fg(Color::Cyan)),
                    Span::raw(val),
                ])
            })
            .collect();
        let attrs = Paragraph::new(attr_lines)
            .block(Block::default().title("Attributes").borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(attrs, chunks[chunk_idx]);
        chunk_idx += 1;
    }

    // Signature panel
    if has_sig {
        if let Some(ref sig) = app.viewer_signature {
            let valid_color = if sig.signature_valid {
                Color::Green
            } else {
                Color::Red
            };
            let sig_text = vec![
                Line::from(vec![
                    Span::styled("Present:     ", Style::default().fg(Color::Cyan)),
                    Span::raw(if sig.signature_present { "Yes" } else { "No" }),
                ]),
                Line::from(vec![
                    Span::styled("Valid:       ", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        if sig.signature_valid { "Yes" } else { "No" },
                        Style::default().fg(valid_color),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Algorithm:   ", Style::default().fg(Color::Cyan)),
                    Span::raw(&sig.algorithm),
                ]),
                Line::from(vec![
                    Span::styled("Certificate: ", Style::default().fg(Color::Cyan)),
                    Span::raw(&sig.certificate_subject),
                ]),
                Line::from(vec![
                    Span::styled("Cert Expiry: ", Style::default().fg(Color::Cyan)),
                    Span::raw(sig.certificate_not_after.as_deref().unwrap_or("N/A")),
                ]),
            ];
            let sig_widget = Paragraph::new(sig_text)
                .block(
                    Block::default()
                        .title("Signature Info")
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: false });
            frame.render_widget(sig_widget, chunks[chunk_idx]);
        }
        chunk_idx += 1;
    }

    // Formatted XML (scrollable)
    let xml_paragraph = Paragraph::new(app.viewer_pretty_xml.as_str())
        .block(
            Block::default()
                .title("SAML XML (formatted)")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.viewer_scroll_offset, 0));
    frame.render_widget(xml_paragraph, chunks[chunk_idx]);
    chunk_idx += 1;

    // Help bar
    let copy_indicator = match &app.viewer_copy_status {
        Some(msg) => format!(" | {}", msg),
        None => String::new(),
    };
    let help = Paragraph::new(format!(
        "Up/Down: Scroll | c/Ctrl+C: Copy XML | r: New Input | Esc: Main Menu | q: Quit{}",
        copy_indicator
    ))
    .style(Style::default().fg(Color::DarkGray))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[chunk_idx]);
}

fn build_viewer_details<'a>(app: &'a App) -> Vec<Line<'a>> {
    let mut lines = Vec::new();

    if let Some(ref req) = app.viewer_authn_request {
        lines.push(detail_line("ID:              ", &req.id));
        lines.push(detail_line("IssueInstant:    ", &req.issue_instant));
        lines.push(detail_line("Issuer:          ", &req.issuer));
        lines.push(detail_line(
            "Destination:     ",
            req.destination.as_deref().unwrap_or("N/A"),
        ));
        lines.push(detail_line(
            "ACS URL:         ",
            req.acs_url.as_deref().unwrap_or("N/A"),
        ));
        lines.push(detail_line(
            "ProtocolBinding: ",
            req.protocol_binding.as_deref().unwrap_or("N/A"),
        ));
        lines.push(detail_line(
            "NameIDPolicy:    ",
            req.name_id_policy.as_deref().unwrap_or("N/A"),
        ));
        if let Some(fa) = req.force_authn {
            lines.push(detail_line(
                "ForceAuthn:      ",
                if fa { "true" } else { "false" },
            ));
        }
        if let Some(ip) = req.is_passive {
            lines.push(detail_line(
                "IsPassive:       ",
                if ip { "true" } else { "false" },
            ));
        }
    }

    if let Some(ref resp) = app.viewer_response {
        lines.push(detail_line("Response ID:     ", &resp.id));
        lines.push(detail_line("IssueInstant:    ", &resp.issue_instant));
        lines.push(detail_line("Issuer:          ", &resp.issuer));
        lines.push(detail_line(
            "Destination:     ",
            resp.destination.as_deref().unwrap_or("N/A"),
        ));
        lines.push(detail_line(
            "InResponseTo:    ",
            resp.in_response_to.as_deref().unwrap_or("N/A"),
        ));
        lines.push(detail_line("Status:          ", &resp.status));
    }

    if let Some(ref assertion) = app.viewer_assertion {
        if app.viewer_response.is_some() {
            lines.push(Line::from(Span::styled(
                "--- Assertion ---",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
        }
        lines.push(detail_line("Issuer:          ", &assertion.issuer));
        lines.push(detail_line("Subject:         ", &assertion.subject));
        lines.push(detail_line("Audience:        ", &assertion.audience));
        lines.push(detail_line("ID:              ", &assertion.assertion_id));
        lines.push(detail_line("Issued:          ", &assertion.issue_instant));
        lines.push(detail_line(
            "NotBefore:       ",
            assertion.not_before.as_deref().unwrap_or("N/A"),
        ));
        lines.push(detail_line(
            "NotAfter:        ",
            assertion.not_after.as_deref().unwrap_or("N/A"),
        ));
        lines.push(detail_line(
            "Signed:          ",
            if assertion.has_signature { "Yes" } else { "No" },
        ));
    }

    if lines.is_empty() {
        lines.push(Line::from("No details available"));
    }

    lines
}

fn detail_line<'a>(label: &'a str, value: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(label, Style::default().fg(Color::Cyan)),
        Span::raw(value),
    ])
}
