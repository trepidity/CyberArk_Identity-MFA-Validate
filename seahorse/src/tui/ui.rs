use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use super::app::{App, Screen, SigningMode};

pub fn render(frame: &mut Frame, app: &App) {
    match app.screen {
        Screen::EnvSelect => render_env_select(frame, app),
        Screen::FlowSelect => render_flow_select(frame, app),
        Screen::AuthInput => render_auth_input(frame, app),
        Screen::Waiting => render_waiting(frame, app),
        Screen::Result => render_result(frame, app),
        Screen::Error => render_error(frame, app),
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

    let envs = ["PROD", "TST"];
    let items: Vec<ListItem> = envs
        .iter()
        .enumerate()
        .map(|(i, env)| {
            let style = if i == app.env_selection {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let prefix = if i == app.env_selection { "> " } else { "  " };
            ListItem::new(format!("{}{}", prefix, env)).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title("Seahorse - Select Environment")
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

    // Raw XML (scrollable)
    let xml_paragraph = Paragraph::new(app.raw_xml.as_str())
        .block(Block::default().title("Raw XML").borders(Borders::ALL))
        .wrap(Wrap { trim: false })
        .scroll((app.scroll_offset, 0));
    frame.render_widget(xml_paragraph, chunks[3]);

    let help =
        Paragraph::new("Up/Down: Scroll XML | r: Retry | Esc: Back to Flow Select | q: Quit")
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
