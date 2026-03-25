use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use crate::app::App;

pub fn render(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // status
            Constraint::Min(8),    // peers
            Constraint::Length(6), // log preview
            Constraint::Length(3), // keybindings
        ])
        .split(frame.area());

    render_status(frame, app, chunks[0]);
    render_peers(frame, app, chunks[1]);
    render_log_preview(frame, app, chunks[2]);
    render_keys(frame, app, chunks[3]);
}

fn render_status(frame: &mut Frame, app: &App, area: Rect) {
    let (indicator, color) = if app.server_running {
        ("RUNNING", Color::Green)
    } else {
        ("STOPPED", Color::Red)
    };

    let pid_text = app
        .server_pid
        .map(|p| format!("  pid {p}"))
        .unwrap_or_default();

    let pk_display = if app.public_key.len() > 40 {
        format!("{}...", &app.public_key[..40])
    } else if app.public_key.is_empty() {
        "not generated".to_owned()
    } else {
        app.public_key.clone()
    };

    let text = vec![
        Line::from(vec![
            Span::raw("  Status: "),
            Span::styled(indicator, Style::default().fg(color).bold()),
            Span::raw(pid_text),
            Span::raw("    Interface: "),
            Span::styled(&app.interface, Style::default().fg(Color::Cyan)),
            Span::raw("    Port: "),
            Span::styled(
                format!("{}/udp", app.port),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::raw("  Key:    "),
            Span::styled(pk_display, Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::raw("  Peers:  "),
            Span::styled(
                format!("{}", app.peers.len()),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw("    Clients: "),
            Span::styled(
                format!("{}", app.clients.len()),
                Style::default().fg(Color::Cyan),
            ),
        ]),
    ];

    let block = Block::default()
        .title(" IronGuard ")
        .title_style(Style::default().fg(Color::Cyan).bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let para = Paragraph::new(text).block(block);
    frame.render_widget(para, area);
}

fn render_peers(frame: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("Name").style(Style::default().fg(Color::DarkGray)),
        Cell::from("IP").style(Style::default().fg(Color::DarkGray)),
        Cell::from("Public Key").style(Style::default().fg(Color::DarkGray)),
        Cell::from("Keepalive").style(Style::default().fg(Color::DarkGray)),
    ]);

    let rows: Vec<Row> = app
        .peers
        .iter()
        .map(|p| {
            let pk_short = if p.public_key.len() > 20 {
                format!("{}...", &p.public_key[..20])
            } else {
                p.public_key.clone()
            };
            Row::new(vec![
                Cell::from(p.name.as_str()),
                Cell::from(p.ip.as_str()),
                Cell::from(pk_short).style(Style::default().fg(Color::DarkGray)),
                Cell::from(p.keepalive.as_str()),
            ])
        })
        .collect();

    let empty_msg = if app.peers.is_empty() {
        vec![Row::new(vec![
            Cell::from("  No peers. Press [c] to create a client.")
                .style(Style::default().fg(Color::DarkGray)),
        ])]
    } else {
        vec![]
    };

    let display_rows = if rows.is_empty() { empty_msg } else { rows };

    let widths = [
        Constraint::Length(15),
        Constraint::Length(18),
        Constraint::Min(24),
        Constraint::Length(10),
    ];

    let table = Table::new(display_rows, widths).header(header).block(
        Block::default()
            .title(format!(" Peers ({}) ", app.peers.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(table, area);
}

fn render_log_preview(frame: &mut Frame, app: &App, area: Rect) {
    let visible = area.height.saturating_sub(2) as usize;
    let start = app.logs.len().saturating_sub(visible);
    let lines: Vec<Line> = app.logs[start..]
        .iter()
        .map(|l| {
            Line::from(Span::styled(
                l.as_str(),
                Style::default().fg(Color::DarkGray),
            ))
        })
        .collect();

    let block = Block::default()
        .title(" Log ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let para = Paragraph::new(lines).block(block);
    frame.render_widget(para, area);
}

fn render_keys(frame: &mut Frame, app: &App, area: Rect) {
    let status = if app.status_msg.is_empty() {
        String::new()
    } else {
        format!("  {}", app.status_msg)
    };

    let run_key = if app.server_running {
        "[r]estart  [x] stop"
    } else {
        "[r]un"
    };

    let text = vec![Line::from(vec![
        Span::styled(" [s]", Style::default().fg(Color::Yellow)),
        Span::raw("etup  "),
        Span::styled("[c]", Style::default().fg(Color::Yellow)),
        Span::raw("lient  "),
        Span::styled("[p]", Style::default().fg(Color::Yellow)),
        Span::raw("eers  "),
        Span::styled("[d]", Style::default().fg(Color::Yellow)),
        Span::raw("aemon  "),
        Span::styled(
            format!("[{}]", &run_key[1..2]),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(&run_key[2..]),
        Span::raw("  "),
        Span::styled("[l]", Style::default().fg(Color::Yellow)),
        Span::raw("ogs  "),
        Span::styled("[?]", Style::default().fg(Color::Yellow)),
        Span::raw("help  "),
        Span::styled("[q]", Style::default().fg(Color::Yellow)),
        Span::raw("uit"),
        Span::styled(status, Style::default().fg(Color::Green)),
    ])];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let para = Paragraph::new(text).block(block);
    frame.render_widget(para, area);
}
